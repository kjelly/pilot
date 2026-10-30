package spec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// A --check preview does not install docker, so on a host that has never had it
// the dcgm-exporter install + container block must wait for the real apply
// (the first one to fail was Step 2's restart: "Could not find the requested
// service docker"). That only holds when THIS ansible run installs docker for
// the host. docker-apply.yml records that itself (pilot_docker_install_planned,
// under the install tasks' own tags), so Ansible's own task selection decides:
// a full site.yml run, `--tags docker,dcgm-exporter`, `--tags tagged` install
// docker first and the preview defers; a standalone dcgm-exporter-apply.yml,
// `--tags dcgm-exporter`, `--tags observability`, `--skip-tags docker[-C1]`
// do not, so a preview of a fresh host must keep failing on the missing
// docker exactly like the real apply does. Being in the `docker` inventory
// group proves nothing either way.

const (
	dockerApplyPath = "../../playbooks/apply/docker-apply.yml"
	dcgmApplyPath   = "../../playbooks/apply/dcgm-exporter-apply.yml"

	dockerMarkerPrefix = "Docker — record that this run installs docker"
	dockerDebianTask   = "Docker — install docker.io (Debian family)"
	dockerRHELTask     = "Docker — install docker (RHEL family)"
	dcgmBlockName      = "dcgm-exporter install + container"
	pendingFactKey     = "dcgm_exporter_docker_pending_in_preview"
	markerFactKey      = "pilot_docker_install_planned"
)

// deferPlayTasks returns every pre_tasks/tasks entry of a playbook, in file order.
func deferPlayTasks(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, play := range plays {
		for _, section := range []string{"pre_tasks", "tasks"} {
			list, _ := play[section].([]any)
			for _, task := range list {
				if m, ok := task.(map[string]any); ok {
					out = append(out, m)
				}
			}
		}
	}
	return out
}

func deferTaskNamed(t *testing.T, tasks []map[string]any, match func(string) bool) map[string]any {
	t.Helper()
	for _, task := range tasks {
		if name, _ := task["name"].(string); name != "" && match(name) {
			return task
		}
	}
	return nil
}

// deferStringList accepts the YAML forms a `tags`/`when` value can take.
func deferStringList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}

func deferSortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func deferTaskFact(task map[string]any, key string) (string, bool) {
	facts, _ := task["ansible.builtin.set_fact"].(map[string]any)
	v, ok := facts[key]
	if !ok {
		return "", false
	}
	return fmt.Sprint(v), true
}

// The marker must be selected by exactly the tags that select docker's install
// tasks (and be gated by the same OS conditions) or it would disagree with the
// install about whether this run installs docker. It must not be always-tagged
// (that would fire under `--tags dcgm-exporter` and recreate the false green)
// and must not look at check mode (it is read in check mode).
func TestDockerApplyInstallMarkerMirrorsTheInstallTasks(t *testing.T) {
	tasks := deferPlayTasks(t, dockerApplyPath)
	marker := deferTaskNamed(t, tasks, func(n string) bool { return strings.HasPrefix(n, dockerMarkerPrefix) })
	if marker == nil {
		t.Fatalf("docker-apply.yml has no task named %q...", dockerMarkerPrefix)
	}
	deb := deferTaskNamed(t, tasks, func(n string) bool { return n == dockerDebianTask })
	rhel := deferTaskNamed(t, tasks, func(n string) bool { return n == dockerRHELTask })
	if deb == nil || rhel == nil {
		t.Fatalf("docker-apply.yml is missing an install task (debian=%v rhel=%v)", deb != nil, rhel != nil)
	}
	// The marker is placed before the install tasks so it also exists when an
	// install task is what makes docker.service appear.
	idx := map[string]int{}
	for i, task := range tasks {
		if name, _ := task["name"].(string); name != "" {
			idx[name] = i
		}
	}
	if idx[marker["name"].(string)] >= idx[dockerDebianTask] || idx[marker["name"].(string)] >= idx[dockerRHELTask] {
		t.Fatal("the marker must come before the install tasks")
	}

	markerTags := deferSortedCopy(deferStringList(marker["tags"]))
	for _, tag := range markerTags {
		if tag == "always" {
			t.Fatalf("marker must not be always-tagged: it would be set under --tags dcgm-exporter; tags=%v", markerTags)
		}
	}
	want := func(label string, got []string) {
		t.Helper()
		if strings.Join(deferSortedCopy(got), ",") != strings.Join(markerTags, ",") {
			t.Fatalf("marker tags %v != %s tags %v", markerTags, label, deferSortedCopy(got))
		}
	}
	want("debian install task", deferStringList(deb["tags"]))
	want("rhel install task", deferStringList(rhel["tags"]))
	include, _ := deb["ansible.builtin.include_tasks"].(map[string]any)
	apply, _ := include["apply"].(map[string]any)
	want("debian include_tasks apply.tags", deferStringList(apply["tags"]))

	if _, cacheable := marker["ansible.builtin.set_fact"].(map[string]any)["cacheable"]; cacheable {
		t.Fatal("the marker must stay host-scoped to this run: no cacheable on the set_fact")
	}
	if v, ok := deferTaskFact(marker, markerFactKey); !ok || v != "true" {
		t.Fatalf("marker must set %s: true, got %q (present=%v)", markerFactKey, v, ok)
	}

	// Same OS conditions as the install tasks, minus `not ansible_check_mode`.
	osRe := regexp.MustCompile(`ansible_os_family\s*==\s*'(\w+)'`)
	var installFamilies []string
	for label, task := range map[string]map[string]any{"debian": deb, "rhel": rhel} {
		var rest []string
		sawCheckGate := false
		for _, cond := range deferStringList(task["when"]) {
			if strings.TrimSpace(cond) == "not ansible_check_mode" {
				sawCheckGate = true
				continue
			}
			rest = append(rest, cond)
		}
		if !sawCheckGate {
			t.Fatalf("%s install task lost its `not ansible_check_mode` gate: %v", label, task["when"])
		}
		if len(rest) != 1 {
			t.Fatalf("%s install task has conditions the marker cannot mirror: %v", label, rest)
		}
		m := osRe.FindStringSubmatch(rest[0])
		if m == nil {
			t.Fatalf("%s install task OS condition %q is not `ansible_os_family == 'X'`", label, rest[0])
		}
		installFamilies = append(installFamilies, m[1])
	}
	markerWhen := deferStringList(marker["when"])
	if len(markerWhen) != 1 {
		t.Fatalf("marker must have exactly the OS condition, got %v", markerWhen)
	}
	if strings.Contains(markerWhen[0], "ansible_check_mode") {
		t.Fatalf("marker `when` must not mention ansible_check_mode: %v", markerWhen)
	}
	var markerFamilies []string
	for _, m := range regexp.MustCompile(`'(\w+)'`).FindAllStringSubmatch(markerWhen[0], -1) {
		markerFamilies = append(markerFamilies, m[1])
	}
	if !strings.HasPrefix(strings.TrimSpace(markerWhen[0]), "ansible_os_family in ") ||
		strings.Join(deferSortedCopy(markerFamilies), ",") != strings.Join(deferSortedCopy(installFamilies), ",") {
		t.Fatalf("marker OS condition %q does not cover exactly the install tasks' OS families %v", markerWhen[0], installFamilies)
	}
}

// The reader must be always-tagged (AGENTS.md 4.4) and must read the marker,
// not the inventory group.
func TestDcgmExporterPendingFactReadsThePlannedInstallMarker(t *testing.T) {
	var pending map[string]any
	for _, task := range deferPlayTasks(t, dcgmApplyPath) {
		if _, ok := deferTaskFact(task, pendingFactKey); ok {
			pending = task
		}
	}
	if pending == nil {
		t.Fatalf("dcgm-exporter-apply.yml has no set_fact for %s", pendingFactKey)
	}
	expr, _ := deferTaskFact(pending, pendingFactKey)
	if !strings.Contains(expr, markerFactKey+" is defined") {
		t.Fatalf("pending fact must test `%s is defined`: %s", markerFactKey, expr)
	}
	if strings.Contains(expr, "group_names") {
		t.Fatalf("pending fact must not use inventory group membership: %s", expr)
	}
	always := false
	for _, tag := range deferStringList(pending["tags"]) {
		always = always || tag == "always"
	}
	if !always {
		t.Fatalf("pending fact must be always-tagged, tags=%v", pending["tags"])
	}
}

// ---- real ansible-playbook matrix ------------------------------------------

type previewHarness struct {
	docker map[string]any // docker play
	dcgm   func(gpu, occupied bool) map[string]any
}

// buildPreviewHarness wires the REAL tasks of the two playbooks into two plays
// that mimic site.yml: the real marker task and the real install tasks reduced
// to name+tags+when with a debug marker for the docker play; the real probe,
// pending fact, report and block `when` (block body swapped for a marker) for
// the dcgm play.
func buildPreviewHarness(t *testing.T) previewHarness {
	t.Helper()
	dockerTasks := deferPlayTasks(t, dockerApplyPath)
	marker := deferTaskNamed(t, dockerTasks, func(n string) bool { return strings.HasPrefix(n, dockerMarkerPrefix) })
	if marker == nil {
		t.Fatal("docker-apply.yml has no install marker task")
	}
	groups := func(marker string) map[string]any {
		return map[string]any{
			"name": "harness: which groups is this host in", "tags": []any{"always"},
			"ansible.builtin.debug": map[string]any{"msg": marker + "{{ group_names | sort | join(',') }}"},
		}
	}
	dtasks := []any{groups("DOCKER-PLAY-GROUPS="), marker}
	for _, name := range []string{dockerDebianTask, dockerRHELTask} {
		real := deferTaskNamed(t, dockerTasks, func(n string) bool { return n == name })
		if real == nil {
			t.Fatalf("docker-apply.yml has no task %q", name)
		}
		dtasks = append(dtasks, map[string]any{
			"name": real["name"], "tags": real["tags"], "when": real["when"],
			"ansible.builtin.debug": map[string]any{"msg": "DOCKER-INSTALL-RAN"},
		})
	}
	dockerPlay := map[string]any{
		"name": "docker", "hosts": "{{ target_group | default('docker') }}", "gather_facts": true,
		// `--tags docker-C1` skips Gathering Facts; the real install tasks then
		// need ansible_os_family from somewhere. Gathered facts override this.
		"vars":  map[string]any{"ansible_os_family": "Debian"},
		"tasks": dtasks,
	}

	dcgmTasks := deferPlayTasks(t, dcgmApplyPath)
	var probe, pending, report, block map[string]any
	for _, task := range dcgmTasks {
		if task["register"] == "dcgm_exporter_docker_unit_check" {
			probe = task
		}
		if _, ok := deferTaskFact(task, pendingFactKey); ok {
			pending = task
		}
		if when, _ := task["when"].(string); strings.TrimSpace(when) == pendingFactKey+" | bool" {
			report = task
		}
		if task["name"] == dcgmBlockName {
			block = task
		}
	}
	for label, task := range map[string]map[string]any{"probe": probe, "pending fact": pending, "report": report, "block": block} {
		if task == nil {
			t.Fatalf("dcgm-exporter-apply.yml has no %s task", label)
		}
	}
	// Only whether the block runs matters here, not what is in it.
	delete(block, "rescue")
	block["block"] = []any{map[string]any{"name": "marker", "ansible.builtin.debug": map[string]any{"msg": "INSTALL-BLOCK-RAN"}}}
	return previewHarness{
		docker: dockerPlay,
		dcgm: func(gpu, occupied bool) map[string]any {
			return map[string]any{
				"name": "dcgm", "hosts": "{{ target_group | default('dcgm-exporter') }}", "gather_facts": false,
				"vars": map[string]any{
					"dcgm_exporter_gpu_present":            gpu,
					"dcgm_exporter_port_occupied_by_other": occupied,
				},
				"tasks": []any{groups("DCGM-PLAY-GROUPS="), probe, pending, report, block},
			}
		},
	}
}

type previewSelector struct {
	name     string
	playbook string // site.yml, docker.yml or dcgm.yml
	args     []string
	// What Ansible's task selection does to a host in the docker group.
	// Checked against the real-mode run, not just assumed.
	dockerInstalls bool
	dcgmBlockRuns  bool
	// The dcgm play's always-tagged tasks (probe, pending fact, report) run:
	// true unless the dcgm play is not part of the run or `--skip-tags` drops
	// it by its import tag (which also drops its always-tagged tasks).
	dcgmAlwaysRuns bool
}

var previewSelectors = []previewSelector{
	{"full site", "site.yml", nil, true, true, true},
	{"tags dcgm-exporter", "site.yml", []string{"--tags", "dcgm-exporter"}, false, true, true},
	{"tags observability", "site.yml", []string{"--tags", "observability"}, false, true, true},
	{"tags docker", "site.yml", []string{"--tags", "docker"}, true, false, true},
	{"tags docker,dcgm-exporter", "site.yml", []string{"--tags", "docker,dcgm-exporter"}, true, true, true},
	{"tags infra", "site.yml", []string{"--tags", "infra"}, true, false, true},
	{"tags docker-C1", "site.yml", []string{"--tags", "docker-C1"}, true, false, true},
	{"tags docker-C2", "site.yml", []string{"--tags", "docker-C2"}, false, false, true},
	{"tags tagged", "site.yml", []string{"--tags", "tagged"}, true, true, true},
	{"skip-tags docker", "site.yml", []string{"--skip-tags", "docker"}, false, true, true},
	{"skip-tags docker-C1", "site.yml", []string{"--skip-tags", "docker-C1"}, false, true, true},
	{"skip-tags dcgm-exporter", "site.yml", []string{"--skip-tags", "dcgm-exporter"}, true, false, false},
	{"standalone dcgm play", "dcgm.yml", nil, false, true, true},
	{"standalone docker play", "docker.yml", nil, true, false, false},
}

// Each cell forks several ansible processes; keep the machine responsive.
var previewRunSlots = make(chan struct{}, 6)

type previewCell struct {
	dir     string
	ansible string
}

func newPreviewCell(t *testing.T, ansible string, h previewHarness, inDockerGroup, gpu, occupied bool, dockerRC int) previewCell {
	t.Helper()
	// Not t.TempDir(): it embeds the subtest name (with commas), and ansible
	// cannot parse an inventory whose path contains one.
	dir, err := os.MkdirTemp("", "dcgm-defer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	write := func(name string, v any) {
		out, err := yaml.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("docker.yml", []any{h.docker})
	write("dcgm.yml", []any{h.dcgm(gpu, occupied)})
	// Mirrors site.yml's import lines for these two playbooks.
	site := "- import_playbook: docker.yml\n  tags: [infra, docker]\n- import_playbook: dcgm.yml\n  tags: [observability, dcgm-exporter]\n"
	if err := os.WriteFile(filepath.Join(dir, "site.yml"), []byte(site), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// systemctl: rc 1 = no docker.service, rc 0 = present.
	if err := os.WriteFile(filepath.Join(dir, "bin", "systemctl"), []byte(fmt.Sprintf("#!/bin/sh\nexit %d\n", dockerRC)), 0o755); err != nil {
		t.Fatal(err)
	}
	inv := "[dcgm-exporter]\nlocalhost ansible_connection=local\n"
	if inDockerGroup {
		inv += "[docker]\nlocalhost ansible_connection=local\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts.ini"), []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ansible.cfg"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return previewCell{dir: dir, ansible: ansible}
}

func (c previewCell) run(t *testing.T, sel previewSelector, check bool, extraEnv ...string) string {
	t.Helper()
	args := []string{"-i", filepath.Join(c.dir, "hosts.ini"), filepath.Join(c.dir, sel.playbook)}
	args = append(args, sel.args...)
	if check {
		args = append(args, "--check")
	}
	previewRunSlots <- struct{}{}
	defer func() { <-previewRunSlots }()
	// ansible-core 2.19's strategy results thread can die on a KeyError race
	// (`_convert_wire_task_result_to_raw`) and then the run hangs forever. That
	// is an ansible bug, not a playbook result, so exactly that signature (a hang
	// killed by our timeout whose output carries the results_thread_main
	// traceback) is retried; any other failure, or a hang without it, fails.
	const attempts = 3
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		cmd := exec.CommandContext(ctx, c.ansible, args...)
		cmd.Dir = c.dir
		cmd.WaitDelay = 10 * time.Second
		cmd.Env = append(os.Environ(),
			"PATH="+filepath.Join(c.dir, "bin")+":"+os.Getenv("PATH"),
			"ANSIBLE_CONFIG="+filepath.Join(c.dir, "ansible.cfg"),
			// No state shared with other cells or the developer's ~/.ansible.
			"ANSIBLE_HOME="+filepath.Join(c.dir, "ansible-home"),
			"ANSIBLE_LOCAL_TEMP="+filepath.Join(c.dir, "local-tmp"),
			"ANSIBLE_REMOTE_TEMP="+filepath.Join(c.dir, "remote-tmp"),
			"ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
		cmd.Env = append(cmd.Env, extraEnv...)
		log, err := cmd.CombinedOutput()
		timedOut := ctx.Err() != nil
		cancel()
		if err == nil {
			return string(log)
		}
		if timedOut && strings.Contains(string(log), "results_thread_main") && attempt < attempts {
			t.Logf("ansible-playbook hung on its known results-thread race (attempt %d/%d), retrying", attempt, attempts)
			continue
		}
		t.Fatalf("ansible-playbook %v: %v\n%s", args, err, log)
	}
}

// A silently unparsed inventory would fall back to the implicit localhost,
// which is in no group, and make every group case vacuous.
func assertInventoryParsed(t *testing.T, log string, sel previewSelector, inDockerGroup bool) {
	t.Helper()
	if strings.Contains(log, "No inventory was parsed") || strings.Contains(log, "Failed to parse inventory") {
		t.Fatalf("inventory was not parsed\n%s", log)
	}
	// `--skip-tags <import tag>` also skips a play's always-tagged tasks, so a
	// play's groups line is only expected where its always-tagged tasks run.
	dcgmPlay := sel.dcgmAlwaysRuns
	dockerPlay := sel.playbook != "dcgm.yml"
	if dcgmPlay {
		want := "DCGM-PLAY-GROUPS=dcgm-exporter"
		if inDockerGroup {
			want += ",docker"
		}
		if !strings.Contains(log, want+`"`) {
			t.Fatalf("dcgm play did not see the host with groups %q\n%s", want, log)
		}
	}
	if sel.dockerInstalls && inDockerGroup && !strings.Contains(log, `DOCKER-PLAY-GROUPS=dcgm-exporter,docker"`) {
		t.Fatalf("docker play did not see the host in the docker group\n%s", log)
	}
	if dockerPlay && !inDockerGroup && strings.Contains(log, "DOCKER-PLAY-GROUPS=") {
		t.Fatalf("docker play ran on a host outside the docker group\n%s", log)
	}
}

func deferAnsibleOrSkip(t *testing.T) string {
	t.Helper()
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not installed")
	}
	return ansible
}

// Oracle for every (selector, inventory, docker.service, mode):
//   - real mode: the block runs whenever Ansible selects it, and docker's
//     install runs iff Ansible selects it for a host in the docker group;
//   - preview: the block is deferred iff docker is missing AND the same
//     selector's real-mode run printed DOCKER-INSTALL-RAN for that host.
func TestDcgmExporterPreviewDefersTheBlockOnlyWhenThisRunInstallsDocker(t *testing.T) {
	ansible := deferAnsibleOrSkip(t)
	h := buildPreviewHarness(t)
	for _, sel := range previewSelectors {
		for _, inDockerGroup := range []bool{true, false} {
			for _, dockerRC := range []int{1, 0} {
				name := fmt.Sprintf("%s/in-docker-group=%v/docker-rc=%d", strings.ReplaceAll(sel.name, ",", "+"), inDockerGroup, dockerRC)
				sel, inDockerGroup, dockerRC := sel, inDockerGroup, dockerRC
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					cell := newPreviewCell(t, ansible, h, inDockerGroup, true, false, dockerRC)
					realLog := cell.run(t, sel, false)
					previewLog := cell.run(t, sel, true)
					assertInventoryParsed(t, realLog, sel, inDockerGroup)
					assertInventoryParsed(t, previewLog, sel, inDockerGroup)

					dockerRan := strings.Contains(realLog, "DOCKER-INSTALL-RAN")
					if want := sel.dockerInstalls && inDockerGroup; dockerRan != want {
						t.Fatalf("real mode: docker install ran=%v, want %v\n%s", dockerRan, want, realLog)
					}
					// Real mode: the block runs whenever selected, deferred or not.
					if ran := strings.Contains(realLog, "INSTALL-BLOCK-RAN"); ran != sel.dcgmBlockRuns {
						t.Fatalf("real mode: install block ran=%v, want %v\n%s", ran, sel.dcgmBlockRuns, realLog)
					}
					if strings.Contains(realLog, "docker.service 還不存在") {
						t.Fatalf("real mode must never report a deferral\n%s", realLog)
					}

					// A preview never installs docker.
					if strings.Contains(previewLog, "DOCKER-INSTALL-RAN") {
						t.Fatalf("preview ran docker's install\n%s", previewLog)
					}
					deferred := dockerRC != 0 && dockerRan
					if ran, want := strings.Contains(previewLog, "INSTALL-BLOCK-RAN"), sel.dcgmBlockRuns && !deferred; ran != want {
						t.Fatalf("preview: install block ran=%v, want %v (docker rc=%d, real run installs docker=%v)\n%s",
							ran, want, dockerRC, dockerRan, previewLog)
					}
					// The always-tagged report fires with the fact whenever the dcgm play's always tasks run.
					reported := strings.Contains(previewLog, "docker.service 還不存在")
					if want := deferred && sel.dcgmAlwaysRuns; reported != want {
						t.Fatalf("preview: deferral reported=%v, want %v\n%s", reported, want, previewLog)
					}
				})
			}
		}
	}
}

// The block never runs without a GPU or with the port served by something
// else, preview or real, whatever docker is doing.
func TestDcgmExporterBlockNeverRunsWithoutGPUOrWithPortOccupied(t *testing.T) {
	ansible := deferAnsibleOrSkip(t)
	h := buildPreviewHarness(t)
	full := previewSelectors[0]
	for _, tt := range []struct {
		name          string
		gpu, occupied bool
	}{
		{"no GPU", false, false},
		{"port served by something else", true, true},
	} {
		for _, dockerRC := range []int{1, 0} {
			for _, check := range []bool{true, false} {
				tt, dockerRC, check := tt, dockerRC, check
				t.Run(fmt.Sprintf("%s/docker-rc=%d/check=%v", tt.name, dockerRC, check), func(t *testing.T) {
					t.Parallel()
					cell := newPreviewCell(t, ansible, h, true, tt.gpu, tt.occupied, dockerRC)
					log := cell.run(t, full, check)
					assertInventoryParsed(t, log, full, true)
					if strings.Contains(log, "INSTALL-BLOCK-RAN") {
						t.Fatalf("install block ran\n%s", log)
					}
				})
			}
		}
	}
}

// The marker is host-scoped to the ansible-playbook run that planned the
// install: with a persistent fact cache, a later `--check --tags dcgm-exporter`
// run must not inherit it and defer (it would go green while the real apply
// fails on the missing docker).
func TestDcgmExporterInstallMarkerIsNotPersistedInTheFactCache(t *testing.T) {
	ansible := deferAnsibleOrSkip(t)
	h := buildPreviewHarness(t)
	cell := newPreviewCell(t, ansible, h, true, true, false, 1)
	cacheDir := filepath.Join(cell.dir, "factcache")
	env := []string{"ANSIBLE_CACHE_PLUGIN=jsonfile", "ANSIBLE_CACHE_PLUGIN_CONNECTION=" + cacheDir, "ANSIBLE_CACHE_PLUGIN_TIMEOUT=3600"}

	first := cell.run(t, previewSelectors[0], true, env...)
	if !strings.Contains(first, "docker.service 還不存在") || strings.Contains(first, "INSTALL-BLOCK-RAN") {
		t.Fatalf("setup: the full-site preview must defer\n%s", first)
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("setup: the jsonfile fact cache was not written (err=%v): the test would be vacuous", err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(cacheDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var facts map[string]any
		if err := json.Unmarshal(raw, &facts); err != nil {
			t.Fatalf("cache file %s: %v", e.Name(), err)
		}
		if _, ok := facts[markerFactKey]; ok || strings.Contains(string(raw), markerFactKey) {
			t.Fatalf("%s was persisted in the fact cache (%s)", markerFactKey, e.Name())
		}
	}
	second := cell.run(t, previewSelectors[1], true, env...)
	if !strings.Contains(second, "INSTALL-BLOCK-RAN") || strings.Contains(second, "docker.service 還不存在") {
		t.Fatalf("`--check --tags dcgm-exporter` after a full preview must not defer (stale marker)\n%s", second)
	}
}

// A --check preview does not write the NVIDIA apt key or repo list, so the
// toolkit install's scoped APT refresh cannot find the .list file; the install
// must be skipped in check mode (same as wazuh-fim's third-party repo).
func TestDcgmExporterToolkitInstallIsSkippedInCheckMode(t *testing.T) {
	raw, err := os.ReadFile("../../playbooks/apply/dcgm-exporter-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	const name = "Step 1: Install nvidia-container-toolkit (spec C1)"
	for _, play := range plays {
		tasks, _ := play["tasks"].([]any)
		for _, task := range tasks {
			block, _ := task.(map[string]any)["block"].([]any)
			for _, inner := range block {
				m, _ := inner.(map[string]any)
				if m["name"] != name {
					continue
				}
				if when, _ := m["when"].(string); strings.TrimSpace(when) != "not ansible_check_mode" {
					t.Fatalf("%q has when %v, want `not ansible_check_mode`", name, m["when"])
				}
				return
			}
		}
	}
	t.Fatalf("dcgm-exporter-apply.yml has no task named %q", name)
}
