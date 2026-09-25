package spec

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// preTaskGateNotAlwaysAllowlist lists pre_tasks input checks that a
// tag-scoped run can still skip in a play whose includes pass tags down
// with `apply`: they read inputs (infra_role, secrets, a resolvable backup
// destination), not the stage. The stage gates that used to be listed here
// are `always` since 2026-09-25 (TestRegression_StageGatesAlwaysRunInTaggedPlays).
// Making these `always` needs each checked for facts set by untagged tasks
// (AGENTS.md §4.4); that is a separate follow-up. Keys are
// "<playbook>|<task name>". Entries may only be removed.
var preTaskGateNotAlwaysAllowlist = map[string]bool{
	"playbooks/apply/core-infra-provider-apply.yml|Gate: infra_role must be dns or ntp":                        true,
	"playbooks/apply/restic-backup-apply.yml|Gate: required secrets present (fail early, before any mutation)": true,
	"playbooks/apply/restic-backup-apply.yml|Gate: backup destination must be resolvable":                      true,
}

// TestRegression_PreTaskGatesRunUnderApplyTags is a repo-wide lint over
// playbooks/**. In a play with an include_tasks that passes tags down with
// `apply`, every assert/fail in pre_tasks must run whenever those included
// tasks can: it must be tagged `always`, or carry every tag the play's
// includes apply. Otherwise `--tags <row>` skips the gate and still runs
// the included mutation. PR #10's review found two such bypasses the
// include migration had opened: freeipa-ca-trust's stage gates
// (`--tags C2 -e stage=prod` installed the CA without confirm_prod) and
// internal-endpoint's C7/C8 DNS gates (see
// TestRegression_InternalEndpointGatesCoverTaggedMutations for the
// tasks-section half, which needs the row mapping).
func TestRegression_PreTaskGatesRunUnderApplyTags(t *testing.T) {
	var files []string
	err := filepath.WalkDir("../../playbooks", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	seen := map[string]bool{}
	checkedPlays := 0
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: parse: %v", rel, err)
		}
		gates, plays := skippablePreTaskGates(doc)
		checkedPlays += plays
		for _, name := range gates {
			key := rel + "|" + name
			if preTaskGateNotAlwaysAllowlist[key] {
				seen[key] = true
				continue
			}
			t.Errorf("%s: pre_tasks gate %q is not `always` (and lacks the tags the play's includes apply), so --tags skips it while the included tasks still run", rel, name)
		}
	}
	// The migrated playbooks alone have more than ten such plays; a much
	// smaller count means the walker stopped finding them.
	if checkedPlays < 10 {
		t.Fatalf("only %d plays with apply-tagged includes found; the walker is broken", checkedPlays)
	}
	for key := range preTaskGateNotAlwaysAllowlist {
		if !seen[key] {
			t.Errorf("preTaskGateNotAlwaysAllowlist entry %q no longer matches — drop it", key)
		}
	}
}

func TestSkippablePreTaskGates(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"untagged gate before apply include (freeipa-ca-trust before the fix)", `
- hosts: all
  pre_tasks:
    - name: g
      ansible.builtin.assert: {that: [true]}
  tasks:
    - name: i
      tags: [C2]
      ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C2]}}
`, []string{"g"}},
		{"always gate", `
- hosts: all
  pre_tasks:
    - name: g
      tags: [always]
      ansible.builtin.assert: {that: [true]}
  tasks:
    - name: i
      tags: [C2]
      ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C2]}}
`, nil},
		{"gate carries every applied tag", `
- hosts: all
  pre_tasks:
    - name: g
      tags: [C1, C2]
      fail: {msg: x}
  tasks:
    - name: i
      tags: [C1]
      include_tasks: {file: tasks/a.yml, apply: {tags: [C1]}}
    - name: j
      tags: [C2]
      include_tasks: {file: tasks/b.yml, apply: {tags: [C2]}}
`, nil},
		{"gate misses one applied tag", `
- hosts: all
  pre_tasks:
    - name: g
      tags: [C1]
      ansible.builtin.fail: {msg: x}
  tasks:
    - name: i
      tags: [C1, C2]
      ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C1, C2]}}
`, []string{"g"}},
		{"always inherited from a block", `
- hosts: all
  pre_tasks:
    - tags: [always]
      block:
        - name: g
          ansible.builtin.assert: {that: [true]}
  tasks:
    - block:
        - name: i
          tags: [C2]
          ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C2]}}
`, nil},
		{"no apply include in the play", `
- hosts: all
  pre_tasks:
    - name: g
      ansible.builtin.assert: {that: [true]}
  tasks:
    - name: i
      tags: [C2]
      ansible.builtin.include_tasks: tasks/a.yml
`, nil},
		{"non-gate pre_task is ignored", `
- hosts: all
  pre_tasks:
    - name: s
      ansible.builtin.set_fact: {x: 1}
  tasks:
    - name: i
      tags: [C2]
      ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C2]}}
`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			got, _ := skippablePreTaskGates(doc)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

var gateModules = []string{"ansible.builtin.assert", "assert", "ansible.builtin.fail", "fail"}

// skippablePreTaskGates returns, for every play in doc that has an
// include_tasks with apply.tags, the names of its assert/fail pre_tasks
// whose effective tags (own plus inherited from the play and enclosing
// blocks) have neither `always` nor every tag those includes apply. The
// second result is the number of such plays checked.
func skippablePreTaskGates(doc any) ([]string, int) {
	plays, _ := doc.([]any)
	var out []string
	checked := 0
	for _, p := range plays {
		play, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := play["hosts"]; !ok {
			continue
		}
		playTags := yamlTags(play)
		applied := map[string]bool{}
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks"} {
			walkTaskTree(play[section], playTags, func(task map[string]any, _ []string) {
				for _, key := range []string{"ansible.builtin.include_tasks", "include_tasks"} {
					inc, _ := task[key].(map[string]any)
					apply, _ := inc["apply"].(map[string]any)
					for _, tag := range yamlTags(apply) {
						applied[tag] = true
					}
				}
			})
		}
		if len(applied) == 0 {
			continue
		}
		checked++
		walkTaskTree(play["pre_tasks"], playTags, func(task map[string]any, tags []string) {
			if !slices.ContainsFunc(gateModules, func(m string) bool { _, ok := task[m]; return ok }) {
				return
			}
			if slices.Contains(tags, "always") {
				return
			}
			for tag := range applied {
				if !slices.Contains(tags, tag) {
					name, _ := task["name"].(string)
					out = append(out, name)
					return
				}
			}
		})
	}
	return out, checked
}

// walkTaskTree calls fn for every task in a task list, recursing into
// block/rescue/always, with each task's effective tags.
func walkTaskTree(list any, inherited []string, fn func(task map[string]any, tags []string)) {
	tasks, _ := list.([]any)
	for _, item := range tasks {
		task, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tags := append(slices.Clone(inherited), yamlTags(task)...)
		fn(task, tags)
		for _, key := range []string{"block", "rescue", "always"} {
			walkTaskTree(task[key], tags, fn)
		}
	}
}

// yamlTags returns a task's or play's `tags:` as a list, accepting both the
// list and the single-string form.
func yamlTags(m map[string]any) []string {
	switch v := m["tags"].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, tag := range v {
			if s, ok := tag.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// TestRegression_InternalEndpointGatesCoverTaggedMutations locks which
// tasks-section gates of internal-endpoint-apply.yml must run under the
// row tags of the mutations they protect. The route DNS reconcile runs
// under C4-C6 and has no zone or collision check of its own, so the C7 and
// C8 gates carry C4-C6; the service-principal (C13) and certificate (C15)
// tasks rely on the C12 enrollment preflight. Before this, `--tags C4`
// could `ipa dnsrecord-mod` a record freeipa-dns.yaml owns. It also locks
// the stage gates on the fleet-wide baseline play (C9 resolver, C10 CA
// trust), which had none.
func TestRegression_InternalEndpointGatesCoverTaggedMutations(t *testing.T) {
	raw, err := os.ReadFile("../../playbooks/apply/internal-endpoint-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc []any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) < 2 {
		t.Fatalf("expected the baseline play and the reconcile play, got %d plays", len(doc))
	}
	find := func(play any, section, prefix string) (map[string]any, []string) {
		var task map[string]any
		var tags []string
		p, _ := play.(map[string]any)
		walkTaskTree(p[section], nil, func(tk map[string]any, tg []string) {
			if name, _ := tk["name"].(string); strings.HasPrefix(name, prefix) {
				task, tags = tk, tg
			}
		})
		if task == nil {
			t.Fatalf("no %s task named %q", section, prefix)
		}
		return task, tags
	}

	for _, gate := range []string{
		"Gate: staging or prod requires explicit confirm",
		"Gate: prod requires recent staging attestation",
	} {
		if _, tags := find(doc[0], "pre_tasks", gate); !slices.Contains(tags, "always") {
			t.Errorf("baseline play: %q must be tagged always, got %v", gate, tags)
		}
	}

	for _, tc := range []struct{ prefix, section string }{
		{"Gate: endpoint's DNS zone exists in freeipa-dns manifest", "tasks"},
		{"Gate: no DNS ownership collision with an explicit freeipa-dns.yaml record", "tasks"},
	} {
		_, tags := find(doc[1], tc.section, tc.prefix)
		for _, row := range []string{"C4", "C5", "C6"} {
			if !slices.Contains(tags, row) {
				t.Errorf("%q must carry %s (the route DNS reconcile runs under it), got %v", tc.prefix, row, tags)
			}
		}
	}

	// The environment-group cross-check is skipped only for the
	// host-decommission provider's read-only query. ansible_run_tags is a
	// tuple on ansible-core 2.19, so the comparison needs `| list`; without
	// it the condition is always true and the query failed on every host in
	// a staging or prod group (found on a vm-target, 2026-09-25).
	for i, play := range doc[:2] {
		task, tags := find(play, "pre_tasks", "Gate: stage must match this host's inventory environment group")
		if !slices.Contains(tags, "always") {
			t.Errorf("play %d: cross-check must be tagged always, got %v", i, tags)
		}
		if when, _ := task["when"].(string); when != "(ansible_run_tags | list) != ['iep_decommission_verify']" {
			t.Errorf("play %d: cross-check when = %q, want the decommission-query exemption with `| list`", i, when)
		}
	}

	preflight, tags := find(doc[1], "tasks", "Preflight: TLS certificate owner host has live FreeIPA enrollment")
	inc, _ := preflight["ansible.builtin.include_tasks"].(map[string]any)
	apply, _ := inc["apply"].(map[string]any)
	for _, row := range []string{"C12", "C13", "C15"} {
		if !slices.Contains(tags, row) || !slices.Contains(yamlTags(apply), row) {
			t.Errorf("C12 preflight must carry %s on the include and in apply.tags, got tags=%v apply=%v", row, tags, yamlTags(apply))
		}
	}
}

// TestRegression_InternalEndpointDeleteDelegateToNeverEmpty locks the
// empty-delegate_to fix in the delete sequence. A literal-address route has
// route_owner "" and a tls.mode: disabled endpoint has certificate_owner "".
// delegate_to is templated before `when`, so either one bare is a hard
// error ("Empty hostname produced from delegate_to"), not a skip. Every
// delegate_to in the file needs a fallback that its `when:` never acts on.
func TestRegression_InternalEndpointDeleteDelegateToNeverEmpty(t *testing.T) {
	raw, err := os.ReadFile("../../playbooks/apply/tasks/internal-endpoint-delete.yml")
	if err != nil {
		t.Fatal(err)
	}
	var tasks []any
	if err := yaml.Unmarshal(raw, &tasks); err != nil {
		t.Fatal(err)
	}
	delegated := 0
	walkTaskTree(tasks, nil, func(task map[string]any, _ []string) {
		target, ok := task["delegate_to"].(string)
		if !ok {
			return
		}
		delegated++
		if !strings.Contains(target, "or inventory_hostname") {
			t.Errorf("task %q: delegate_to %q has no fallback for an empty owner", task["name"], target)
		}
	})
	if delegated < 7 {
		t.Fatalf("found only %d delegated tasks; expected the nginx and certificate steps", delegated)
	}
}

// stageGateNotAlwaysAllowlist lists stage gates that may carry a row or
// action tag instead of `always`, with the reason. Keys are
// "<playbook>|<task name>". Entries may only be removed.
var stageGateNotAlwaysAllowlist = map[string]string{
	"playbooks/decommission/wazuh-manager-agent-deregister.yml|Gate: staging or prod requires explicit confirm (deregister action only)": "tagged agent_deregister, the one mutating action, so the read-only agent_query action (the provider's pre-check) is not blocked by it",
	"playbooks/decommission/wazuh-manager-agent-deregister.yml|Gate: prod requires recent staging attestation (deregister action only)":  "same as the confirm gate",
}

// stageGateText matches the stage variables and confirm/attestation inputs
// a stage gate reads.
var stageGateText = regexp.MustCompile(`\b(patch_)?stage\b|confirm_(staging|prod)|staging_attested_within_hours`)

// TestRegression_StageGatesAlwaysRunInTaggedPlays is a repo-wide lint over
// playbooks/**. In any play with a task tagged other than `always`, every
// assert that reads the stage (confirm, environment-group cross-check,
// prod attestation and other prod-only checks) must run under every
// --tags selection, so it must be tagged `always`. Six apply playbooks
// (core-infra-provider, docker, keycloak, keycloak-db, reverse-proxy,
// seaweedfs-s3) had these gates untagged until 2026-09-25. pilot deploy's
// single-component wizard passes its "只跑某幾個檢查項目" answer straight to
// --tags, so a host in the prod group deployed at the default stage
// (sandbox) with a row tag skipped the cross-check and was changed with
// sandbox rules and no confirmation.
func TestRegression_StageGatesAlwaysRunInTaggedPlays(t *testing.T) {
	seen := map[string]bool{}
	plays := 0
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		doc := loadYAML(t, path)
		gates, checked := stageGatesNotAlways(doc)
		plays += checked
		for _, name := range gates {
			key := rel + "|" + name
			if _, ok := stageGateNotAlwaysAllowlist[key]; ok {
				seen[key] = true
				continue
			}
			t.Errorf("%s: stage gate %q is not tagged always, so --tags skips it while tagged tasks still run", rel, name)
		}
	}
	if plays < 50 {
		t.Fatalf("only %d plays with tagged tasks found; the walker is broken", plays)
	}
	for key := range stageGateNotAlwaysAllowlist {
		if !seen[key] {
			t.Errorf("stageGateNotAlwaysAllowlist entry %q no longer matches — drop it", key)
		}
	}
}

// TestRegression_ApplyPlaysWithConfirmGateHaveCrossCheck locks AGENTS.md
// §4.3: every apply play that gates on confirm_staging/confirm_prod also
// asserts that the stage matches the host's staging/prod inventory group.
// freeipa-ca-trust, internal-endpoint (both plays) and reverse-proxy had no
// such check until 2026-09-25, although §4.3 said every playbook had it.
func TestRegression_ApplyPlaysWithConfirmGateHaveCrossCheck(t *testing.T) {
	checked := 0
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		if !strings.HasPrefix(rel, "playbooks/apply/") {
			continue
		}
		missing, n := playsMissingCrossCheck(loadYAML(t, path))
		checked += n
		for _, play := range missing {
			t.Errorf("%s: play %q has a confirm gate but no stage/inventory-group cross-check (AGENTS.md §4.3)", rel, play)
		}
	}
	if checked < 35 {
		t.Fatalf("only %d apply plays with a confirm gate found; the walker is broken", checked)
	}
}

func TestStageGateDetection(t *testing.T) {
	const src = `
- name: untagged gates in a tagged play
  hosts: all
  pre_tasks:
    - name: confirm
      ansible.builtin.assert: {that: ["(stage == 'sandbox') or (stage == 'prod' and confirm_prod | bool)"]}
    - name: xcheck
      tags: [always]
      ansible.builtin.assert: {that: ["not ('prod' in group_names and stage != 'prod')"]}
    - name: prod only
      ansible.builtin.assert: {that: ["path | length > 0"]}
      when: stage == 'prod'
    - name: unrelated input check
      ansible.builtin.assert: {that: ["foo is defined"]}
  tasks:
    - name: row task
      tags: [C1]
      ansible.builtin.debug: {msg: x}
- name: confirm gate, no cross-check
  hosts: all
  pre_tasks:
    - name: confirm
      tags: [always]
      ansible.builtin.assert: {that: ["stage == 'sandbox' or confirm_staging | bool"]}
- name: nothing tagged
  hosts: all
  pre_tasks:
    - name: confirm
      ansible.builtin.assert: {that: ["confirm_prod | bool"]}
  tasks:
    - ansible.builtin.debug: {msg: x}
`
	var doc any
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	gates, plays := stageGatesNotAlways(doc)
	if strings.Join(gates, ",") != "confirm,prod only" || plays != 1 {
		t.Errorf("stageGatesNotAlways = %v over %d plays, want [confirm prod only] over 1", gates, plays)
	}
	missing, n := playsMissingCrossCheck(doc)
	if strings.Join(missing, ",") != "confirm gate, no cross-check,nothing tagged" || n != 3 {
		t.Errorf("playsMissingCrossCheck = %v of %d, want the second and third play of 3", missing, n)
	}
}

// stageGatesNotAlways returns, for every play in doc with a task tagged
// other than `always`, the names of the asserts that read the stage but
// are not tagged `always` (own or inherited), and how many such plays it
// checked.
func stageGatesNotAlways(doc any) ([]string, int) {
	plays, _ := doc.([]any)
	var out []string
	checked := 0
	for _, p := range plays {
		play, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := play["hosts"]; !ok {
			continue
		}
		playTags := yamlTags(play)
		tagged := false
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks"} {
			walkTaskTree(play[section], playTags, func(_ map[string]any, tags []string) {
				if slices.ContainsFunc(tags, func(tag string) bool { return tag != "always" }) {
					tagged = true
				}
			})
		}
		if !tagged {
			continue
		}
		checked++
		for _, section := range []string{"pre_tasks", "tasks"} {
			walkTaskTree(play[section], playTags, func(task map[string]any, tags []string) {
				if isStageGate(task) && !slices.Contains(tags, "always") {
					name, _ := task["name"].(string)
					out = append(out, name)
				}
			})
		}
	}
	return out, checked
}

// playsMissingCrossCheck returns the names of the plays in doc that have a
// confirm_staging/confirm_prod assert but no assert comparing the stage
// with group_names, and how many plays with a confirm assert it checked.
func playsMissingCrossCheck(doc any) ([]string, int) {
	plays, _ := doc.([]any)
	var out []string
	checked := 0
	for _, p := range plays {
		play, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := play["hosts"]; !ok {
			continue
		}
		confirm, cross := false, false
		for _, section := range []string{"pre_tasks", "tasks"} {
			walkTaskTree(play[section], nil, func(task map[string]any, _ []string) {
				that := assertThat(task)
				if strings.Contains(that, "confirm_staging") || strings.Contains(that, "confirm_prod") {
					confirm = true
				}
				if strings.Contains(that, "group_names") && regexp.MustCompile(`\b(patch_)?stage\b`).MatchString(that) {
					cross = true
				}
			})
		}
		if !confirm {
			continue
		}
		checked++
		if !cross {
			name, _ := play["name"].(string)
			out = append(out, name)
		}
	}
	return out, checked
}

// isStageGate reports whether task is an assert whose that: or when: reads
// the stage or its confirm/attestation inputs.
func isStageGate(task map[string]any) bool {
	if _, ok := task["ansible.builtin.assert"]; !ok {
		if _, ok := task["assert"]; !ok {
			return false
		}
	}
	return stageGateText.MatchString(assertThat(task) + " " + fmt.Sprint(task["when"]))
}

// assertThat returns an assert task's that: as one string ("" for any other
// task).
func assertThat(task map[string]any) string {
	for _, module := range []string{"ansible.builtin.assert", "assert"} {
		if args, ok := task[module].(map[string]any); ok {
			return fmt.Sprint(args["that"])
		}
	}
	return ""
}

func playbookFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir("../../playbooks", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return files
}

func loadYAML(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: parse: %v", path, err)
	}
	return doc
}
