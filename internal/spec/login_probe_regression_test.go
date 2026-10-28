package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/loginprobe"
	"go.yaml.in/yaml/v3"
)

// TestRegression_LoginProbeSpec locks the structure of
// docs/verification/login-probe.md (GitHub issue kjelly/pilot#11) and the
// invariants the probe's Go contract and the apply playbook rely on:
//
//	C1  installed artifact + version format
//	C2  dedicated pilot-login-probe account + active service
//	C3  config schema validates
//	C4  private key 0600 owned by the service account, public key beside it
//	C5  ssh_config pins SSSD host-key trust and disables every other path
//	C6  no listener of its own
//	C7  textfile present, families declared, rewritten within 120 s
//	C8  no key material in textfile or journal
//	C9  canary resolves and has no sudo
//	C10 daemon rounds reach stage ok on at least one target
//	C11 one-shot probe --json works and only emits the fixed stage enum
//	C12 unit hardening (User, NoNewPrivileges, ProtectSystem=strict)
//	C13 every stage series published per target (verifyOnly)
//	C14 idempotent re-apply (verifyOnly)
func TestRegression_LoginProbeSpec(t *testing.T) {
	const specPath = "../../docs/verification/login-probe.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13", "C14"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	rows := map[string]*Row{}
	for i := range s.Rows {
		if s.Rows[i].ID != wantIDs[i] {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, wantIDs[i])
		}
		rows[s.Rows[i].ID] = &s.Rows[i]
	}

	for _, id := range []string{"C13", "C14"} {
		if !rows[id].VerifyOnly {
			t.Errorf("%s must be verifyOnly — scenario/multi-run evidence comes from the topology drills, not a single applied host", id)
		}
	}
	for _, r := range s.Rows {
		if r.VerifyOnly {
			continue
		}
		if len(r.Tags) != 1 || r.Tags[0] != r.ID {
			t.Errorf("%s: tags=%v, want exactly its own bare row ID (contracts/login-probe.yaml traceability.tag.kind=bare)", r.ID, r.Tags)
		}
	}

	// Verification never mutates the target.
	for _, r := range s.Rows {
		if r.Action != nil && r.Action.Mode != "readOnly" {
			t.Errorf("%s: action mode = %q, want readOnly", r.ID, r.Action.Mode)
		}
	}

	// C5 must pin the SSSD/FreeIPA host-key trust path (AGENTS.md §5.9: no
	// ssh-keyscan snapshot, no TOFU) and refuse every non-pubkey method.
	for _, want := range []string{
		"ProxyCommand /usr/bin/sss_ssh_knownhostsproxy -p %p %h",
		"StrictHostKeyChecking yes",
		"GlobalKnownHostsFile /var/lib/sss/pubconf/known_hosts",
		"PasswordAuthentication no",
		"KbdInteractiveAuthentication no",
		"GSSAPIAuthentication no",
		"BatchMode yes",
		"RequestTTY no",
	} {
		if !strings.Contains(rows["C5"].Command, want) {
			t.Errorf("C5 must require the ssh_config directive %q", want)
		}
	}
	if strings.Contains(strings.ToLower(rows["C5"].Command), "ssh-keyscan") {
		t.Error("C5 must never accept an ssh-keyscan snapshot as host-key trust")
	}

	// The spec's metric names are the Go package's: a rename on either side
	// must fail here, not on a live Prometheus.
	for id, want := range map[string]string{
		"C7":  loginprobe.MetricLastWrite,
		"C10": loginprobe.MetricSuccess,
		"C13": loginprobe.MetricLastStage,
	} {
		if !strings.Contains(rows[id].Command, want) {
			t.Errorf("%s must read %s", id, want)
		}
	}
	for _, stage := range loginprobe.AllStages {
		if !strings.Contains(rows["C13"].Command, string(stage)) || !strings.Contains(rows["C11"].Command, string(stage)) {
			t.Errorf("C11/C13 must enumerate stage %q (loginprobe.AllStages changed without updating the spec)", stage)
		}
	}

	// C8 is the issue's R2 guarantee: key material never reaches logs or metrics.
	for _, want := range []string{"PRIVATE KEY", "journalctl -u pilot-login-probe.service"} {
		if !strings.Contains(rows["C8"].Command, want) {
			t.Errorf("C8 must scan for %q", want)
		}
	}

	// C9 is the issue's R1 guarantee: a least-privileged canary with no sudo.
	if !strings.Contains(rows["C9"].Command, "is not allowed to run sudo") {
		t.Error("C9 must assert the real `sudo -l -U` denial wording captured on 2026-10-13")
	}

	// C10/C11 need longer than the 15s default: a failing target takes up to
	// login_probe_total_timeout, and C10 waits for the daemon's own round.
	if rows["C10"].Timeout.Seconds() < 120 || rows["C11"].Timeout.Seconds() < 60 {
		t.Errorf("C10/C11 timeouts too short: %s / %s", rows["C10"].Timeout, rows["C11"].Timeout)
	}

	// No credentials belong in a spec (AGENTS.md).
	for _, r := range s.Rows {
		lower := strings.ToLower(r.Command)
		for _, forbidden := range []string{"secret_key", "access_key", "api_key=", "password=", "-----begin"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s must not reference %q; got %q", r.ID, forbidden, r.Command)
			}
		}
	}

	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}
}

// TestRegression_LoginProbeTargetListRendering runs login-probe-apply.yml's
// own settings + target-computation tasks under the local ansible-core and
// checks the rendered target list: an inventory name that already is the
// FQDN keeps it (the host-decommission workflow keys FreeIPA clients that
// way), a short name gets the domain appended, login_probe_host overrides,
// and the decommission-only login_probe_exclude_targets removes a host by
// inventory name or FQDN, as a list or a bare string, case-insensitively.
func TestRegression_LoginProbeTargetListRendering(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	src, err := os.ReadFile("../../playbooks/apply/login-probe-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []struct {
		PreTasks []map[string]any `yaml:"pre_tasks"`
	}
	if err := yaml.Unmarshal(src, &plays); err != nil {
		t.Fatal(err)
	}
	var tasks []map[string]any
	for _, task := range plays[0].PreTasks {
		name, _ := task["name"].(string)
		if strings.HasPrefix(name, "Resolve login-probe settings") || strings.HasPrefix(name, "Compute the probe targets") {
			tasks = append(tasks, task)
		}
	}
	if len(tasks) != 2 {
		t.Fatalf("found %d of the 2 target-computation tasks", len(tasks))
	}
	tasks = append(tasks, map[string]any{"ansible.builtin.debug": map[string]any{"msg": "TARGETS={{ login_probe_target_list | map(attribute='name') | join(',') }}|HOSTS={{ login_probe_target_list | map(attribute='host') | join(',') }}"}})
	play := []map[string]any{{"hosts": "mon", "connection": "local", "gather_facts": false, "tasks": tasks}}
	dir := t.TempDir()
	playYAML, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	inv := `all:
  children:
    login-probe: {hosts: {mon: {}}}
    freeipa-client:
      hosts:
        mon: {}
        web1: {}
        db1.ipa.pilot.internal: {}
        legacy: {login_probe_host: Legacy-Alias.ipa.pilot.internal}
`
	for name, content := range map[string]string{"play.yml": string(playYAML), "inv.yml": inv} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(extra ...string) string {
		t.Helper()
		args := append([]string{"-i", "inv.yml", "play.yml"}, extra...)
		cmd := exec.Command("ansible-playbook", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("ansible-playbook %v: %v\n%s", extra, err, out)
		}
		m := regexp.MustCompile(`TARGETS=[^"]*`).FindString(string(out))
		if m == "" {
			t.Fatalf("no TARGETS line:\n%s", out)
		}
		return m
	}
	all := "TARGETS=db1.ipa.pilot.internal,legacy,mon,web1|HOSTS=db1.ipa.pilot.internal,legacy-alias.ipa.pilot.internal,mon.ipa.pilot.internal,web1.ipa.pilot.internal"
	for _, c := range []struct {
		extra []string
		want  string
	}{
		{nil, all},
		{[]string{"-e", `{"login_probe_exclude_targets": ["web1"]}`}, "TARGETS=db1.ipa.pilot.internal,legacy,mon|HOSTS=db1.ipa.pilot.internal,legacy-alias.ipa.pilot.internal,mon.ipa.pilot.internal"},
		{[]string{"-e", `{"login_probe_exclude_targets": ["DB1.ipa.pilot.internal"]}`}, "TARGETS=legacy,mon,web1|HOSTS=legacy-alias.ipa.pilot.internal,mon.ipa.pilot.internal,web1.ipa.pilot.internal"},
		{[]string{"-e", `{"login_probe_exclude_targets": ["web1.ipa.pilot.internal"]}`}, "TARGETS=db1.ipa.pilot.internal,legacy,mon|HOSTS=db1.ipa.pilot.internal,legacy-alias.ipa.pilot.internal,mon.ipa.pilot.internal"},
		{[]string{"-e", "login_probe_exclude_targets=LEGACY"}, "TARGETS=db1.ipa.pilot.internal,mon,web1|HOSTS=db1.ipa.pilot.internal,mon.ipa.pilot.internal,web1.ipa.pilot.internal"},
		{[]string{"-e", `{"login_probe_exclude_targets": ["unrelated"]}`}, all},
	} {
		if got := run(c.extra...); got != c.want {
			t.Errorf("%v:\n got %s\nwant %s", c.extra, got, c.want)
		}
	}
}

func TestRegression_LoginProbeRollbackCoversManagedState(t *testing.T) {
	apply, err := os.ReadFile("../../playbooks/apply/login-probe-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	source := string(apply)
	for _, want := range []string{
		"login_probe_rollback_paths:",
		"{{ login_probe_bin_dest }}",
		"{{ login_probe_key_path }}",
		"{{ login_probe_key_path }}.pub",
		"{{ login_probe_ssh_config_path }}",
		"{{ login_probe_config_path }}",
		"{{ login_probe_unit_path }}",
		"{{ login_probe_textfile_path }}",
		"ansible.builtin.service_facts:",
		"Snapshot every existing managed file before mutation",
		"ROLLBACK — restore every managed file that existed before apply",
		"ROLLBACK — remove managed files created by this failed first install",
		"ROLLBACK — restore pre-existing directory ownership and mode",
		"ROLLBACK — restore whether the service was enabled and active before apply",
		"ROLLBACK — restore the pre-existing service account attributes",
		"ROLLBACK — remove a service account created by this failed first install",
		"Private rollback snapshot retained at",
	} {
		if !strings.Contains(source, want) {
			t.Errorf("login-probe apply rollback is missing %q", want)
		}
	}
	if strings.Contains(source, "pilot-login-probe.prev") {
		t.Error("rollback must snapshot the complete managed state, not only the previous binary")
	}
	if !strings.Contains(source, "login_probe_exporter_metrics") ||
		!strings.Contains(source, "node_exporter_basic_auth_password") ||
		!strings.Contains(source, "pilot_login_probe_textfile_preflight") {
		t.Error("C7 apply must authenticate to node_exporter and prove it exposes a textfile metric")
	}
}

func TestRegression_LoginProbeExampleTargetsMatchStringListContract(t *testing.T) {
	example, err := os.ReadFile("../../group_vars/login-probe.example.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(example)
	for _, want := range []string{
		"- web01=web01.ipa.pilot.internal:22",
		"- web02=web02.ipa.pilot.internal",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("example explicit target must use contract string syntax %q", want)
		}
	}
	if strings.Contains(s, "{name: web01, host:") {
		t.Error("the documented target example is a map but the contract/playbook accept name=host[:port] strings")
	}
}

// loginProbePreTasks returns the named pre_tasks of login-probe-apply.yml,
// in playbook order, failing unless every prefix matched exactly one task.
func loginProbePreTasks(t *testing.T, prefixes ...string) []map[string]any {
	t.Helper()
	return playbookPreTasks(t, "../../playbooks/apply/login-probe-apply.yml", prefixes...)
}

// playbookPreTasks returns the named pre_tasks of the first play in path,
// in playbook order, failing unless every prefix matched exactly one task.
func playbookPreTasks(t *testing.T, path string, prefixes ...string) []map[string]any {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var plays []struct {
		PreTasks []map[string]any `yaml:"pre_tasks"`
	}
	if err := yaml.Unmarshal(src, &plays); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	seen := map[string]int{}
	for _, task := range plays[0].PreTasks {
		name, _ := task["name"].(string)
		for _, p := range prefixes {
			if strings.HasPrefix(name, p) {
				out = append(out, task)
				seen[p]++
			}
		}
	}
	for _, p := range prefixes {
		if seen[p] != 1 {
			t.Fatalf("%s has %d pre_tasks named %q..., want 1", path, seen[p], p)
		}
	}
	return out
}

// runLocalPlay runs tasks against localhost and returns the output and
// whether ansible-playbook succeeded.
func runLocalPlay(t *testing.T, vars map[string]any, tasks []map[string]any, extra ...string) (string, bool) {
	t.Helper()
	return runLocalPlayInventory(t, "", vars, tasks, extra...)
}

// runLocalPlayInventory is runLocalPlay against inventory inv (YAML; it must
// define localhost), so tasks can read other hosts' hostvars and groups.
// An empty inv means "localhost," only.
func runLocalPlayInventory(t *testing.T, inv string, vars map[string]any, tasks []map[string]any, extra ...string) (string, bool) {
	t.Helper()
	play := map[string]any{"hosts": "localhost", "connection": "local", "gather_facts": false, "vars": vars, "tasks": tasks}
	return runLocalPlays(t, inv, []map[string]any{play}, extra...)
}

// runLocalPlays runs plays, in order, as one ansible-playbook call against
// inventory inv (as for runLocalPlayInventory), so a fact one play sets is
// visible to the next, as between the playbooks site.yml imports.
func runLocalPlays(t *testing.T, inv string, plays []map[string]any, extra ...string) (string, bool) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("ansible-playbook not installed: %v (PILOT_REQUIRE_CONTAINER_TESTS=1)", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	dir := t.TempDir()
	data, err := yaml.Marshal(plays)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "play.yml"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	invArg := "localhost,"
	if inv != "" {
		invArg = filepath.Join(dir, "inv.yml")
		if err := os.WriteFile(invArg, []byte(inv), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("ansible-playbook", append([]string{"-i", invArg, "play.yml"}, extra...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// One unresolvable target must not block the deploy or a decommission
// re-render (it stays a target and the probe reports transport); no target
// resolving at all is a wrong domain or broken DNS and is refused (PR #80
// review). Runs the playbook's own resolve tasks with getent.
func TestRegression_LoginProbeUnresolvableTargetWarnsUnlessNoneResolve(t *testing.T) {
	tasks := loginProbePreTasks(t,
		"Gate: every target's FQDN resolves",
		"Gate: at least one target FQDN resolves",
		"Warn: these targets do not resolve")
	target := func(name, host string) map[string]any { return map[string]any{"name": name, "host": host, "port": 22} }
	for _, c := range []struct {
		name    string
		targets []map[string]any
		ok      bool
		warn    bool
	}{
		{"all resolve", []map[string]any{target("a", "localhost")}, true, false},
		{"one does not resolve", []map[string]any{target("a", "localhost"), target("b", "pilot-no-such-host.invalid")}, true, true},
		{"none resolve", []map[string]any{target("b", "pilot-no-such-host.invalid"), target("c", "pilot-no-such-host-2.invalid")}, false, false},
	} {
		out, ok := runLocalPlay(t, map[string]any{"login_probe_target_list": c.targets}, tasks)
		if ok != c.ok {
			t.Errorf("%s: ansible-playbook success = %v, want %v\n%s", c.name, ok, c.ok, out)
		}
		if warned := strings.Contains(out, "WARNING: ['pilot-no-such-host.invalid'] do not resolve"); warned != c.warn {
			t.Errorf("%s: warning printed = %v, want %v\n%s", c.name, warned, c.warn, out)
		}
		if !c.ok && !strings.Contains(out, "no probe target resolves") {
			t.Errorf("%s: refused without the no-target message:\n%s", c.name, out)
		}
	}
}

// --check --diff of an already-deployed probe host must not fail in the
// rollback snapshot: check mode does not create the snapshot directory, so
// copying an existing managed file into it failed every preview of a
// deployed host (found by a --check run on the PR #80 topology). Runs the
// playbook's own snapshot tasks in check mode with one existing file.
func TestRegression_LoginProbeSnapshotSkipsCheckMode(t *testing.T) {
	tasks := loginProbePreTasks(t,
		"Create the private rollback snapshot directory",
		"Snapshot every existing managed file before mutation")
	dir := t.TempDir()
	managed := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(managed, []byte("targets: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "backups", "apply-1-host")
	vars := map[string]any{
		"login_probe_rollback_dir":   snapshot,
		"login_probe_previous_files": []map[string]any{{"item": managed, "stat": map[string]any{"exists": true}}},
	}
	out, ok := runLocalPlay(t, vars, tasks, "--check", "--diff")
	if !ok {
		t.Fatalf("snapshot tasks fail under --check:\n%s", out)
	}
	if _, err := os.Stat(snapshot); !os.IsNotExist(err) {
		t.Errorf("--check created the snapshot directory %s (err=%v)", snapshot, err)
	}
}
