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
