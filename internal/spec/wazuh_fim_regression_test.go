package spec

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegression_WazuhFimC1InstalledSelectionStates(t *testing.T) {
	s, err := Parse("../../docs/verification/wazuh-fim.md")
	if err != nil {
		t.Fatal(err)
	}
	command := ""
	for _, row := range s.Rows {
		if row.ID == "C1" {
			command = row.Command
		}
	}
	if command == "" {
		t.Fatal("missing C1 command")
	}
	directory := t.TempDir()
	grep, err := exec.LookPath("grep")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(grep, filepath.Join(directory, "grep")); err != nil {
		t.Fatal(err)
	}
	query := "#!/bin/sh\nprintf '%s\\n' \"$PILOT_DPKG_STATE\"\n"
	if err := os.WriteFile(filepath.Join(directory, "dpkg-query"), []byte(query), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"install ok installed", "hold ok installed", "hold ok config-files", "deinstall ok installed", "install reinstreq half-installed", ""} {
		t.Run(state, func(t *testing.T) {
			cmd := exec.Command("/bin/sh", "-c", command)
			cmd.Env = []string{"PATH=" + directory, "PILOT_DPKG_STATE=" + state}
			err := cmd.Run()
			wantInstalled := state == "install ok installed" || state == "hold ok installed"
			if (err == nil) != wantInstalled {
				t.Fatalf("C1 installed-state result for %q: %v", state, err)
			}
		})
	}
}

// TestRegression_WazuhFimSpec locks the structure of
// docs/verification/wazuh-fim.md (v1.6 — Wazuh agent FIM/syscheck with
// whodata on a per-host-overridable directory list, auditd-backed who-data
// attribution, optional enrollment against
// docs/verification/wazuh-manager.md):
//
//	C1/C2   wazuh-agent + auditd installed
//	C3/C4   wazuh-agent.service + auditd.service active
//	C5      at least one directory configured with check_all+whodata
//	        (host-agnostic — v1.1 dropped the literal /etc, /boot check
//	        since wazuh_fim_directories is now overridable per host)
//	C6      whodata provider explicitly set to "audit"
//	C7      /etc/hosts pins the wazuh-manager alias
//	C8      <address> in ossec.conf points at the wazuh-manager alias
//	C9      client.keys populated (agent-auth registration completed)
//	C10     native/package version equality, exact pin, service and stable journal
//	C11     who-data actually live: endpoint socket, connected audisp-af_unix stream,
//	        kernel wazuh_fim watch (a configured-but-never-started EL passed C1-C10)
//
// Cross-row invariants locked below:
//
//   - C1-C9 must all use positive-logic rc per
//     verification-spec-template.md trap 1.
//   - C9 must use the `sh -c '... && echo 0 || echo 1'` form.
//   - C5 must NOT hardcode a literal path (/etc or /boot) — v1.1's whole
//     point is that wazuh_fim_directories is overridable per host, so a
//     literal-path assertion would false-fail on hosts with a custom list.
//   - C7/C8 must reference the `wazuh-manager` alias (not a raw
//     site-specific IP/host), same design as audit-log-forwarding.md's
//     siem-log-server alias.
//   - No row may use ~active (matches inactive as a substring).
//   - wazuh_manager_host must be OPTIONAL: the apply playbook must not
//     hard-fail when it's omitted (local FIM whodata rules are independent
//     of whether a manager exists yet).
//   - wazuh_fim_directories must be a templated list (Jinja loop), not a
//     hardcoded pair of directory lines, so it's genuinely overridable
//     per-host (host_vars) rather than requiring a playbook edit.
//   - agent-auth (registration) must be idempotency-gated on client.keys
//     being empty/missing, not run unconditionally on every apply — running
//     it every time would re-request a key each run and thrash the
//     manager's agent list.
func TestRegression_WazuhFimSpec(t *testing.T) {
	const specPath = "../../docs/verification/wazuh-fim.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	cmd := map[string]string{}
	exp := map[string]string{}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}
	for _, r := range s.Rows {
		cmd[r.ID] = r.Command
		exp[r.ID] = strings.TrimSpace(r.Expected)
		switch strings.ToLower(exp[r.ID]) {
		case "ok", "normal", "reasonable", "sufficient", "合理", "正常", "足夠":
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// All rows are rc-based numeric `0`.
	for _, id := range wantIDs {
		if exp[id] != "0" {
			t.Errorf("%s expected must be rc-based `0`, got %q", id, exp[id])
		}
	}
	for _, id := range []string{"C1", "C2"} {
		if !strings.Contains(cmd[id], "command -v rpm") ||
			!strings.Contains(cmd[id], "dpkg-query") {
			t.Errorf("%s package probe must support both EL rpm and Ubuntu dpkg, got %q", id, cmd[id])
		}
	}
	// EL needs the af_unix plugin package too: audit alone leaves the plugin `active = yes` with no binary.
	if !strings.Contains(cmd["C2"], "rpm -q audit audispd-plugins") {
		t.Errorf("C2 must check both EL packages that provide who-data (audit, audispd-plugins), got %q", cmd["C2"])
	}
	if !strings.Contains(cmd["C1"], "grep -qxE '(install|hold) ok installed'") {
		t.Errorf("C1 must recognize native held installed packages without accepting incomplete dpkg states: %q", cmd["C1"])
	}

	// C9 must use the `sh -c '... && echo 0 || echo 1'` form.
	if !strings.Contains(cmd["C9"], "&& echo 0") || !strings.Contains(cmd["C9"], "|| echo 1") {
		t.Errorf("C9 must use the `... && echo 0 || echo 1` form, got %q", cmd["C9"])
	}
	for _, token := range []string{"agent-verify", "--family", "/etc/debian_version", "/etc/redhat-release", "&& echo 0", "|| echo 1"} {
		if !strings.Contains(cmd["C10"], token) {
			t.Errorf("C10 native effective-state probe lacks %q", token)
		}
	}
	for _, token := range []string{"test -S /var/ossec/queue/sockets/audit", "ss -xHap", "ESTAB", "audisp-af_unix", "auditctl -l", "wazuh_fim", "&& echo 0", "|| echo 1"} {
		if !strings.Contains(cmd["C11"], token) {
			t.Errorf("C11 live who-data probe lacks %q: %q", token, cmd["C11"])
		}
	}
	for _, row := range s.Rows {
		if (row.ID == "C10" || row.ID == "C11") && !NeedsBecome(row) {
			t.Errorf("%s reads root-only state (coordinator / process names / kernel audit rules) and must execute with verify privilege escalation", row.ID)
		}
	}

	// C5 must gate on check_all+whodata attributes together, but must NOT
	// hardcode a specific path — the whole point of v1.1 is that the
	// directory list is host-overridable, so a literal /etc or /boot
	// assertion would false-fail on a host with a custom list.
	if !strings.Contains(cmd["C5"], `check_all="yes"`) || !strings.Contains(cmd["C5"], `whodata="yes"`) {
		t.Errorf("C5 must assert both check_all=\"yes\" and whodata=\"yes\", got %q", cmd["C5"])
	}
	if strings.Contains(cmd["C5"], ">/etc<") || strings.Contains(cmd["C5"], ">/boot<") {
		t.Errorf("C5 must not hardcode a literal monitored path (breaks per-host overrides), got %q", cmd["C5"])
	}

	// C7/C8 must reference the site-independent wazuh-manager alias.
	for _, id := range []string{"C7", "C8"} {
		if !strings.Contains(cmd[id], "wazuh-manager") {
			t.Errorf("%s must reference the wazuh-manager alias, got %q", id, cmd[id])
		}
	}

	// No row anywhere may use ~active (false-positives on "inactive").
	for _, r := range s.Rows {
		if strings.EqualFold(strings.TrimSpace(r.Expected), "~active") {
			t.Errorf("row %s uses ~active (matches inactive); use rc-based systemctl is-active", r.ID)
		}
	}

	playbookRaw, err := os.ReadFile("../../playbooks/apply/wazuh-fim-apply.yml")
	if err != nil {
		t.Fatalf("read wazuh-fim-apply.yml: %v", err)
	}
	applyRaw := string(playbookRaw)

	// wazuh_manager_host must be OPTIONAL.
	if strings.Contains(applyRaw, "Missing required var") || strings.Contains(applyRaw, "Assert required variables") {
		t.Errorf("wazuh-fim-apply.yml must not hard-require wazuh_manager_host; enrollment must be optional")
	}
	if !strings.Contains(applyRaw, "wazuh_manager_host | default(") {
		t.Errorf("wazuh-fim-apply.yml must use default() filter for wazuh_manager_host so group_vars can override")
	}
	if !strings.Contains(applyRaw, "wazuh_enrollment_enabled") {
		t.Errorf("wazuh-fim-apply.yml must derive a wazuh_enrollment_enabled gate from wazuh_manager_host")
	}

	// wazuh_fim_directories must be a real, templated (per-host overridable)
	// list, not a hardcoded pair of directory lines. Its default is set in
	// pre_tasks, not play vars:, which would outrank group_vars/host_vars.
	if !strings.Contains(applyRaw, `wazuh_fim_directories: "{{ wazuh_fim_directories | default(['/etc', '/boot']) }}"`) {
		t.Errorf("wazuh-fim-apply.yml must default wazuh_fim_directories to [\"/etc\", \"/boot\"]")
	}
	if !strings.Contains(applyRaw, "{% for dir in wazuh_fim_directories %}") {
		t.Errorf("wazuh-fim-apply.yml must render <directories> entries via a Jinja loop over wazuh_fim_directories (per-host overridable), not hardcoded lines")
	}

	// agent-auth must be idempotency-gated on client.keys being empty, not
	// run unconditionally on every apply.
	authIdx := strings.Index(applyRaw, "agent-auth -m")
	if authIdx < 0 {
		t.Fatalf("wazuh-fim-apply.yml must invoke agent-auth to register with the manager")
	}
	if !strings.Contains(applyRaw, "wazuh_client_keys_stat.stat.exists") && !strings.Contains(applyRaw, "wazuh_client_keys_stat.stat.size") {
		t.Errorf("wazuh-fim-apply.yml's agent-auth task must be gated on client.keys being empty/missing (idempotency), not run unconditionally")
	}

	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}

	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	covered := map[string]bool{}
	for _, tk := range pb.Tasks {
		for _, id := range tk.SourceIDs {
			covered[id] = true
		}
	}
	for _, id := range wantIDs {
		if !covered[id] {
			t.Errorf("spec row %s is not covered by any generated task", id)
		}
	}
}

// TestRegression_WazuhFimC11LiveWhoDataStates runs the C11 row's own shell over states captured on real hosts
// (testdata/native-captures: Ubuntu 24.04 and AlmaLinux 9). The only substitution is the endpoint path, which is a
// private socket so the test needs no /var/ossec; `ss` and `auditctl` answer from the captures through PATH shims,
// the pipeline and its matchers are the spec's. The row must pass for a live endpoint and fire for every state in
// which who-data is not really working, including the one that made C1-C10 pass on a broken EL: no endpoint at all.
func TestRegression_WazuhFimC11LiveWhoDataStates(t *testing.T) {
	s, err := Parse("../../docs/verification/wazuh-fim.md")
	if err != nil {
		t.Fatal(err)
	}
	command := ""
	for _, row := range s.Rows {
		if row.ID == "C11" {
			command = row.Command
		}
	}
	if command == "" {
		t.Fatal("missing C11 command")
	}
	capture := func(name string) string {
		path, err := filepath.Abs(filepath.Join("testdata", "native-captures", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	type state struct {
		name, ss, auditctl string
		socket, want       bool
	}
	states := []state{
		// Live: a connected stream on the endpoint and the kernel watches (Ubuntu 24.04 capture).
		{"live endpoint with kernel watches", "ss-xHap.audit-endpoint.healthy.ubuntu2404.txt", "auditctl-l.wazuh_fim.ubuntu2404.txt", true, true},
		// AlmaLinux 9 capture of the same live state after the fixed apply.
		{"live endpoint with kernel watches, EL", "ss-xHap.audit-endpoint.healthy.almalinux9.txt", "auditctl-l.wazuh_fim.almalinux9.txt", true, true},
		// The agent is stopped: the plugin still listens but nobody is connected and the watches are gone.
		{"agent stopped", "ss-xHap.audit-endpoint.agent-stopped.ubuntu2404.txt", "auditctl-l.no-rules.ubuntu2404.txt", true, false},
		// Connected but no kernel watch, and a watch with nobody connected: each half alone is not who-data.
		{"connected stream without kernel watch", "ss-xHap.audit-endpoint.healthy.ubuntu2404.txt", "auditctl-l.no-rules.ubuntu2404.txt", true, false},
		{"kernel watch without a connected stream", "ss-xHap.audit-endpoint.agent-stopped.ubuntu2404.txt", "auditctl-l.wazuh_fim.ubuntu2404.txt", true, false},
		// Ubuntu capture: the plugin was deactivated and the socket FILE stayed behind with no listener.
		{"stale socket file, plugin gone", "ss-xHap.audit-endpoint.plugin-gone.ubuntu2404.txt", "auditctl-l.wazuh_fim.ubuntu2404.txt", true, false},
		// AlmaLinux capture of the pre-fix state: audispd-plugins absent, so no socket, no listener, no watch.
		{"no endpoint at all, EL without audispd-plugins", "ss-xHap.audit-endpoint.no-plugin.almalinux9.txt", "auditctl-l.no-rules.almalinux9.txt", false, false},
	}
	for _, tc := range states {
		t.Run(tc.name, func(t *testing.T) {
			// A fixed-shape directory: the endpoint path is substituted into the row's shell text, and the
			// default t.TempDir() keeps shell metacharacters of the subtest name (parentheses) in the path.
			directory, err := os.MkdirTemp("", "pilot-c11-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(directory) })
			endpoint := filepath.Join(directory, "audit")
			if tc.socket {
				listener, err := net.Listen("unix", endpoint)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
			}
			for _, name := range []string{"sh", "grep", "sed", "cat"} {
				path, err := exec.LookPath(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path, filepath.Join(directory, name)); err != nil {
					t.Fatal(err)
				}
			}
			shims := map[string]string{
				"ss":       "#!/bin/sh\nsed \"s#/var/ossec/queue/sockets/audit#$PILOT_ENDPOINT#g\" \"$PILOT_SS\"\n",
				"auditctl": "#!/bin/sh\ncat \"$PILOT_AUDITCTL\"\n",
			}
			for name, body := range shims {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("/bin/sh", "-c", strings.ReplaceAll(command, "/var/ossec/queue/sockets/audit", endpoint))
			cmd.Env = []string{"PATH=" + directory, "PILOT_ENDPOINT=" + endpoint,
				"PILOT_SS=" + capture(tc.ss), "PILOT_AUDITCTL=" + capture(tc.auditctl)}
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("the row's own shell must always return 0 and print its verdict: %v", err)
			}
			want := "1"
			if tc.want {
				want = "0"
			}
			if got := strings.TrimSpace(string(out)); got != want {
				t.Fatalf("C11 printed %q, want %q for %s", got, want, tc.name)
			}
		})
	}
}
