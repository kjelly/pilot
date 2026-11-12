package spec

import (
	"encoding/json"
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
// docs/verification/wazuh-fim.md (v1.7 — Wazuh agent FIM/syscheck with
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
//	C11     EL who-data endpoint is a listening socket with a connected wazuh-syscheckd
//	        (a configured-but-never-started EL passed C1-C10; Issue #323)
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
	// C11 observes the endpoint through the kernel's socket table. It is listener-agnostic (an external
	// audisp-af_unix and auditd's builtin af_unix are both fine: Ubuntu 22.04 passed no exact-listener predicate) and
	// does not read kernel watches (audit-log-forwarding's augenrules flush leaves 0 of them with a live endpoint,
	// #324): naming either brings back the predicates that failed a working host or collided with #324.
	for _, token := range []string{"/etc/redhat-release", "test -S /var/ossec/queue/sockets/audit", "ss -xHap", "LISTEN", "ESTAB", "wazuh-syscheckd", "$6", "$8", "then echo 0", "else echo 1"} {
		if !strings.Contains(cmd["C11"], token) {
			t.Errorf("C11 live who-data probe lacks %q: %q", token, cmd["C11"])
		}
	}
	for _, token := range []string{"audisp-af_unix", "auditctl", "wazuh_fim", "pgrep", "ps "} {
		if strings.Contains(cmd["C11"], token) {
			t.Errorf("C11 must stay listener-agnostic and watch-free; it names %q: %q", token, cmd["C11"])
		}
	}
	for _, row := range s.Rows {
		if (row.ID == "C10" || row.ID == "C11") && !NeedsBecome(row) {
			t.Errorf("%s reads root-only state (coordinator / process names and root-owned sockets) and must execute with verify privilege escalation", row.ID)
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

// c11State is one `ss -xHap` snapshot with the facts around it, and the verdict C11 must print for it.
type c11State struct {
	name    string
	ss      string
	socket  bool   // the endpoint path is a socket inode
	redhat  bool   // /etc/redhat-release exists (an EL host)
	want    bool   // C11 prints 0
	derived string // empty: the ss text is an unedited capture from a real host; otherwise how it was MODELED
}

// c11States builds the states from the committed native captures. Every state that is not an unedited capture is
// MODELED by editing a native one (a line removed, a program renamed, an inode pair altered) and names its edit; the
// state of an EL host after a HUP with no agent restart is itself a native capture.
func c11States(t *testing.T) []c11State {
	t.Helper()
	capture := func(name string) string {
		raw, err := os.ReadFile(filepath.Join("testdata", "native-captures", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	const endpoint = "/var/ossec/queue/sockets/audit"
	// edit rewrites every ss line (a line with at least the eight netid..peer-inode columns) through f.
	edit := func(text string, f func(fields []string, line string) (string, bool)) string {
		var out []string
		for _, line := range strings.Split(text, "\n") {
			if fields := strings.Fields(line); len(fields) >= 8 {
				var keep bool
				if line, keep = f(fields, line); !keep {
					continue
				}
			}
			out = append(out, line)
		}
		return strings.Join(out, "\n")
	}
	isClient := func(f []string, line string) bool {
		return f[0] == "u_str" && f[1] == "ESTAB" && strings.Contains(line, "wazuh-syscheckd")
	}
	isListen := func(f []string) bool { return f[1] == "LISTEN" && f[4] == endpoint }
	dropIf := func(drop func(f []string, line string) bool) func([]string, string) (string, bool) {
		return func(f []string, line string) (string, bool) { return line, !drop(f, line) }
	}
	healthy := capture("ss-xHap.audit-endpoint.healthy.almalinux9.txt")
	stopped := capture("ss-xHap.audit-endpoint.agent-stopped.ubuntu2404.txt")
	return []c11State{
		{"live endpoint, external listener (AlmaLinux 9 capture)", healthy, true, true, true, ""},
		{"live endpoint, external listener (Ubuntu 24.04 capture, syscheckd line first)", capture("ss-xHap.audit-endpoint.healthy.ubuntu2404.txt"), true, true, true, ""},
		{"live endpoint, auditd itself listening", strings.ReplaceAll(healthy, `"audisp-af_unix"`, `"auditd"`), true, true, true,
			"AlmaLinux 9 capture with the listening program renamed (no native capture of a builtin listener is committed)"},
		{"listener only, no stream (agent stopped; Ubuntu 24.04 capture)", stopped, true, true, false, ""},
		{"no endpoint at all, EL without audispd-plugins (empty AlmaLinux 9 capture)", capture("ss-xHap.audit-endpoint.no-plugin.almalinux9.txt"), false, true, false, ""},
		{"stale socket file, nothing listens (empty Ubuntu 24.04 capture, plugin gone)", capture("ss-xHap.audit-endpoint.plugin-gone.ubuntu2404.txt"), true, true, false, ""},
		// Native AlmaLinux 9.8 (audit 3.1.5): auditd sent one SIGHUP with audispd-plugins installed and no agent restart;
		// the capture is the endpoint-path lines of `ss -xHap` (`grep -F sockets/audit`), trailing column padding stripped.
		{"EL listener after HUP alone: no syscheckd stream (AlmaLinux 9.8 capture)", capture("ss-xHap.audit-endpoint.hup-only.almalinux9.txt"), true, true, false, ""},
		{"accepted server side without a syscheckd client", edit(healthy, dropIf(isClient)), true, true, false, "AlmaLinux 9 capture without the syscheckd stream line"},
		{"syscheckd stream that is not the peer of the endpoint", edit(healthy, func(f []string, l string) (string, bool) {
			if isClient(f, l) {
				l = strings.NewReplacer("42613", "99999", "43081", "88888").Replace(l)
			}
			return l, true
		}), true, true, false, "AlmaLinux 9 capture with the syscheckd stream's inodes changed"},
		{"connected pair but nothing listens", edit(healthy, dropIf(func(f []string, l string) bool { return isListen(f) })), true, true, false, "AlmaLinux 9 capture without the LISTEN line"},
		{"the live state, but the endpoint path is not a socket", healthy, false, true, false, ""},
		{"a Debian host is not covered: 0 whatever the sockets say", stopped, false, false, true, ""},
	}
}

// TestRegression_WazuhFimC11LiveWhoDataStates runs the C11 row's own shell over c11States and, over the same texts,
// the coordinator's predicate (AuditRuntime.parse_streams, which the ordinary apply's agent-whodata-ensure uses to
// choose between no-op, restart and refusal). Both must give the verdict the table states, so the spec row and the
// code that repairs the host cannot drift apart, and the row must fire for every state in which who-data is not
// really connected, including the one that made C1-C10 pass on a broken EL (no endpoint at all).
//
// The row's shell and matchers are the spec's. The only substitutions are the endpoint path (a private socket, so no
// /var/ossec is needed) and /etc/redhat-release (a private file). `ss` answers through a PATH shim and no other tool
// of the target exists on PATH, notably no `auditctl`: a row that needed kernel watches would fail the live states.
// The row runs under every awk this machine has because the targets (gawk on EL) and CI differ.
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
	states := c11States(t)

	// The coordinator's reading of the same texts. The texts carry the real endpoint path, which parse_streams expects.
	wazuhHarnessReady(t, "C11 coordinator-predicate parity")
	texts := make([]string, len(states))
	for i, st := range states {
		texts[i] = st.ss
	}
	input, err := json.Marshal(texts)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := filepath.Abs("../../playbooks/apply/files/wazuh-transaction.py")
	if err != nil {
		t.Fatal(err)
	}
	py := exec.Command("python3", "-I", "-B", "-c", `import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("coordinator", sys.argv[1])
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
print(json.dumps([w.AuditRuntime.parse_streams(text) for text in json.load(sys.stdin)]))`, coordinator)
	py.Env = wazuhHarnessEnv()
	py.Stdin = strings.NewReader(string(input))
	out, err := py.Output()
	if err != nil {
		t.Fatalf("coordinator predicate: %v", err)
	}
	var streams []map[string]bool
	if err := json.Unmarshal(out, &streams); err != nil || len(streams) != len(states) {
		t.Fatalf("coordinator predicate output %q: %v", out, err)
	}

	awks := map[string]string{} // resolved path -> name
	for _, name := range []string{"awk", "mawk", "gawk"} {
		if path, err := exec.LookPath(name); err == nil {
			if real, err := filepath.EvalSymlinks(path); err == nil {
				awks[real] = name
			}
		}
	}
	if len(awks) == 0 {
		t.Fatal("no awk on PATH; the C11 row needs one")
	}

	for i, st := range states {
		// AuditRuntime.connected: the endpoint is a socket with a listener and a connected syscheckd. The coordinator
		// only ever runs on an EL host (the RedHat-family gate), so a Debian state has no coordinator verdict.
		if got := st.socket && streams[i]["listening"] && streams[i]["connected"]; st.redhat && got != st.want {
			t.Errorf("coordinator predicate for %q = %v, want %v (listening=%v connected=%v)", st.name, got, st.want, streams[i]["listening"], streams[i]["connected"])
		}
		for awkPath, awkName := range awks {
			t.Run(awkName+"/"+st.name, func(t *testing.T) {
				// A fixed-shape directory: the endpoint path is substituted into the row's shell text, and the default
				// t.TempDir() keeps shell metacharacters of the subtest name in the path.
				directory, err := os.MkdirTemp("", "pilot-c11-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(directory) })
				socketPath := filepath.Join(directory, "audit")
				if st.socket {
					listener, err := net.Listen("unix", socketPath)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = listener.Close() })
				}
				release := filepath.Join(directory, "redhat-release")
				if st.redhat {
					if err := os.WriteFile(release, []byte("AlmaLinux release 9\n"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(awkPath, filepath.Join(directory, "awk")); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"sh", "sed", "cat"} {
					path, err := exec.LookPath(name)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(path, filepath.Join(directory, name)); err != nil {
						t.Fatal(err)
					}
				}
				shim := "#!/bin/sh\nsed \"s#/var/ossec/queue/sockets/audit#$PILOT_ENDPOINT#g\" \"$PILOT_SS\"\n"
				if err := os.WriteFile(filepath.Join(directory, "ss"), []byte(shim), 0o755); err != nil {
					t.Fatal(err)
				}
				ssFile := filepath.Join(directory, "ss.txt")
				if err := os.WriteFile(ssFile, []byte(st.ss), 0o644); err != nil {
					t.Fatal(err)
				}
				text := strings.ReplaceAll(strings.ReplaceAll(command, "/var/ossec/queue/sockets/audit", socketPath), "/etc/redhat-release", release)
				cmd := exec.Command("/bin/sh", "-c", text)
				cmd.Env = []string{"PATH=" + directory, "PILOT_ENDPOINT=" + socketPath, "PILOT_SS=" + ssFile}
				out, err := cmd.Output()
				if err != nil {
					t.Fatalf("the row's own shell must always return 0 and print its verdict: %v", err)
				}
				want := "1"
				if st.want {
					want = "0"
				}
				if got := strings.TrimSpace(string(out)); got != want {
					t.Fatalf("C11 printed %q, want %q (%s; modeled from: %q)", got, want, st.name, st.derived)
				}
			})
		}
	}
}
