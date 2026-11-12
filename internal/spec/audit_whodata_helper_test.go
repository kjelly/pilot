package spec

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Tests of playbooks/apply/files/audit-whodata.py on its own: what `probe` reads, what `rearm` waits for and
// the typed reasons it fails with. The system tools are PATH shims; the data they print is a real capture from
// a disposable Ubuntu 24.04.4 or AlmaLinux 9.8 VM (testdata/native-captures: `augenrules --check` in both
// outcomes, `auditctl -l` with the managed rules and the Wazuh watches, `systemctl show wazuh-agent` for
// active/inactive/not-found, the audisp-af_unix LISTEN line after an auditd restart, the coordinator's
// writer-inspect output), 2026-11-12. Text for states nobody captured is synthetic and named as such:
//
//   - `activating`/`deactivating`/`reloading` ActiveState values and a `systemctl` that cannot connect to the
//     bus (the shapes systemd documents; no VM was put in them);
//   - the `augenrules --check` line for an empty rules directory (from the script source), and an
//     `auditctl -l` failure text (only its non-zero exit matters).
//
// The probe is built so that none of them can make it read a failure as "nothing there": an unrecognised
// text or a non-zero exit is reported as such.

type probeShims struct {
	auditctl   string // stdout of `auditctl -l`; "-" = no auditctl on the host
	auditctlRC int
	augenrules string // stdout of `augenrules --check`; "-" = none
	augenRC    int
	agent      string // stdout of `systemctl show wazuh-agent ...`
	agentRC    int
}

func helperPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("../../playbooks/apply/files/audit-whodata.py")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func runProbe(t *testing.T, shims probeShims, rules string) map[string]any {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!"+shell+"\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	data := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if shims.auditctl != "-" {
		write("auditctl", "cat "+data("auditctl", shims.auditctl)+"\nexit "+strconv.Itoa(shims.auditctlRC)+"\n")
	}
	if shims.augenrules != "-" {
		write("augenrules", "cat "+data("augenrules", shims.augenrules)+"\nexit "+strconv.Itoa(shims.augenRC)+"\n")
	}
	write("systemctl", "cat "+data("agent", shims.agent)+"\nexit "+strconv.Itoa(shims.agentRC)+"\n")
	argv := []string{helperPath(t), "probe"}
	if rules != "" {
		path := data("rules", rules)
		argv = append(argv, "--rules", path)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(python, argv...)
	// The shims first, then only the interpreter's and the shell's own directories: a real auditctl or augenrules
	// (in /sbin on a host with auditd) on the machine running the test must not answer.
	command.Env = append(os.Environ(), "PATH="+bin+":"+filepath.Dir(python)+":/usr/bin:/bin")
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("probe output is not one JSON object: %v\n%s", err, out)
	}
	return doc
}

func TestAuditWhodataProbeReadsEveryStateWithoutGuessing(t *testing.T) {
	template := templateRules(t)
	wazuh := readCapture(t, "auditctl-l.wazuh_fim.ubuntu2404.txt")
	wazuhEL := readCapture(t, "auditctl-l.wazuh_fim.almalinux9.txt")
	noRules := readCapture(t, "auditctl-l.no-rules.ubuntu2404.txt")
	// Real captures of both outcomes of `augenrules --check` and of the agent unit's states.
	augenNoChange := readCapture(t, "augenrules-check.no-change.ubuntu2404.rc0.txt")
	augenChanged := readCapture(t, "augenrules-check.rules-changed.ubuntu2404.rc0.txt")
	agentActive := readCapture(t, "systemctl-show-wazuh-agent.active.ubuntu2404.rc0.txt")
	agentInactive := readCapture(t, "systemctl-show-wazuh-agent.inactive.almalinux9.rc0.txt")
	agentAbsent := readCapture(t, "systemctl-show-wazuh-agent.not-found.ubuntu2404.rc0.txt")
	// The real `auditctl -l` of the managed rules and the Wazuh watches: the managed lines alone, and both.
	managedAndWazuh := readCapture(t, "auditctl-l.managed-and-wazuh_fim.ubuntu2404.txt")
	managedListing := ""
	for _, line := range strings.SplitAfter(managedAndWazuh, "\n") {
		if !strings.Contains(line, "wazuh_fim") {
			managedListing += line
		}
	}
	cases := []struct {
		name  string
		shims probeShims
		rules string
		want  map[string]any
	}{
		{"agent active holding watches, Ubuntu capture",
			probeShims{auditctl: wazuh, augenrules: augenNoChange, agent: agentActive}, "",
			map[string]any{"agent": "active", "kernel": "ok", "watches": []any{"-w /boot -p wa -k wazuh_fim", "-w /etc -p wa -k wazuh_fim"}, "expected": []any{"-w /boot -p wa -k wazuh_fim", "-w /etc -p wa -k wazuh_fim"}}},
		{"agent active holding watches, EL capture",
			probeShims{auditctl: wazuhEL, augenrules: augenNoChange, agent: agentActive}, "",
			map[string]any{"agent": "active", "kernel": "ok", "watches": []any{"-w /boot -p wa -k wazuh_fim", "-w /etc -p wa -k wazuh_fim"}}},
		{"`No rules` is a readable, empty list, not a failure",
			probeShims{auditctl: noRules, augenrules: augenNoChange, agent: agentActive}, "",
			map[string]any{"agent": "active", "kernel": "ok", "watches": []any{}}},
		{"auditctl failing is unreadable, never an empty list",
			probeShims{auditctl: "Error - audit support not in kernel\n", auditctlRC: 1, augenrules: augenNoChange, agent: agentActive}, "",
			map[string]any{"agent": "active", "kernel": "unreadable", "watches": []any{}}},
		{"no auditctl on the host (a fresh VM before the package)",
			probeShims{auditctl: "-", augenrules: "-", agent: agentAbsent}, "",
			map[string]any{"agent": "absent", "kernel": "absent", "watches": []any{}}},
		{"EL capture: agent active, rules unchanged, managed rules and watches present",
			probeShims{auditctl: readCapture(t, "auditctl-l.managed-and-wazuh_fim.almalinux9.txt"), augenrules: readCapture(t, "augenrules-check.no-change.almalinux9.rc0.txt"), agent: readCapture(t, "systemctl-show-wazuh-agent.active.almalinux9.rc0.txt")}, template,
			map[string]any{"agent": "active", "kernel": "ok", "managed": "present", "augenrules": "no_change", "watches": []any{"-w /boot -p wa -k wazuh_fim", "-w /etc -p wa -k wazuh_fim"}}},
		{"EL capture: rules changed after a rules.d edit",
			probeShims{auditctl: noRules, augenrules: readCapture(t, "augenrules-check.rules-changed.almalinux9.rc0.txt"), agent: readCapture(t, "systemctl-show-wazuh-agent.not-found.almalinux9.rc0.txt")}, template,
			map[string]any{"agent": "absent", "managed": "missing", "augenrules": "changed"}},
		{"agent installed but stopped",
			probeShims{auditctl: noRules, augenrules: augenNoChange, agent: agentInactive}, "",
			map[string]any{"agent": "inactive"}},
		{"agent state that cannot be read is unknown",
			probeShims{auditctl: wazuh, augenrules: augenNoChange, agent: "Failed to connect to bus\n", agentRC: 1}, "",
			map[string]any{"agent": "unknown"}},
		{"agent state that is not the two properties asked for is unknown",
			probeShims{auditctl: wazuh, augenrules: augenNoChange, agent: "SomethingElse=1\n"}, "",
			map[string]any{"agent": "unknown"}},
		// Transitional states (synthetic: nobody put a VM in them; the values are systemd's documented ActiveState
		// values, and `activating` is also what an auto-restarting unit reports).
		{"a starting or auto-restarting agent is transitioning, not active and not unknown",
			probeShims{auditctl: wazuh, augenrules: augenNoChange, agent: "LoadState=loaded\nActiveState=activating\n"}, "",
			map[string]any{"agent": "transitioning", "expected": []any{}}},
		{"a stopping agent is transitioning",
			probeShims{auditctl: wazuh, augenrules: augenNoChange, agent: "LoadState=loaded\nActiveState=deactivating\n"}, "",
			map[string]any{"agent": "transitioning", "expected": []any{}}},
		{"a reloading agent is running, so it is active and its watches are the set to give back",
			probeShims{auditctl: wazuh, augenrules: augenNoChange, agent: "LoadState=loaded\nActiveState=reloading\n"}, "",
			map[string]any{"agent": "active", "expected": []any{"-w /boot -p wa -k wazuh_fim", "-w /etc -p wa -k wazuh_fim"}}},
		{"a failed unit is inactive",
			probeShims{auditctl: wazuh, augenrules: augenNoChange, agent: "LoadState=loaded\nActiveState=failed\n"}, "",
			map[string]any{"agent": "inactive", "expected": []any{}}},
		{"an ActiveState with no meaning here is unknown",
			probeShims{auditctl: wazuh, augenrules: augenNoChange, agent: "LoadState=loaded\nActiveState=maintenance\n"}, "",
			map[string]any{"agent": "unknown", "expected": []any{}}},
		{"the set to give back is empty for a stopped agent even when watches are listed",
			probeShims{auditctl: wazuh, augenrules: augenNoChange, agent: agentInactive}, "",
			map[string]any{"agent": "inactive", "kernel": "ok", "expected": []any{}}},
		{"the set to give back is empty when the list cannot be read",
			probeShims{auditctl: "boom\n", auditctlRC: 1, augenrules: augenNoChange, agent: agentActive}, "",
			map[string]any{"agent": "active", "kernel": "unreadable", "expected": []any{}}},
		{"no auditctl: nothing can hold a who-data watch, the set is empty and the state is absent, not unreadable",
			probeShims{auditctl: "-", augenrules: "-", agent: agentActive}, "",
			map[string]any{"agent": "active", "kernel": "absent", "expected": []any{}}},
		{"managed rules all in the kernel, augenrules sees no change",
			probeShims{auditctl: managedAndWazuh, augenrules: augenNoChange, agent: agentActive}, template,
			map[string]any{"managed": "present", "augenrules": "no_change"}},
		{"augenrules reports a difference",
			probeShims{auditctl: managedListing, augenrules: augenChanged, agent: agentAbsent}, template,
			map[string]any{"managed": "present", "augenrules": "changed"}},
		{"kernel list emptied behind an unchanged file",
			probeShims{auditctl: noRules, augenrules: augenNoChange, agent: agentAbsent}, template,
			map[string]any{"managed": "missing", "augenrules": "no_change"}},
		{"a key listed fewer times than the file declares it is missing (two setuid_setgid_exec rules)",
			probeShims{auditctl: strings.Replace(managedListing, "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=setuid_setgid_exec\n", "", 1), augenrules: augenNoChange, agent: agentAbsent}, template,
			map[string]any{"managed": "missing"}},
		{"the -k form of a key counts as well as -F key=",
			probeShims{auditctl: strings.ReplaceAll(managedListing, "-F key=", "-k "), augenrules: augenNoChange, agent: agentAbsent}, template,
			map[string]any{"managed": "present"}},
		{"an unreadable kernel list is unknown, never present",
			probeShims{auditctl: "boom\n", auditctlRC: 1, augenrules: augenNoChange, agent: agentAbsent}, template,
			map[string]any{"managed": "unknown"}},
		{"no rules file to compare (a preview on a host this role has not rendered)",
			probeShims{auditctl: noRules, augenrules: augenNoChange, agent: agentAbsent}, "",
			map[string]any{"kernel": "ok"}},
		{"augenrules text it does not know is unrecognized",
			probeShims{auditctl: noRules, augenrules: "/usr/sbin/augenrules: No rules\n", agent: agentAbsent}, template,
			map[string]any{"augenrules": "unrecognized"}},
		{"both outcomes at once is unrecognized",
			probeShims{auditctl: noRules, augenrules: augenNoChange + augenChanged, agent: agentAbsent}, template,
			map[string]any{"augenrules": "unrecognized"}},
		{"augenrules failing is unreadable",
			probeShims{auditctl: noRules, augenrules: "boom\n", augenRC: 1, agent: agentAbsent}, template,
			map[string]any{"augenrules": "unreadable"}},
		{"no augenrules on the host",
			probeShims{auditctl: noRules, augenrules: "-", agent: agentAbsent}, template,
			map[string]any{"augenrules": "absent"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := runProbe(t, tc.shims, tc.rules)
			for key, want := range tc.want {
				got, _ := json.Marshal(doc[key])
				wantJSON, _ := json.Marshal(want)
				if string(got) != string(wantJSON) {
					t.Errorf("%s = %s, want %s (document %v)", key, got, wantJSON, doc)
				}
			}
		})
	}
}

// The watch pattern is one text in three places: the Wazuh coordinator's AuditRuntime.ready (its own definition
// of "a who-data watch"), this role's helper, and the `auditctl -l | grep` of spec row C23. A copy that drifts
// would make the role give back watches the coordinator does not count, or the row pass on lines it ignores.
func TestRegression_WhodataWatchPatternHasOneSource(t *testing.T) {
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	pick := func(label, text, pattern string) string {
		match := regexp.MustCompile(pattern).FindStringSubmatch(text)
		if match == nil {
			t.Fatalf("%s: no watch pattern found", label)
		}
		return match[1]
	}
	coordinator := pick("coordinator", read("../../playbooks/apply/files/wazuh-transaction.py"), `re\.search\(r'([^']*wazuh_fim[^']*)'`)
	helper := pick("helper", read("../../playbooks/apply/files/audit-whodata.py"), `WAZUH_FIM_WATCH = r'([^']*)'`)
	if helper != coordinator {
		t.Fatalf("the helper's watch pattern %q differs from the coordinator's %q", helper, coordinator)
	}
	s, err := Parse("../../docs/verification/audit-log-forwarding.md")
	if err != nil {
		t.Fatal(err)
	}
	var row string
	for _, r := range s.Rows {
		if r.ID == "C23" {
			row = r.Command
		}
	}
	ere := pick("row C23", row, `grep -qE "([^"]*wazuh_fim[^"]*)"`)
	// The row is POSIX ERE and the others Python re; both are valid RE2, so Go can judge all three on the same lines.
	python, posix := regexp.MustCompile(coordinator), regexp.MustCompile(ere)
	lines := append(strings.Split(readCapture(t, "auditctl-l.wazuh_fim.ubuntu2404.txt"), "\n"),
		strings.Split(readCapture(t, "auditctl-l.wazuh_fim.almalinux9.txt"), "\n")...)
	lines = append(lines,
		"-w /etc -p wa -F key=wazuh_fim", "-a always,exit -F arch=b64 -S execve -F key=wazuh_fim",
		"-w /etc -p wa -k wazuh_fim_extra", "-w /etc -p wa -k wazuh_fimx", "-w /etc/wazuh_fim -p wa -k identity",
		"-w /etc -p wa -k  wazuh_fim", "-w /etc -p wa -k wazuh_fim ", "-w /etc -p wa -k my_wazuh_fim", "No rules", "")
	for _, line := range lines {
		if python.MatchString(line) != posix.MatchString(line) {
			t.Errorf("the coordinator/helper pattern and the C23 pattern disagree on %q (%t vs %t)", line, python.MatchString(line), posix.MatchString(line))
		}
	}
	for line, want := range map[string]bool{
		"-w /boot -p wa -k wazuh_fim":      true,
		"-w /etc -p wa -F key=wazuh_fim":   true,
		"-w /etc -p wa -k wazuh_fimx":      false,
		"-w /etc -p wa -k my_wazuh_fim":    false,
		"-w /etc/wazuh_fim -p wa -k ident": false,
		"No rules":                         false,
	} {
		if python.MatchString(line) != want {
			t.Errorf("the watch pattern on %q = %t, want %t", line, python.MatchString(line), want)
		}
	}
}

// runRearm runs `audit-whodata.py rearm` against the stateful shims of the runtime harness. It returns the
// decoded result, the exit status and the shim call log.
func runRearm(t *testing.T, expect []string, kernel []string, listener string, scenario map[string]any) (map[string]any, int, []string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	state := filepath.Join(dir, "state")
	for _, d := range []string{bin, state} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"systemctl", "auditctl", "ss"} {
		if err := os.WriteFile(filepath.Join(bin, tool), []byte("#!"+python+"\n"+auditWhodataShim), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	put := func(name, body string) {
		if err := os.WriteFile(filepath.Join(state, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scenario["wazuh_lines"] = expect
	scenario["rules_file"] = filepath.Join(dir, "none")
	raw, _ := json.Marshal(scenario)
	put("scenario.json", string(raw))
	if kernel == nil {
		kernel = []string{}
	}
	kernelJSON, _ := json.Marshal(kernel)
	put("kernel.json", string(kernelJSON))
	put("state.json", `{"agent": "active", "auditd": "active", "listener": "`+listener+`"}`)
	put("ss-up.txt", readCapture(t, "ss-xHap.audit-endpoint.healthy.ubuntu2404.txt"))
	put("ss-down.txt", readCapture(t, "ss-xHap.audit-endpoint.agent-stopped.ubuntu2404.txt")[:0])
	expectJSON, _ := json.Marshal(expect)
	command := exec.Command(python, helperPath(t), "rearm", "--expect-json", string(expectJSON),
		"--endpoint-timeout", "1", "--watch-timeout", "1", "--interval", "0.05")
	command.Env = append(os.Environ(), "PATH="+bin+":"+filepath.Dir(python)+":/usr/bin:/bin", "AUDIT_TEST_DIR="+state)
	out, err := command.Output()
	rc := 0
	if exit, ok := err.(*exec.ExitError); ok {
		rc = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("rearm output is not one JSON object: %v\n%s", err, out)
	}
	var calls []string
	if raw, err := os.ReadFile(filepath.Join(state, "calls")); err == nil {
		calls = strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	return doc, rc, calls
}

func TestAuditWhodataRearmWaitsRestartsOnceAndProves(t *testing.T) {
	watches := ruleLines(readCapture(t, "auditctl-l.wazuh_fim.ubuntu2404.txt"))
	restarts := func(calls []string) int {
		n := 0
		for _, call := range calls {
			if call == "systemctl restart wazuh-agent" {
				n++
			}
		}
		return n
	}
	t.Run("restored: one restart, and the watches are seen again", func(t *testing.T) {
		doc, rc, calls := runRearm(t, watches, nil, "up", map[string]any{})
		if rc != 0 || doc["state"] != "restored" || doc["restarted"] != true || restarts(calls) != 1 {
			t.Fatalf("rc=%d doc=%v calls=%v", rc, doc, calls)
		}
	})
	t.Run("the endpoint never comes back: typed, and the agent is not restarted into nothing", func(t *testing.T) {
		doc, rc, calls := runRearm(t, watches, nil, "down", map[string]any{})
		if rc != 1 || doc["reason"] != "endpoint_not_ready" || doc["restarted"] != false || restarts(calls) != 0 {
			t.Fatalf("rc=%d doc=%v calls=%v", rc, doc, calls)
		}
	})
	t.Run("the restart fails", func(t *testing.T) {
		doc, rc, calls := runRearm(t, watches, nil, "up", map[string]any{"agent_restart_fails": true})
		if rc != 1 || doc["reason"] != "agent_restart_failed" || restarts(calls) != 1 {
			t.Fatalf("rc=%d doc=%v calls=%v", rc, doc, calls)
		}
	})
	t.Run("the agent restarts and the watches never return: the missing ones are named", func(t *testing.T) {
		doc, rc, _ := runRearm(t, watches, []string{"-w /etc/passwd -p wa -k identity"}, "up", map[string]any{"agent_rearms": false})
		missing, _ := json.Marshal(doc["missing"])
		want, _ := json.Marshal(watches)
		if rc != 1 || doc["reason"] != "watches_not_restored" || string(missing) != string(want) {
			t.Fatalf("rc=%d doc=%v", rc, doc)
		}
	})
	t.Run("a kernel list that cannot be read is not 'no watches'", func(t *testing.T) {
		doc, rc, _ := runRearm(t, watches, nil, "up", map[string]any{"auditctl_fails": true})
		if rc != 1 || doc["reason"] != "kernel_unreadable" {
			t.Fatalf("rc=%d doc=%v", rc, doc)
		}
	})
	t.Run("a partial return is not enough: every watch of S must be back", func(t *testing.T) {
		// The agent comes back holding only one of the two watches it held before.
		doc, rc, _ := runRearm(t, watches, []string{watches[0]}, "up", map[string]any{"agent_rearms": false})
		missing, _ := json.Marshal(doc["missing"])
		want, _ := json.Marshal(watches[1:])
		if rc != 1 || doc["reason"] != "watches_not_restored" || string(missing) != string(want) {
			t.Fatalf("rc=%d doc=%v", rc, doc)
		}
	})
	t.Run("an empty expectation is refused, not treated as done", func(t *testing.T) {
		doc, rc, calls := runRearm(t, []string{}, nil, "up", map[string]any{})
		if rc != 2 || doc["reason"] != "bad_invocation" || restarts(calls) != 0 {
			t.Fatalf("rc=%d doc=%v calls=%v", rc, doc, calls)
		}
	})
}
