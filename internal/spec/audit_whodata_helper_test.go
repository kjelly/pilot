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
// the typed reasons it fails with. The system tools are PATH shims; the data they print is, where it exists,
// a real capture from a disposable Ubuntu 24.04 or AlmaLinux 9 VM (testdata/native-captures). Three kinds of
// text have no real capture in the tree yet and are modelled from the native tools' own source and
// documentation instead; each is named pendingCapture... so a reader never takes it for evidence, and the
// target run supplies the real ones (see the runbook, section 5.6):
//
//   - `augenrules --check`, both outcomes: modelled from the augenrules script of audit 3.1.2/3.0.7 and
//     EL9's audit package (it exits 0 either way and prints "<path>: No change" or
//     "<path>: Rules have changed and should be updated");
//   - `auditctl -l` of the rules this role renders (the syscall rules list their key as `-F key=...`);
//   - `systemctl show wazuh-agent --property=LoadState --property=ActiveState`.
//
// The probe is built so that none of them can make it read a failure as "nothing there": an unrecognised
// text or a non-zero exit is reported as such.

const (
	pendingCaptureAugenrulesNoChange = "/usr/sbin/augenrules: No change\n"
	pendingCaptureAugenrulesChanged  = "/usr/sbin/augenrules: Rules have changed and should be updated\n"
	pendingCaptureAuditctlManaged    = "-w /usr/bin/sudo -p x -k privileged-sudo\n" +
		"-w /etc/passwd -p wa -k identity\n" +
		"-w /etc/sudoers -p wa -k sudoers_changes\n" +
		"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=setuid_setgid_exec\n" +
		"-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=setuid_setgid_exec\n" +
		"-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F key=setuid_setgid_change\n"
	pendingCaptureAgentActive   = "LoadState=loaded\nActiveState=active\n"
	pendingCaptureAgentInactive = "LoadState=loaded\nActiveState=inactive\n"
	pendingCaptureAgentAbsent   = "LoadState=not-found\nActiveState=inactive\n"
)

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
	cases := []struct {
		name  string
		shims probeShims
		rules string
		want  map[string]any
	}{
		{"agent active holding watches, Ubuntu capture",
			probeShims{auditctl: wazuh, augenrules: pendingCaptureAugenrulesNoChange, agent: pendingCaptureAgentActive}, "",
			map[string]any{"agent": "active", "kernel": "ok", "watches": []any{"-w /boot -p wa -k wazuh_fim", "-w /etc -p wa -k wazuh_fim"}}},
		{"agent active holding watches, EL capture",
			probeShims{auditctl: wazuhEL, augenrules: pendingCaptureAugenrulesNoChange, agent: pendingCaptureAgentActive}, "",
			map[string]any{"agent": "active", "kernel": "ok", "watches": []any{"-w /boot -p wa -k wazuh_fim", "-w /etc -p wa -k wazuh_fim"}}},
		{"`No rules` is a readable, empty list, not a failure",
			probeShims{auditctl: noRules, augenrules: pendingCaptureAugenrulesNoChange, agent: pendingCaptureAgentActive}, "",
			map[string]any{"agent": "active", "kernel": "ok", "watches": []any{}}},
		{"auditctl failing is unreadable, never an empty list",
			probeShims{auditctl: "Error - audit support not in kernel\n", auditctlRC: 1, augenrules: pendingCaptureAugenrulesNoChange, agent: pendingCaptureAgentActive}, "",
			map[string]any{"agent": "active", "kernel": "unreadable", "watches": []any{}}},
		{"no auditctl on the host (a fresh VM before the package)",
			probeShims{auditctl: "-", augenrules: "-", agent: pendingCaptureAgentAbsent}, "",
			map[string]any{"agent": "absent", "kernel": "absent", "watches": []any{}}},
		{"agent installed but stopped",
			probeShims{auditctl: noRules, augenrules: pendingCaptureAugenrulesNoChange, agent: pendingCaptureAgentInactive}, "",
			map[string]any{"agent": "inactive"}},
		{"agent state that cannot be read is unknown",
			probeShims{auditctl: wazuh, augenrules: pendingCaptureAugenrulesNoChange, agent: "Failed to connect to bus\n", agentRC: 1}, "",
			map[string]any{"agent": "unknown"}},
		{"agent state that is not the two properties asked for is unknown",
			probeShims{auditctl: wazuh, augenrules: pendingCaptureAugenrulesNoChange, agent: "SomethingElse=1\n"}, "",
			map[string]any{"agent": "unknown"}},
		{"a starting agent is unknown, not active",
			probeShims{auditctl: wazuh, augenrules: pendingCaptureAugenrulesNoChange, agent: "LoadState=loaded\nActiveState=activating\n"}, "",
			map[string]any{"agent": "unknown"}},
		{"managed rules all in the kernel, augenrules sees no change",
			probeShims{auditctl: pendingCaptureAuditctlManaged + wazuh, augenrules: pendingCaptureAugenrulesNoChange, agent: pendingCaptureAgentActive}, template,
			map[string]any{"managed": "present", "augenrules": "no_change"}},
		{"augenrules reports a difference",
			probeShims{auditctl: pendingCaptureAuditctlManaged, augenrules: pendingCaptureAugenrulesChanged, agent: pendingCaptureAgentAbsent}, template,
			map[string]any{"managed": "present", "augenrules": "changed"}},
		{"kernel list emptied behind an unchanged file",
			probeShims{auditctl: noRules, augenrules: pendingCaptureAugenrulesNoChange, agent: pendingCaptureAgentAbsent}, template,
			map[string]any{"managed": "missing", "augenrules": "no_change"}},
		{"a key listed fewer times than the file declares it is missing (two setuid_setgid_exec rules)",
			probeShims{auditctl: strings.Replace(pendingCaptureAuditctlManaged, "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=setuid_setgid_exec\n", "", 1), augenrules: pendingCaptureAugenrulesNoChange, agent: pendingCaptureAgentAbsent}, template,
			map[string]any{"managed": "missing"}},
		{"the -k form of a key counts as well as -F key=",
			probeShims{auditctl: strings.ReplaceAll(pendingCaptureAuditctlManaged, "-F key=", "-k "), augenrules: pendingCaptureAugenrulesNoChange, agent: pendingCaptureAgentAbsent}, template,
			map[string]any{"managed": "present"}},
		{"an unreadable kernel list is unknown, never present",
			probeShims{auditctl: "boom\n", auditctlRC: 1, augenrules: pendingCaptureAugenrulesNoChange, agent: pendingCaptureAgentAbsent}, template,
			map[string]any{"managed": "unknown"}},
		{"no rules file to compare (a preview on a host this role has not rendered)",
			probeShims{auditctl: noRules, augenrules: pendingCaptureAugenrulesNoChange, agent: pendingCaptureAgentAbsent}, "",
			map[string]any{"kernel": "ok"}},
		{"augenrules text it does not know is unrecognized",
			probeShims{auditctl: noRules, augenrules: "/usr/sbin/augenrules: No rules\n", agent: pendingCaptureAgentAbsent}, template,
			map[string]any{"augenrules": "unrecognized"}},
		{"both outcomes at once is unrecognized",
			probeShims{auditctl: noRules, augenrules: pendingCaptureAugenrulesNoChange + pendingCaptureAugenrulesChanged, agent: pendingCaptureAgentAbsent}, template,
			map[string]any{"augenrules": "unrecognized"}},
		{"augenrules failing is unreadable",
			probeShims{auditctl: noRules, augenrules: "boom\n", augenRC: 1, agent: pendingCaptureAgentAbsent}, template,
			map[string]any{"augenrules": "unreadable"}},
		{"no augenrules on the host",
			probeShims{auditctl: noRules, augenrules: "-", agent: pendingCaptureAgentAbsent}, template,
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
