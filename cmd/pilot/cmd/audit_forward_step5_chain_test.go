package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The distro rsyslog policy chain of audit-log-forwarding-apply.yml (Step 5a to 5d),
// taken from the playbook as it is and run by real ansible-playbook against a copy of
// the policy, then judged by real logrotate:
//
//   - the paths the policy rotates other than the managed one survive the apply
//     whatever their spelling (flush-left, indented, quoted, ~): logrotate's own list
//     of considered logs, with the managed /etc/logrotate.d/syslog next to the rewritten
//     file, is exactly the list before the apply;
//   - the file is removed only when nothing but the managed path was in it;
//   - a second apply changes nothing;
//   - a policy the helper cannot handle safely stops the run with the file untouched.
//
// (The playbook's Step 5 writes the managed stanza before this chain and does not
// restore logrotate when a later task fails: kjelly/pilot#199, not covered here.)
type step5Run struct {
	rc          int
	changed     int
	failed      int
	out         string
	policy      string // the file after the run
	policyAlive bool
}

var step5Recap = regexp.MustCompile(`localhost\s+: ok=(\d+)\s+changed=(\d+)\s+unreachable=\d+\s+failed=(\d+)`)

func step5Playbook(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRootForTest(t), "playbooks", "apply", "audit-log-forwarding-apply.yml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	a := strings.Index(s, "        - name: \"Step 5a:")
	b := strings.Index(s, "        - name: \"Step 6a:")
	if a < 0 || b < a {
		t.Fatal("cannot find Step 5a .. Step 6a in audit-log-forwarding-apply.yml")
	}
	block := strings.ReplaceAll(s[a:b], "/etc/logrotate.d/rsyslog", filepath.Join(dir, "rsyslog"))
	for _, bad := range []string{"dest: /etc", "path: /etc", " /etc/logrotate.d/rsyslog"} {
		if strings.Contains(block, bad) {
			t.Fatalf("the extracted block still touches %q:\n%s", bad, block)
		}
	}
	pb := "- hosts: localhost\n  gather_facts: false\n  vars:\n    audit_syslog_path: /var/log/syslog\n  tasks:\n" + block
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	awk, err := os.ReadFile(dropPathScript(t))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "files", "logrotate-drop-path.awk"), string(awk))
	writeFile(t, filepath.Join(dir, "p.yml"), pb)
	return filepath.Join(dir, "p.yml")
}

func runStep5(t *testing.T, dir, playbook string) step5Run {
	t.Helper()
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", "-c", "local", playbook)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_INVENTORY_UNPARSED_WARNING=False",
		"ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "tmp"), "ANSIBLE_NOCOLOR=1", "ANSIBLE_FORCE_COLOR=0")
	out, err := cmd.CombinedOutput()
	r := step5Run{out: string(out)}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			r.rc = ee.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	if m := step5Recap.FindStringSubmatch(r.out); m != nil {
		r.changed, _ = strconv.Atoi(m[2])
		r.failed, _ = strconv.Atoi(m[3])
	} else {
		t.Fatalf("no recap in ansible output:\n%s", r.out)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "rsyslog")); err == nil {
		r.policy, r.policyAlive = string(b), true
	}
	return r
}

func TestAuditLogForwardingStep5ChainUnderAnsible(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip("ansible-playbook not installed")
	}
	logrotate, err := exec.LookPath("logrotate")
	if err != nil {
		t.Skip("logrotate not installed")
	}
	const tail = "\n\trotate 4\n}\n"
	type tc struct {
		name, policy string
		// kept: the file stays (true) or goes (false); fails: ansible fails and the file is untouched
		kept, fails bool
		// every one of these must be in the file afterwards
		contains []string
		// the managed path is declared by the policy exactly once (so logrotate's list must equal)
		compare bool
	}
	for _, c := range []tc{
		{name: "Ubuntu 22.04+: the managed path alone in the only stanza goes with the file",
			policy: "/var/log/syslog\n{\n\trotate 7\n\tpostrotate\n\t\t/usr/lib/rsyslog/rsyslog-rotate\n\tendscript\n}\n", kept: false, compare: true},
		{name: "a lone stanza with only comments around it goes with the file",
			policy: "# vendor\n\n/var/log/syslog\n{\n\trotate 7\n}\n# end\n", kept: false, compare: true},
		{name: "Ubuntu 24.04: lone stanza first, others after",
			policy: "/var/log/syslog\n{\n\trotate 7\n}\n\n/var/log/mail.log\n/var/log/kern.log\n{\n\trotate 4\n}\n", kept: true, compare: true,
			contains: []string{"/var/log/mail.log\n/var/log/kern.log\n{"}},
		{name: "quoted other paths",
			policy: "\"/var/log/mail.log\"\n\"/var/log/kern.log\"\n\"/var/log/syslog\"\n{\n\trotate 4\n\tweekly\n}\n", kept: true, compare: true,
			contains: []string{"\"/var/log/mail.log\"\n\"/var/log/kern.log\"\n{"}},
		{name: "indented other paths in their own stanza",
			policy: "/var/log/syslog\n{\n\trotate 7\n}\n\n  /var/log/mail.log\n  /var/log/kern.log\n{" + tail, kept: true, compare: true,
			contains: []string{"  /var/log/mail.log\n  /var/log/kern.log\n{"}},
		{name: "tilde other path",
			policy: "/var/log/syslog\n{\n\trotate 7\n}\n\n~/mail.log\n{" + tail, kept: true, compare: true, contains: []string{"~/mail.log\n{"}},
		{name: "tab indented paths sharing a stanza",
			policy: "\t/var/log/syslog\n\t/var/log/mail.log {" + tail, kept: true, compare: true, contains: []string{"\t/var/log/mail.log {"}},
		{name: "another path with an escaped quote",
			policy: "/var/log/syslog \"/var/log/mail\\\".log\"\n{" + tail, kept: true, compare: true, contains: []string{"\"/var/log/mail\\\".log\"\n{"}},
		{name: "a script that holds the path text",
			policy: "/var/log/other {\n\trotate 7\n\tpostrotate\n\t/var/log/syslog\n\tendscript\n}\n\n/var/log/syslog\n/var/log/mail.log\n{" + tail, kept: true, compare: true,
			contains: []string{"\tpostrotate\n\t/var/log/syslog\n\tendscript\n}", "/var/log/mail.log\n{"}},
		{name: "words that are data after the managed path",
			policy: "/var/log/syslog # vendor default\n{" + tail, kept: true, compare: true},
		{name: "a policy that does not declare the managed path stays as it is",
			policy: "\"/var/log/mail.log\" {" + tail, kept: true, contains: []string{"\"/var/log/mail.log\" {"}},
		{name: "a kept glob that covers the managed path stops the run",
			policy: "/var/log/syslog /var/log/sys* {" + tail, kept: true, fails: true},
		{name: "a byte that is not UTF-8 stops the run",
			policy: "/var/log/syslog /var/log/\xff.log {" + tail, kept: true, fails: true},
		{name: "a policy logrotate rejects stops the run",
			policy: "/var/log/other\n{\n\trotate 7\n\t/var/log/syslog\n}\n", kept: true, fails: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			playbook := step5Playbook(t, dir)
			writeFile(t, filepath.Join(dir, "rsyslog"), c.policy)
			if err := os.Chmod(filepath.Join(dir, "rsyslog"), 0o644); err != nil {
				t.Fatal(err)
			}
			first := runStep5(t, dir, playbook)
			if c.fails {
				if first.rc == 0 || first.failed == 0 {
					t.Fatalf("ansible did not fail (rc %d):\n%s", first.rc, first.out)
				}
				if !first.policyAlive || first.policy != c.policy {
					t.Fatalf("the policy changed although the run failed:\n%q", first.policy)
				}
				return
			}
			if first.rc != 0 {
				t.Fatalf("ansible rc %d:\n%s", first.rc, first.out)
			}
			if first.policyAlive != c.kept {
				t.Fatalf("file kept=%v, want %v; content %q\n%s", first.policyAlive, c.kept, first.policy, first.out)
			}
			for _, want := range c.contains {
				if !strings.Contains(first.policy, want) {
					t.Fatalf("%q is not in the policy afterwards:\n%q", want, first.policy)
				}
			}
			second := runStep5(t, dir, playbook)
			if second.rc != 0 || second.changed != 0 {
				t.Fatalf("second apply: rc %d changed=%d (want 0, 0)\n%s", second.rc, second.changed, second.out)
			}
			if second.policyAlive != first.policyAlive || second.policy != first.policy {
				t.Fatalf("the second apply changed the policy:\n%q\n%q", first.policy, second.policy)
			}
			if c.compare {
				before := parseWithLogrotate(t, logrotate, map[string]string{"rsyslog": c.policy})
				files := map[string]string{"syslog": managedSyslogStanza}
				if first.policyAlive {
					files["rsyslog"] = first.policy
				}
				after := parseWithLogrotate(t, logrotate, files)
				if len(before.errors) > 0 || len(after.errors) > 0 || strings.Contains(after.raw, "duplicate log entry") {
					t.Fatalf("errors before %v, after %v\n%s", before.errors, after.errors, after.raw)
				}
				if strings.Join(before.considered, "\n") != strings.Join(after.considered, "\n") {
					t.Fatalf("logrotate considers %q after the apply, %q before\nfile now: %q", after.considered, before.considered, first.policy)
				}
			}
		})
	}
}
