package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// The distro rsyslog policy handling of audit-log-forwarding-apply.yml: Step 1d (the
// preflight), Step 5 (renders the managed /etc/logrotate.d/syslog) and Step 5a to 5e
// (rewrite or remove /etc/logrotate.d/rsyslog), taken from the playbook as it is and
// run by real ansible-playbook against copies of the files, then judged by real
// logrotate:
//
//   - the paths the policy rotates other than the managed one survive the apply
//     whatever their spelling (flush-left, indented, quoted, ~) and whatever bytes the
//     file holds (a Latin-1 comment, a non-UTF-8 name);
//   - the file is removed only when nothing but the managed path was in it;
//   - a second apply changes nothing, a check-mode run writes nothing;
//   - when the helper (or logrotate's check of its output) cannot accept the policy the
//     play fails before ANY write: the managed stanza is not written, the policy is
//     untouched and no temporary directory is left behind. (Without the preflight the
//     managed stanza would already be there while the distro file still declares the
//     path: logrotate then aborts on "duplicate log entry". kjelly/pilot#199 is the
//     rescue that does not restore logrotate files; it is not covered here.)
//
// What the tree before the helper did with these inputs (BASE, `grep -cE '^/'` and
// lineinfile): quoted, indented and ~ paths deleted the whole policy; a Latin-1 byte
// anywhere was applied; a non-UTF-8 byte in a path line made grep treat the file as binary
// and deleted it.
type step5Run struct {
	rc          int
	changed     int
	failed      int
	out         string
	policy      string // the policy file after the run
	policyAlive bool
	managed     string // the managed stanza file after the run
	managedLive bool
	leftovers   []string // entries in the temp directory the playbook was given
}

var step5Recap = regexp.MustCompile(`localhost\s+: ok=(\d+)\s+changed=(\d+)\s+unreachable=\d+\s+failed=(\d+)`)

// step5Playbook writes the extracted tasks; withPreflight false leaves Step 1d out.
func step5Playbook(t *testing.T, dir string, withPreflight bool) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRootForTest(t), "playbooks", "apply", "audit-log-forwarding-apply.yml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	pa := strings.Index(s, "    # Step 1d:")
	pb := strings.Index(s, "    - block:\n        - name: \"Step 2:")
	a := strings.Index(s, "        - name: \"Step 5: Render /etc/logrotate.d/syslog\"")
	b := strings.Index(s, "        - name: \"Step 6a:")
	if pa < 0 || pb < pa || a < 0 || b < a {
		t.Fatal("cannot find Step 1d or Step 5 .. Step 6a in audit-log-forwarding-apply.yml")
	}
	pre := s[pa:pb]
	if !withPreflight {
		pre = ""
	}
	// the preflight is a play-level task (4 spaces); Step 5 is inside the block (8)
	var indented []string
	for _, l := range strings.Split(pre, "\n") {
		if l != "" {
			l = "    " + l
		}
		indented = append(indented, l)
	}
	block := strings.Join(indented, "\n") + s[a:b]
	block = strings.ReplaceAll(block, "/etc/logrotate.d/rsyslog", filepath.Join(dir, "rsyslog"))
	block = strings.ReplaceAll(block, "/etc/logrotate.d/syslog", filepath.Join(dir, "syslog"))
	// not root here
	block = regexp.MustCompile(`\n\s+owner: root\n\s+group: root`).ReplaceAllString(block, "")
	for _, bad := range []string{"dest: /etc", "path: /etc", " /etc/logrotate.d/", "f=/etc/"} {
		if strings.Contains(block, bad) {
			t.Fatalf("the extracted block still touches %q:\n%s", bad, block)
		}
	}
	pb2 := "- hosts: localhost\n  gather_facts: false\n  vars:\n    audit_syslog_path: /var/log/syslog\n    audit_syslog_group: root\n    syslog_logrotate_rotate: 14\n    syslog_logrotate_maxage: 90\n  tasks:\n" + block
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	awk, err := os.ReadFile(dropPathScript(t))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "files", "logrotate-drop-path.awk"), string(awk))
	name := "p.yml"
	if !withPreflight {
		name = "nopre.yml"
	}
	writeFile(t, filepath.Join(dir, name), pb2)
	return filepath.Join(dir, name)
}

type step5Opts struct {
	umask string   // "002": the whole run under that umask
	env   []string // added to the environment
}

func runStep5(t *testing.T, dir, playbook string, extra ...string) step5Run {
	t.Helper()
	return runStep5With(t, dir, playbook, step5Opts{}, extra...)
}

func runStep5With(t *testing.T, dir, playbook string, o step5Opts, extra ...string) step5Run {
	t.Helper()
	scratch := filepath.Join(dir, "scratch")
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-i", "localhost,", "-c", "local", playbook}, extra...)
	var cmd *exec.Cmd
	if o.umask != "" {
		cmd = exec.Command("sh", append([]string{"-c", "umask " + o.umask + "; exec \"$@\"", "sh", "ansible-playbook"}, args...)...)
	} else {
		cmd = exec.Command("ansible-playbook", args...)
	}
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_INVENTORY_UNPARSED_WARNING=False",
		"ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "tmp"), "ANSIBLE_NOCOLOR=1", "ANSIBLE_FORCE_COLOR=0",
		"TMPDIR="+scratch)
	cmd.Env = append(cmd.Env, o.env...)
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
	if b, err := os.ReadFile(filepath.Join(dir, "syslog")); err == nil {
		r.managed, r.managedLive = string(b), true
	}
	ents, _ := os.ReadDir(scratch)
	for _, e := range ents {
		r.leftovers = append(r.leftovers, e.Name())
	}
	return r
}

func newStep5Dir(t *testing.T, policy string) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "rsyslog"), policy)
	if err := os.Chmod(filepath.Join(dir, "rsyslog"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
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
		// kept: the file stays (true) or goes (false)
		kept bool
		// fails: ansible fails before any write
		fails bool
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
		// BASE applied this; a Latin-1 byte (here in a comment) anywhere in the file must not stop the apply
		{name: "a Latin-1 byte in a comment of the distro layout",
			policy: "/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n# caf\xe9 comment\n", kept: true, compare: true,
			contains: []string{"# caf\xe9 comment\n", "/var/log/mail.log\n{"}},
		// BASE deleted the whole policy for this one (grep took the file for binary)
		{name: "a non-UTF-8 byte in another path is kept as it is",
			policy: "/var/log/syslog /var/log/\xff.log {" + tail, kept: true, contains: []string{"/var/log/\xff.log {"}},
		{name: "a policy that does not declare the managed path stays as it is",
			policy: "\"/var/log/mail.log\" {" + tail, kept: true, contains: []string{"\"/var/log/mail.log\" {"}},
		{name: "a kept glob that covers the managed path stops the run",
			policy: "/var/log/syslog /var/log/sys* {" + tail, kept: true, fails: true},
		{name: "a kept path with a trailing slash that covers the managed path stops the run",
			policy: "/var/log/syslog /var/log/syslog/ {" + tail, kept: true, fails: true},
		{name: "a policy logrotate rejects stops the run",
			policy: "/var/log/other\n{\n\trotate 7\n\t/var/log/syslog\n}\n", kept: true, fails: true},
		{name: "a lone stanza that logrotate rejects (no endscript) stops the run",
			policy: "/var/log/syslog\n{\n\trotate 7\n\tpostrotate\n\t\ttrue\n}\n", kept: true, fails: true},
		// logrotate says "error: <file>:N unexpected }" for this one: the check of Step 1d's
		// own "error:" line, not the unknown-option check, has to stop it
		{name: "a rewrite that logrotate rejects with an error line stops the run",
			policy: "/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n}\n", kept: true, fails: true},
		{name: "a rewrite that logrotate warns about (unknown option) stops the run",
			policy: "/var/log/syslog\n/var/log/mail.log\n{\n\tbogus\n\trotate 4\n}\n", kept: true, fails: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := newStep5Dir(t, c.policy)
			playbook := step5Playbook(t, dir, true)
			first := runStep5(t, dir, playbook)
			if len(first.leftovers) > 0 {
				t.Fatalf("the run left %v in the temp directory", first.leftovers)
			}
			if c.fails {
				if first.rc == 0 || first.failed == 0 {
					t.Fatalf("ansible did not fail (rc %d):\n%s", first.rc, first.out)
				}
				if !first.policyAlive || first.policy != c.policy {
					t.Fatalf("the policy changed although the run failed:\n%q", first.policy)
				}
				if first.managedLive {
					t.Fatalf("the managed stanza was written although the run failed (the distro file still declares the path):\n%s", first.managed)
				}
				// and it failed in the preflight, ahead of Step 5
				if !strings.Contains(first.out, "TASK [Step 1d") || strings.Contains(first.out, "TASK [Step 5: Render") {
					t.Fatalf("the failure is not at Step 1d:\n%s", first.out)
				}
				return
			}
			if first.rc != 0 {
				t.Fatalf("ansible rc %d:\n%s", first.rc, first.out)
			}
			if !first.managedLive {
				t.Fatal("the managed stanza was not written")
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
			if len(second.leftovers) > 0 {
				t.Fatalf("the second run left %v in the temp directory", second.leftovers)
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

// A check-mode run reports what would change and writes nothing (the helper runs for
// real, on a temporary copy that is removed again); the real run after it applies.
func TestAuditLogForwardingStep5CheckModeWritesNothing(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip("ansible-playbook not installed")
	}
	if _, err := exec.LookPath("logrotate"); err != nil {
		t.Skip("logrotate not installed")
	}
	const policy = "/var/log/syslog\n{\n\trotate 7\n}\n\n/var/log/mail.log\n{\n\trotate 4\n}\n"
	dir := newStep5Dir(t, policy)
	playbook := step5Playbook(t, dir, true)
	chk := runStep5(t, dir, playbook, "--check")
	if chk.rc != 0 || chk.policy != policy || chk.managedLive || len(chk.leftovers) > 0 {
		t.Fatalf("check mode: rc %d, policy changed=%v, managed written=%v, leftovers %v\n%s", chk.rc, chk.policy != policy, chk.managedLive, chk.leftovers, chk.out)
	}
	if chk.changed == 0 {
		t.Fatalf("check mode reports nothing to change:\n%s", chk.out)
	}
	real := runStep5(t, dir, playbook)
	if real.rc != 0 || !strings.Contains(real.policy, "/var/log/mail.log") || strings.Contains(real.policy, "/var/log/syslog") || !real.managedLive {
		t.Fatalf("real run after check mode: rc %d\n%q\n%s", real.rc, real.policy, real.out)
	}
}

// Step 5c's own validate (logrotate's check of the file about to be installed) stops the
// install and leaves the file as it was. The preflight normally stops such a policy
// earlier, so this runs the chain without it.
func TestAuditLogForwardingStep5cValidateRejectsAndKeepsTheFile(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip("ansible-playbook not installed")
	}
	if _, err := exec.LookPath("logrotate"); err != nil {
		t.Skip("logrotate not installed")
	}
	const policy = "/var/log/syslog\n/var/log/mail.log\n{\n\tbogus\n\trotate 4\n}\n"
	dir := newStep5Dir(t, policy)
	r := runStep5(t, dir, step5Playbook(t, dir, false))
	if r.rc == 0 || r.failed == 0 || !strings.Contains(r.out, "Step 5c") {
		t.Fatalf("ansible did not fail at Step 5c (rc %d):\n%s", r.rc, r.out)
	}
	if r.policy != policy {
		t.Fatalf("the rejected policy was installed:\n%q", r.policy)
	}
	if len(r.leftovers) > 0 {
		t.Fatalf("the failed run left %v in the temp directory (the always section must remove it)", r.leftovers)
	}
}

// The distro file keeps its mode, owner and group through Step 5c. A copy without them
// takes the umask's mode (0664 under umask 002), and logrotate refuses a policy that is
// "writable by group or others": the distro policy would silently be skipped.
func TestAuditLogForwardingStep5cKeepsModeOwnerAndGroup(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip("ansible-playbook not installed")
	}
	const policy = "/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n"
	secondary := -1
	if gids, err := os.Getgroups(); err == nil {
		for _, g := range gids {
			if g != os.Getgid() {
				secondary = g
				break
			}
		}
	}
	for _, umask := range []string{"002", "022", "077"} {
		for _, mode := range []os.FileMode{0o644, 0o640, 0o600, 0o755, 0o444} {
			t.Run(umask+"/"+mode.String(), func(t *testing.T) {
				dir := newStep5Dir(t, policy)
				rs := filepath.Join(dir, "rsyslog")
				if err := os.Chmod(rs, mode); err != nil {
					t.Fatal(err)
				}
				if secondary >= 0 {
					if err := os.Chown(rs, os.Getuid(), secondary); err != nil {
						t.Fatal(err)
					}
				}
				r := runStep5With(t, dir, step5Playbook(t, dir, true), step5Opts{umask: umask})
				if r.rc != 0 || !r.policyAlive || strings.Contains(r.policy, "/var/log/syslog") {
					t.Fatalf("the apply did not rewrite the policy (rc %d):\n%q\n%s", r.rc, r.policy, r.out)
				}
				fi, err := os.Stat(rs)
				if err != nil {
					t.Fatal(err)
				}
				if fi.Mode().Perm() != mode {
					t.Fatalf("mode %v after the apply, was %v", fi.Mode().Perm(), mode)
				}
				if secondary >= 0 {
					if gid := int(fi.Sys().(*syscall.Stat_t).Gid); gid != secondary {
						t.Fatalf("group %d after the apply, was %d", gid, secondary)
					}
				}
			})
		}
	}
}

// A check-mode run on a host that has the policy but not logrotate yet (Step 1c does not
// install it in check mode) must still work: the helper runs, only logrotate's check of
// its output is skipped. A real run without logrotate fails, before any write.
func TestAuditLogForwardingStep1dWithoutLogrotate(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip("ansible-playbook not installed")
	}
	var keep []string
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if _, err := os.Stat(filepath.Join(d, "logrotate")); err != nil {
			keep = append(keep, d)
		}
	}
	noLogrotate := step5Opts{env: []string{"PATH=" + strings.Join(keep, string(os.PathListSeparator))}}
	const policy = "/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n"

	t.Run("check mode", func(t *testing.T) {
		dir := newStep5Dir(t, policy)
		r := runStep5With(t, dir, step5Playbook(t, dir, true), noLogrotate, "--check")
		if r.rc != 0 || r.policy != policy || r.managedLive || len(r.leftovers) > 0 {
			t.Fatalf("check mode without logrotate: rc %d, policy changed=%v, managed written=%v, leftovers %v\n%s", r.rc, r.policy != policy, r.managedLive, r.leftovers, r.out)
		}
	})
	t.Run("check mode still stops a policy the helper refuses", func(t *testing.T) {
		dir := newStep5Dir(t, "/var/log/syslog /var/log/sys* {\n\trotate 4\n}\n")
		r := runStep5With(t, dir, step5Playbook(t, dir, true), noLogrotate, "--check")
		if r.rc == 0 || r.failed == 0 {
			t.Fatalf("check mode did not fail on a glob that covers the path:\n%s", r.out)
		}
	})
	t.Run("real run", func(t *testing.T) {
		dir := newStep5Dir(t, policy)
		r := runStep5With(t, dir, step5Playbook(t, dir, true), noLogrotate)
		if r.rc == 0 || r.failed == 0 {
			t.Fatalf("a real run without logrotate did not fail:\n%s", r.out)
		}
		if r.policy != policy || r.managedLive || len(r.leftovers) > 0 {
			t.Fatalf("the failed run wrote something: policy changed=%v, managed written=%v, leftovers %v", r.policy != policy, r.managedLive, r.leftovers)
		}
		if !strings.Contains(r.out, "TASK [Step 1d") || strings.Contains(r.out, "TASK [Step 5: Render") {
			t.Fatalf("the failure is not at Step 1d:\n%s", r.out)
		}
	})
}
