package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The audit-log-forwarding playbook removes its own log path from the distro's
// /etc/logrotate.d/rsyslog with this helper. Ubuntu 22.04+ ships
// "/var/log/syslog" alone before its "{": removing only that line left a stanza
// with no filename, which logrotate rejects as a whole.
func TestLogrotateDropPathHelper(t *testing.T) {
	awk, err := exec.LookPath("awk")
	if err != nil {
		t.Skip("awk not installed")
	}
	script := filepath.Join(repoRootForTest(t), "playbooks", "apply", "files", "logrotate-drop-path.awk")

	const lone = "/var/log/syslog\n{\n\trotate 7\n\tpostrotate\n\t\t}\n\tendscript\n}\n\n/var/log/mail.log\n/var/log/kern.log\n{\n\trotate 4\n}\n"
	const loneWant = "/var/log/mail.log\n/var/log/kern.log\n{\n\trotate 4\n}\n"
	const commentedEndscript = "/var/log/other\n{\n\trotate 7\n\tpostrotate\n\t\t/usr/lib/rsyslog/rsyslog-rotate\n\tendscript # rotate done\n}\n\n/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n"
	const commentedEndscriptWant = "/var/log/other\n{\n\trotate 7\n\tpostrotate\n\t\t/usr/lib/rsyslog/rsyslog-rotate\n\tendscript # rotate done\n}\n\n/var/log/mail.log\n{\n\trotate 4\n}\n"

	for _, tt := range []struct{ name, in, path, want string }{
		{"lone path takes its whole stanza, blank line included", lone, "/var/log/syslog", loneWant},
		{"a lone path on the same line as the brace too", "/var/log/syslog {\n\trotate 7\n}\n\n/var/log/mail.log {\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/mail.log {\n\trotate 4\n}\n"},
		{"a shared path loses only its own line", "/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/mail.log\n{\n\trotate 4\n}\n"},
		{"a shared path on the brace line keeps the brace", "/var/log/mail.log\n/var/log/syslog {\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/mail.log\n{\n\trotate 4\n}\n"},
		{"space separated paths", "/var/log/syslog /var/log/mail.log {\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/mail.log {\n\trotate 4\n}\n"},
		{"a path that is not there changes nothing", lone, "/var/log/messages", lone},
		// logrotate takes the first word as the directive: "endscript # why" closes the
		// script. A matcher for the bare word only left in_script set, so every later
		// stanza was copied as script body and a shared /var/log/syslog stayed.
		{"endscript with a trailing comment closes the script", commentedEndscript, "/var/log/syslog", commentedEndscriptWant},
		{"a comment after postrotate still opens the script", "/var/log/other {\n\tpostrotate # reload\n\t\t}\n\tendscript\n}\n\n/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/other {\n\tpostrotate # reload\n\t\t}\n\tendscript\n}\n\n/var/log/mail.log\n{\n\trotate 4\n}\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := filepath.Join(t.TempDir(), "rsyslog")
			writeFile(t, in, tt.in)
			out, err := exec.Command(awk, "-v", "drop="+tt.path, "-f", script, in).CombinedOutput()
			if err != nil {
				t.Fatalf("awk: %v\n%s", err, out)
			}
			if string(out) != tt.want {
				t.Fatalf("got:\n%q\nwant:\n%q", out, tt.want)
			}
		})
	}
}

// The rewrite must not leave the path declared: the playbook renders its own
// /etc/logrotate.d/syslog for it, and logrotate aborts the whole run with
// "duplicate log entry" when two files declare one path, which the copy's
// validate (it parses only the one file) never sees.
func TestLogrotateDropPathLeavesNoDuplicateWithTheManagedStanza(t *testing.T) {
	awk, err := exec.LookPath("awk")
	if err != nil {
		t.Skip("awk not installed")
	}
	logrotate, err := exec.LookPath("logrotate")
	if err != nil {
		t.Skip("logrotate not installed")
	}
	script := filepath.Join(repoRootForTest(t), "playbooks", "apply", "files", "logrotate-drop-path.awk")
	const managed = "/var/log/syslog {\n\tdaily\n\trotate 4\n\tmissingok\n}\n"

	for _, tt := range []struct{ name, policy string }{
		{"Ubuntu 24.04, syslog alone in its stanza", "/var/log/syslog\n{\n\trotate 7\n\tpostrotate\n\t\t/usr/lib/rsyslog/rsyslog-rotate\n\tendscript\n}\n\n/var/log/mail.log\n/var/log/kern.log\n{\n\trotate 4\n}\n"},
		{"syslog shared with other paths", "/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n"},
		{"a commented endscript before the shared stanza", "/var/log/other\n{\n\trotate 7\n\tpostrotate\n\t\t/usr/lib/rsyslog/rsyslog-rotate\n\tendscript # rotate done\n}\n\n/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			policy := filepath.Join(dir, "rsyslog.in")
			writeFile(t, policy, tt.policy)
			rewritten, err := exec.Command(awk, "-v", "drop=/var/log/syslog", "-f", script, policy).CombinedOutput()
			if err != nil {
				t.Fatalf("awk: %v\n%s", err, rewritten)
			}
			confd := filepath.Join(dir, "logrotate.d")
			if err := os.Mkdir(confd, 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(confd, "rsyslog"), string(rewritten))
			writeFile(t, filepath.Join(confd, "syslog"), managed)
			main := filepath.Join(dir, "logrotate.conf")
			writeFile(t, main, "include "+confd+"\n")
			for _, f := range []string{main, filepath.Join(confd, "rsyslog"), filepath.Join(confd, "syslog")} {
				if err := os.Chmod(f, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			out, _ := exec.Command(logrotate, "-d", "-s", filepath.Join(dir, "state"), main).CombinedOutput()
			if strings.Contains(string(out), "duplicate log entry") {
				t.Fatalf("logrotate sees /var/log/syslog twice:\n%s\nrewritten policy:\n%s", out, rewritten)
			}
		})
	}
}

func TestLogrotateDropPathFailsInsteadOfLeavingThePath(t *testing.T) {
	awk, err := exec.LookPath("awk")
	if err != nil {
		t.Skip("awk not installed")
	}
	script := filepath.Join(repoRootForTest(t), "playbooks", "apply", "files", "logrotate-drop-path.awk")
	in := filepath.Join(t.TempDir(), "rsyslog")
	// A script line that is the path itself: the helper keeps script text verbatim, so
	// the path survives. That must be an error, not a silently written duplicate.
	writeFile(t, in, "/var/log/other\n{\n\tpostrotate\n\t/var/log/syslog\n\tendscript\n}\n")
	out, err := exec.Command(awk, "-v", "drop=/var/log/syslog", "-f", script, in).CombinedOutput()
	if err == nil {
		t.Fatalf("awk succeeded and left the path in:\n%s", out)
	}
	if !strings.Contains(string(out), "still declared") {
		t.Fatalf("unexpected failure: %v\n%s", err, out)
	}
}
