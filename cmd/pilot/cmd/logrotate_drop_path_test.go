package cmd

import (
	"os/exec"
	"path/filepath"
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

	for _, tt := range []struct{ name, in, path, want string }{
		{"lone path takes its whole stanza, blank line included", lone, "/var/log/syslog", loneWant},
		{"a lone path on the same line as the brace too", "/var/log/syslog {\n\trotate 7\n}\n\n/var/log/mail.log {\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/mail.log {\n\trotate 4\n}\n"},
		{"a shared path loses only its own line", "/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/mail.log\n{\n\trotate 4\n}\n"},
		{"a shared path on the brace line keeps the brace", "/var/log/mail.log\n/var/log/syslog {\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/mail.log\n{\n\trotate 4\n}\n"},
		{"space separated paths", "/var/log/syslog /var/log/mail.log {\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/mail.log {\n\trotate 4\n}\n"},
		{"a path that is not there changes nothing", lone, "/var/log/messages", lone},
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
