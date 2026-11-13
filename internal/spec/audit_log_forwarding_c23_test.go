package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegression_AuditLogForwardingC23States runs spec row C23's own shell over states captured on real hosts
// (testdata/native-captures: Ubuntu 24.04 and AlmaLinux 9). `systemctl`, `ss`, `auditctl` and `sudo` are PATH
// shims that answer from the captures; `grep` and `sh` are the real ones, so the pipeline and its matchers are
// the spec's. The only substitution is the path of ossec.conf (a private file instead of /var/ossec).
//
// The row must pass wherever who-data is not live (nothing to protect) and for a live one with its watches, and
// fire for the state this issue is about: the endpoint and its listener intact, the agent active, the kernel
// list emptied by an `augenrules --load` or an auditd restart. A row that cannot fail would pass on the base.
func TestRegression_AuditLogForwardingC23States(t *testing.T) {
	s, err := Parse("../../docs/verification/audit-log-forwarding.md")
	if err != nil {
		t.Fatal(err)
	}
	command := ""
	for _, row := range s.Rows {
		if row.ID == "C23" {
			command = row.Command
			if strings.TrimSpace(row.Expected) != "0" {
				t.Fatalf("C23 expected must be rc-based 0, got %q", row.Expected)
			}
		}
	}
	if command == "" {
		t.Fatal("missing C23 command")
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
	const (
		whodataOn  = `<directories check_all="yes" whodata="yes">/etc</directories>` + "\n"
		whodataOff = `<directories check_all="yes">/etc</directories>` + "\n"
	)
	type state struct {
		name     string
		agent    bool   // systemctl is-active wazuh-agent succeeds
		conf     string // ossec.conf
		ss       string // capture, "" = no ss on the host
		auditctl string // capture
		lines    string // extra `auditctl -l` text instead of a capture
		want     string
	}
	states := []state{
		// Live who-data with its watches: the row passes (Ubuntu and AlmaLinux captures).
		{"live, Ubuntu 24.04", true, whodataOn, "ss-xHap.audit-endpoint.healthy.ubuntu2404.txt", "auditctl-l.wazuh_fim.ubuntu2404.txt", "", "0"},
		{"live, AlmaLinux 9", true, whodataOn, "ss-xHap.audit-endpoint.healthy.almalinux9.txt", "auditctl-l.wazuh_fim.almalinux9.txt", "", "0"},
		// The issue: the endpoint and its listener are intact, the kernel list was emptied. The row must fire.
		{"flushed while the endpoint is live, Ubuntu 24.04", true, whodataOn, "ss-xHap.audit-endpoint.healthy.ubuntu2404.txt", "auditctl-l.no-rules.ubuntu2404.txt", "", "1"},
		{"flushed while the endpoint is live, AlmaLinux 9", true, whodataOn, "ss-xHap.audit-endpoint.healthy.almalinux9.txt", "auditctl-l.no-rules.almalinux9.txt", "", "1"},
		// auditd restarted by Step 8a: a new listener with nobody connected and no watches. Still fires.
		{"restarted auditd: listener without a connection, no watches", true, whodataOn, "ss-xHap.audit-endpoint.agent-stopped.ubuntu2404.txt", "auditctl-l.no-rules.ubuntu2404.txt", "", "1"},
		// The state right after Step 8a on Ubuntu 24.04: the LISTEN line of the new audisp-af_unix. With the
		// watches back it passes; without them (the list was emptied by the restart) it must fire.
		{"after an auditd restart: listener captured, watches back", true, whodataOn, "ss-xHap.audit-endpoint.after-auditd-restart.ubuntu2404.txt", "auditctl-l.wazuh_fim.ubuntu2404.txt", "", "0"},
		{"after an auditd restart: listener captured, list emptied", true, whodataOn, "ss-xHap.audit-endpoint.after-auditd-restart.ubuntu2404.txt", "auditctl-l.no-rules.ubuntu2404.txt", "", "1"},
		// Where who-data is not live there is nothing to protect.
		{"agent stopped (the plugin still listens)", false, whodataOn, "ss-xHap.audit-endpoint.agent-stopped.ubuntu2404.txt", "auditctl-l.no-rules.ubuntu2404.txt", "", "0"},
		{"agent without whodata configured", true, whodataOff, "ss-xHap.audit-endpoint.healthy.ubuntu2404.txt", "auditctl-l.no-rules.ubuntu2404.txt", "", "0"},
		{"stale socket file, plugin gone (no listener)", true, whodataOn, "ss-xHap.audit-endpoint.plugin-gone.ubuntu2404.txt", "auditctl-l.no-rules.ubuntu2404.txt", "", "0"},
		{"no endpoint at all, EL without audispd-plugins", true, whodataOn, "ss-xHap.audit-endpoint.no-plugin.almalinux9.txt", "auditctl-l.no-rules.almalinux9.txt", "", "0"},
		// Not being able to look is not a pass.
		{"no ss on the host while who-data is configured", true, whodataOn, "", "auditctl-l.wazuh_fim.ubuntu2404.txt", "", "1"},
		// The matcher counts the key exactly: a lookalike is not a who-data watch, the -F key= form is.
		{"a lookalike key is not the watch", true, whodataOn, "ss-xHap.audit-endpoint.healthy.ubuntu2404.txt", "", "-w /etc -p wa -k wazuh_fimx\n", "1"},
		{"the -F key= form is the watch", true, whodataOn, "ss-xHap.audit-endpoint.healthy.ubuntu2404.txt", "", "-w /etc -p wa -F key=wazuh_fim\n", "0"},
	}
	for _, tc := range states {
		t.Run(tc.name, func(t *testing.T) {
			// A fixed-shape directory: the default t.TempDir() keeps shell metacharacters of the subtest name in the path.
			dir, err := os.MkdirTemp("", "pilot-c23-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			for _, name := range []string{"sh", "grep", "cat", "true", "false"} {
				path, err := exec.LookPath(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path, filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			conf := filepath.Join(dir, "ossec.conf")
			if err := os.WriteFile(conf, []byte(tc.conf), 0o600); err != nil {
				t.Fatal(err)
			}
			listing := filepath.Join(dir, "auditctl.txt")
			if tc.auditctl != "" {
				data, err := os.ReadFile(capture(tc.auditctl))
				if err != nil {
					t.Fatal(err)
				}
				tc.lines = string(data)
			}
			if err := os.WriteFile(listing, []byte(tc.lines), 0o600); err != nil {
				t.Fatal(err)
			}
			shims := map[string]string{
				"sudo":      "#!/bin/sh\nexec \"$@\"\n",
				"auditctl":  "#!/bin/sh\ncat \"$PILOT_AUDITCTL\"\n",
				"systemctl": "#!/bin/sh\n" + map[bool]string{true: "exit 0", false: "exit 3"}[tc.agent] + "\n",
			}
			if tc.ss != "" {
				shims["ss"] = "#!/bin/sh\ncat \"$PILOT_SS\"\n"
			}
			for name, body := range shims {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			row := strings.ReplaceAll(command, "/var/ossec/etc/ossec.conf", conf)
			run := exec.Command("sh", "-c", row)
			run.Env = []string{"PATH=" + dir, "PILOT_AUDITCTL=" + listing}
			if tc.ss != "" {
				run.Env = append(run.Env, "PILOT_SS="+capture(tc.ss))
			}
			out, err := run.CombinedOutput()
			if err != nil {
				t.Fatalf("row shell: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != tc.want {
				t.Fatalf("C23 = %q, want %q", got, tc.want)
			}
		})
	}
}
