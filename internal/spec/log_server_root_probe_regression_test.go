package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegression_LogServerProbesUseTheEffectiveRoot runs log-server.md's
// C6–C8 and log-shipping.md's C3 as written, against a receiver config
// rendered for a non-default siem_log_root. PR #79 made siem_log_root an
// effective inventory input; with fixed /var/log/siem rows a custom root
// failed C6–C8, and an old fixed selftest string left in a directory let
// C7/C8 pass. Here a fake `logger` stands in for rsyslog's delivery: it
// writes the message under <root>/<host>/ the way the siemReceiver dynaFile
// does, or nothing when "rsyslog" is stopped.
func TestRegression_LogServerProbesUseTheEffectiveRoot(t *testing.T) {
	for _, tool := range []string{"sh", "sed", "grep", "date"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed: %v", tool, err)
		}
	}
	rows := func(path string) map[string]string {
		s, err := Parse(path)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		cmd := map[string]string{}
		for _, r := range s.Rows {
			cmd[r.ID] = r.Command
		}
		return cmd
	}
	server := rows("../../docs/verification/log-server.md")
	shipping := rows("../../docs/verification/log-shipping.md")

	dir := t.TempDir()
	root := filepath.Join(dir, "srv", "siem")
	conf := filepath.Join(dir, "10-siem-receiver.conf")
	// The two template lines exactly as log-server-apply.yml renders them.
	body := `module(load="imtcp")` + "\n" +
		`template(name="SiemAuditPath" type="string" string="` + root + `/%HOSTNAME%/audit.log")` + "\n" +
		`template(name="SiemAuthPath" type="string" string="` + root + `/%HOSTNAME%/auth.log")` + "\n"
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	promtail := filepath.Join(dir, "promtail-config.yml")

	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// logger -p <facility>.info <message>: deliver like rsyslog unless the
	// STOPPED file exists.
	fake := "#!/bin/sh\n[ -e " + filepath.Join(dir, "STOPPED") + " ] && exit 0\n" +
		"case \"$2\" in local6.*) f=audit.log;; *) f=auth.log;; esac\n" +
		"mkdir -p " + root + "/testhost && printf '%s\\n' \"$3\" >> " + root + "/testhost/$f\n"
	if err := os.WriteFile(filepath.Join(bin, "logger"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(command string) string {
		t.Helper()
		command = strings.ReplaceAll(command, "/etc/rsyslog.d/10-siem-receiver.conf", conf)
		command = strings.ReplaceAll(command, "/etc/pilot/promtail/promtail-config.yml", promtail)
		c := exec.Command("sh", "-c", command)
		c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("command failed: %v\n%s\n%s", err, command, out)
		}
		return strings.TrimSpace(string(out))
	}

	// The root does not exist yet: C6 fails.
	if got := run(server["C6"]); got != "1" {
		t.Errorf("C6 before the root exists: want 1, got %q", got)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := run(server["C6"]); got != "0" {
		t.Errorf("C6 with %s present: want 0, got %q", root, got)
	}

	// Delivery works: C7/C8 pass under the custom root.
	for _, id := range []string{"C7", "C8"} {
		if got := run(server[id]); got != "0" {
			t.Errorf("%s with delivery: want 0, got %q", id, got)
		}
	}

	// rsyslog stopped, and old fixed selftest strings left in the old
	// default layout and under the root: C7/C8 must still fail.
	if err := os.WriteFile(filepath.Join(dir, "STOPPED"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"audit.log", "auth.log"} {
		if err := os.WriteFile(filepath.Join(root, "testhost", f), []byte("PILOT-SIEM-SELFTEST-AUDIT\nPILOT-SIEM-SELFTEST-AUTH\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"C7", "C8"} {
		if got := run(server[id]); got != "1" {
			t.Errorf("%s with rsyslog stopped and only old selftest strings present: want 1, got %q", id, got)
		}
	}

	// log-shipping C3: the scrape glob must be the receiver's root.
	if err := os.WriteFile(promtail, []byte("        __path__: /var/log/siem/**/*.log\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := run(shipping["C3"]); got != "1" {
		t.Errorf("log-shipping C3 with Promtail on the default root but rsyslog writing to %s: want 1, got %q", root, got)
	}
	if err := os.WriteFile(promtail, []byte("        __path__: "+root+"/**/*.log\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := run(shipping["C3"]); got != "0" {
		t.Errorf("log-shipping C3 with Promtail on %s: want 0, got %q", root, got)
	}
}

// TestRegression_LogServerLetsConfinedRsyslogWriteTheRoot: rsyslogd is
// confined to /var/log by AppArmor on Ubuntu (usr.sbin.rsyslogd) and by
// SELinux on EL. With siem_log_root: /srv/siem on Ubuntu 24.04, omfile failed
// with "Permission denied", every message was discarded and the apply
// succeeded; after the profile was fixed nothing landed until rsyslog
// restarted (2026-10-15). log-server must grant the root to the confined
// daemon before rsyslog is (re)started, and restart it when that grant
// changes.
func TestRegression_LogServerLetsConfinedRsyslogWriteTheRoot(t *testing.T) {
	raw, err := os.ReadFile("../../playbooks/apply/log-server-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	pb := string(raw)
	include := strings.Index(pb, "file: tasks/rsyslog-confined-log-root.yml")
	render := strings.Index(pb, `name: "Step 3: Render 10-siem-receiver.conf`)
	restart := strings.Index(pb, `name: "Step 6a: Restart rsyslog`)
	if include < 0 || render < 0 || restart < 0 || include > render || render > restart {
		t.Fatalf("log-server must include tasks/rsyslog-confined-log-root.yml before Step 3 and Step 6a; got indexes %d, %d, %d", include, render, restart)
	}
	if !strings.Contains(pb, `rsyslog_log_root: "{{ siem_log_root_real }}"`) {
		t.Error("the include must pass the resolved root siem_log_root_real")
	}
	step6a := pb[restart:]
	if end := strings.Index(step6a[1:], "- name:"); end > 0 {
		step6a = step6a[:end+1]
	}
	for _, want := range []string{"rsyslog_apparmor_local", "rsyslog_selinux_fcontext", "C6, C7, C8"} {
		if !strings.Contains(step6a, want) {
			t.Errorf("Step 6a must restart rsyslog when the log-root access changes (%q missing):\n%s", want, step6a)
		}
	}

	raw, err = os.ReadFile("../../playbooks/apply/tasks/rsyslog-confined-log-root.yml")
	if err != nil {
		t.Fatal(err)
	}
	tf := string(raw)
	for _, want := range []string{
		"/etc/apparmor.d/local/usr.sbin.rsyslogd", "{{ rsyslog_log_root }}/ rw,", "{{ rsyslog_log_root }}/** rwk,",
		"'absent' if rsyslog_log_root_in_var_log", "apparmor_parser, -r, /etc/apparmor.d/usr.sbin.rsyslogd",
		"/sys/fs/selinux/enforce", "community.general.sefcontext", `target: "{{ rsyslog_log_root }}(/.*)?"`,
		"setype: var_log_t", "restorecon, -RF", "not ansible_check_mode",
	} {
		if !strings.Contains(tf, want) {
			t.Errorf("tasks/rsyslog-confined-log-root.yml must contain %q", want)
		}
	}
}
