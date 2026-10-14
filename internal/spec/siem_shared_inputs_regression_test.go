package spec

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// siemResolve runs the tasks of playbook that keep selects, on localhost in
// group with groupVars, and returns the values of names.
func siemResolve(t *testing.T, playbook, group string, keep func(string) bool, groupVars map[string]any, names ...string) map[string]any {
	t.Helper()
	play := loadFirstPlay(t, playbook)
	tasks := append(pickTasks(play, keep), showTask(names))
	return runInventoryPlay(t, group, play["vars"], tasks, groupVars)
}

// TestRegression_SIEMSharedInputsResolveTheSameOnEverySide is the AGENTS.md
// §5.7 consistency test for the inputs the SIEM playbooks share on one host:
// log-server writes under siem_log_root and log-shipping's Promtail tails it;
// audit-log-forwarding and wazuh-manager send to siem_forward_port and
// log-server listens on siem_receiver_tcp_port. For the same inventory value
// (unset, "", null or set), each pair must resolve the same directory and
// port. With `default()` alone an empty or null siem_log_root reached
// log-server as "" (rsyslog then wrote /%HOSTNAME%/audit.log) while
// log-shipping tailed /var/log/siem.
func TestRegression_SIEMSharedInputsResolveTheSameOnEverySide(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	cases := []struct {
		name     string
		value    any // siem_log_root; nil with set=false means not set at all
		port     any // siem_forward_port and siem_receiver_tcp_port
		set      bool
		wantRoot string
		wantPort string
	}{
		{"unset", nil, nil, false, "/var/log/siem", "514"},
		{"empty", "", "", true, "/var/log/siem", "514"},
		{"null", nil, nil, true, "/var/log/siem", "514"},
		{"set", "/var/log/siem-site", "2514", true, "/var/log/siem-site", "2514"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gv map[string]any
			if tc.set {
				gv = map[string]any{"siem_log_root": tc.value, "siem_forward_port": tc.port, "siem_receiver_tcp_port": tc.port}
			}
			server := siemResolve(t, "log-server-apply.yml", "log-server", isDefaultsTask, gv, "siem_log_root", "siem_receiver_tcp_port")
			shipping := siemResolve(t, "log-shipping-apply.yml", "log-server", func(name string) bool {
				return strings.HasPrefix(name, "Resolve siem_log_root_effective")
			}, gv, "siem_log_root_effective")
			audit := siemResolve(t, "audit-log-forwarding-apply.yml", "audit-log-forwarding", isDefaultsTask, gv, "siem_forward_port")
			wazuh := siemResolve(t, "wazuh-manager-apply.yml", "wazuh-manager", isDefaultsTask, gv, "siem_forward_port")

			if server["siem_log_root"] != tc.wantRoot || shipping["siem_log_root_effective"] != tc.wantRoot {
				t.Errorf("siem_log_root: log-server writes under %v, log-shipping tails %v; want both %s",
					server["siem_log_root"], shipping["siem_log_root_effective"], tc.wantRoot)
			}
			if server["siem_receiver_tcp_port"] != tc.wantPort || audit["siem_forward_port"] != tc.wantPort || wazuh["siem_forward_port"] != tc.wantPort {
				t.Errorf("ports: log-server listens on %v, audit-log-forwarding sends to %v, wazuh-manager to %v; want all %s",
					server["siem_receiver_tcp_port"], audit["siem_forward_port"], wazuh["siem_forward_port"], tc.wantPort)
			}
		})
	}
}

// logServerGateTasks returns log-server's defaults task, its siem_log_root
// gates and a show task, plus its play vars with siem_log_owner set to
// owner (the play derives it from facts this localhost run does not gather).
func logServerGateTasks(t *testing.T, owner string) (map[string]any, []any) {
	t.Helper()
	play := loadFirstPlay(t, "log-server-apply.yml")
	tasks := append(pickTasks(play, func(name string) bool {
		return isDefaultsTask(name) || strings.HasPrefix(name, "Gate: siem_log_root")
	}), showTask([]string{"siem_log_root"}))
	if len(tasks) != 8 {
		t.Fatalf("expected the defaults task, six siem_log_root gate tasks and show; got %d tasks", len(tasks))
	}
	vars := map[string]any{}
	for k, v := range play["vars"].(map[string]any) {
		vars[k] = v
	}
	vars["siem_log_owner"] = owner
	return vars, tasks
}

// TestRegression_LogServerRefusesASharedSiemLogRoot runs log-server's
// defaults and its siem_log_root gates. log-server's Step 2 makes
// siem_log_root owned by the rsyslog user (file: state=directory follows a
// symlink) and Step 4 rotates siem_log_root/*/*.log, so since siem_log_root
// comes from inventory a value such as /var/log, a path that resolves to a
// shared directory, or an existing directory this role did not create must
// fail before any mutation, while a rerun on the directory it did create
// passes. A path through a symlink is judged by the directory it resolves
// to: hosts whose /var is a symlink still use the default. The mount-point
// exception (a new filesystem's root holding only lost+found) needs root and
// is covered by the VM run in the evidence record.
func TestRegression_LogServerRefusesASharedSiemLogRoot(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	vars, tasks := logServerGateTasks(t, me.Username)
	run := func(root string) string {
		_, failed := tryInventoryPlay(t, "log-server", vars, tasks, map[string]any{"siem_log_root": root})
		return failed
	}
	const names = "Gate: siem_log_root is a dedicated absolute directory"
	const resolved = "Gate: siem_log_root resolves to a new directory or one this role created"

	// Names do not depend on who owns what, so they always run.
	t.Run("names", func(t *testing.T) {
		for _, ok := range []string{"/var/log/siem-pr79-absent", "/srv/siem-pr79-absent", "/data/logs/siem_1.x"} {
			if failed := run(ok); failed != "" {
				t.Errorf("siem_log_root=%s: want accepted, got %s", ok, failed)
			}
		}
		for _, bad := range []string{"/var/log", "/var", "/", "/srv", "/home", "/usr/share/siem", "/usr/lib", "/etc/rsyslog.d",
			"/run/log", "var/log/siem", "/var/log/siem/", "/var//log/siem", "/var/log/../siem",
			"/var/log/./siem", "/var/log/siem dir", "/var/log/$(id)", "/var/log/siem-pr79\n"} {
			if failed := run(bad); !strings.Contains(failed, names) {
				t.Errorf("siem_log_root=%q: want %q to fail, got %q", bad, names, failed)
			}
		}
		// A dedicated-looking name that resolves to a shared or system directory.
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		toVarLog := filepath.Join(base, "to-var-log")
		if err := os.Symlink("/var/log", toVarLog); err != nil {
			t.Fatal(err)
		}
		bad := []string{toVarLog}
		if fi, err := os.Lstat("/var/run"); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			bad = append(bad, "/var/run/siem-pr79") // resolves under /run
		}
		for _, root := range bad {
			if failed := run(root); !strings.Contains(failed, resolved) || !strings.Contains(failed, "shared or system directory") {
				t.Errorf("siem_log_root=%s: want %q to refuse it as a shared or system directory, got %q", root, resolved, failed)
			}
		}
	})

	// The filesystem cases compare an existing directory's owner and group
	// with siem_log_owner, which the play uses for both.
	t.Run("filesystem", func(t *testing.T) {
		group, err := user.LookupGroupId(me.Gid)
		if err != nil || group.Name != me.Username {
			t.Skipf("the gate compares owner and group with one name; %s's primary group is not %s", me.Username, me.Username)
		}
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		mkdir := func(path string) string {
			t.Helper()
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o755); err != nil {
				t.Fatal(err)
			}
			return path
		}
		symlink := func(target, link string) string {
			t.Helper()
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link
		}
		cases := []struct {
			name string
			root func() string
			ok   bool
			msg  string
		}{
			{"absent", func() string { return filepath.Join(base, "absent", "siem") }, true, ""},
			{"empty", func() string { return mkdir(filepath.Join(base, "empty")) }, true, ""},
			{"rerun: only per-host directories", func() string {
				root := mkdir(filepath.Join(base, "rerun"))
				mkdir(filepath.Join(root, "client-1"))
				if err := os.WriteFile(filepath.Join(root, "client-1", "audit.log"), []byte("x\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return root
			}, true, ""},
			{"a symlink to a new directory", func() string {
				return symlink(mkdir(filepath.Join(base, "target1")), filepath.Join(base, "link1"))
			}, true, ""},
			{"a parent is a symlink", func() string {
				return filepath.Join(symlink(mkdir(filepath.Join(base, "target2")), filepath.Join(base, "link2")), "siem")
			}, true, ""},
			{"a file at the top", func() string {
				root := mkdir(filepath.Join(base, "file"))
				if err := os.WriteFile(filepath.Join(root, "syslog"), []byte("x\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return root
			}, false, "holds entries other than per-host directories"},
			{"a hidden file at the top", func() string {
				root := mkdir(filepath.Join(base, "hidden"))
				if err := os.WriteFile(filepath.Join(root, ".profile"), []byte("x\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return root
			}, false, "holds entries other than per-host directories"},
			{"a symlink to a directory holding a file", func() string {
				target := mkdir(filepath.Join(base, "target3"))
				if err := os.WriteFile(filepath.Join(target, "data"), []byte("x\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return symlink(target, filepath.Join(base, "link3"))
			}, false, "holds entries other than per-host directories"},
			{"an empty directory with another mode (like /var/log/private, 0700)", func() string {
				root := mkdir(filepath.Join(base, "private"))
				if err := os.Chmod(root, 0o700); err != nil {
					t.Fatal(err)
				}
				return root
			}, false, "chmod 0755"},
			{"a regular file", func() string {
				path := filepath.Join(base, "regular")
				if err := os.WriteFile(path, nil, 0o644); err != nil {
					t.Fatal(err)
				}
				return path
			}, false, "exists and is not a directory"},
		}
		for _, tc := range cases {
			root := tc.root()
			failed := run(root)
			switch {
			case tc.ok && failed != "":
				t.Errorf("%s (%s): want accepted, got %s", tc.name, root, failed)
			case !tc.ok && (!strings.Contains(failed, resolved) || !strings.Contains(failed, tc.msg)):
				t.Errorf("%s (%s): want %q to fail with %q, got %q", tc.name, root, resolved, tc.msg, failed)
			}
		}

		// Directories owned by someone other than siem_log_owner, empty or not.
		otherVars, _ := logServerGateTasks(t, "nobody")
		for _, root := range []string{mkdir(filepath.Join(base, "other-empty")), mkdir(filepath.Join(base, "other", "client-1"))} {
			root = strings.TrimSuffix(root, "/client-1")
			if _, failed := tryInventoryPlay(t, "log-server", otherVars, tasks, map[string]any{"siem_log_root": root}); !strings.Contains(failed, resolved) {
				t.Errorf("%s not owned by siem_log_owner: want %q to fail, got %q", root, resolved, failed)
			}
		}
	})
}

// auditPortGate runs audit-log-forwarding's defaults and its port gate on
// localhost, with siem-1 (never contacted) as the inventory log-server.
func auditPortGate(t *testing.T, serverVars, clientVars map[string]any) string {
	t.Helper()
	play := loadFirstPlay(t, "audit-log-forwarding-apply.yml")
	tasks := append(pickTasks(play, func(name string) bool {
		return isDefaultsTask(name) || strings.HasPrefix(name, "Gate: siem_forward_port matches")
	}), showTask([]string{"siem_forward_port"}))
	if len(tasks) != 3 {
		t.Fatalf("expected the defaults task, the port gate and show; got %d tasks", len(tasks))
	}
	inv := map[string]any{"all": map[string]any{"children": map[string]any{
		"log-server": map[string]any{"hosts": map[string]any{"siem-1": map[string]any{
			"ansible_host": "192.0.2.10", "ansible_fqdn": "siem-1.example.internal"}}},
		"audit-log-forwarding": map[string]any{"hosts": map[string]any{"localhost": localHostVars()}},
	}}}
	_, failed := tryInventoryPlayIn(t, inv, map[string]map[string]any{"log-server": serverVars, "audit-log-forwarding": clientVars},
		"audit-log-forwarding", play["vars"], tasks)
	return failed
}

// TestRegression_AuditForwardPortMatchesTheLogServerReceiver: the clients'
// siem_forward_port and log-server's siem_receiver_tcp_port are separate
// inputs, normally in group_vars/audit-log-forwarding.yml and
// group_vars/log-server.yml. With log-server on 2514 and the clients on 514,
// rsyslog forwarded to a port nothing listened on and the apply succeeded.
func TestRegression_AuditForwardPortMatchesTheLogServerReceiver(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	const gate = "Gate: siem_forward_port matches the inventory log-server's siem_receiver_tcp_port"
	cases := []struct {
		name           string
		server, client map[string]any
		fail           bool
	}{
		{"both unset", map[string]any{}, map[string]any{}, false},
		{"both 2514, one quoted", map[string]any{"siem_receiver_tcp_port": 2514}, map[string]any{"siem_forward_port": "2514"}, false},
		{"receiver empty, sender unset", map[string]any{"siem_receiver_tcp_port": ""}, map[string]any{}, false},
		{"receiver 2514, sender default", map[string]any{"siem_receiver_tcp_port": 2514}, map[string]any{}, true},
		{"receiver default, sender 2514", map[string]any{}, map[string]any{"siem_forward_port": 2514}, true},
		{"explicit siem_forward_host is the log-server's address", map[string]any{"siem_receiver_tcp_port": 2514},
			map[string]any{"siem_forward_host": "192.0.2.10"}, true},
		{"explicit siem_forward_host is the log-server's inventory name", map[string]any{"siem_receiver_tcp_port": 2514},
			map[string]any{"siem_forward_host": "siem-1"}, true},
		{"external receiver is not checked", map[string]any{"siem_receiver_tcp_port": 2514},
			map[string]any{"siem_forward_host": "198.51.100.7"}, false},
		// AGENTS.md §5.13: a name for the log-server written with other
		// case, as its FQDN, or with a trailing dot is still the log-server.
		{"explicit siem_forward_host is the inventory name in upper case", map[string]any{"siem_receiver_tcp_port": 2514},
			map[string]any{"siem_forward_host": "SIEM-1"}, true},
		{"explicit siem_forward_host is the log-server's FQDN with a trailing dot", map[string]any{"siem_receiver_tcp_port": 2514},
			map[string]any{"siem_forward_host": "siem-1.example.internal."}, true},
		{"explicit siem_forward_host is the log-server's FQDN in mixed case", map[string]any{"siem_receiver_tcp_port": 2514},
			map[string]any{"siem_forward_host": "Siem-1.Example.Internal"}, true},
		{"the log-server's FQDN with matching ports", map[string]any{"siem_receiver_tcp_port": 2514},
			map[string]any{"siem_forward_host": "siem-1.example.internal", "siem_forward_port": 2514}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			failed := auditPortGate(t, tc.server, tc.client)
			if tc.fail && !strings.Contains(failed, gate) {
				t.Errorf("want %q to fail, got %q", gate, failed)
			}
			if !tc.fail && failed != "" {
				t.Errorf("want accepted, got %q", failed)
			}
		})
	}
}

// TestRegression_SIEMCountsFallBackForEmptyValues: with `default(n)` an
// empty or null logrotate count rendered `rotate ` (logrotate then skips the
// whole policy, so /var/log/syslog stops rotating) and an empty loki_port
// made the push URL `pilot-loki-backend:`.
func TestRegression_SIEMCountsFallBackForEmptyValues(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	checks := []struct {
		playbook, group string
		want            map[string]any
	}{
		{"log-server-apply.yml", "log-server", map[string]any{"siem_logrotate_rotate": 14, "siem_logrotate_maxage": 90}},
		{"audit-log-forwarding-apply.yml", "audit-log-forwarding", map[string]any{
			"audit_logrotate_rotate": 14, "audit_logrotate_maxage": 90, "syslog_logrotate_rotate": 14, "syslog_logrotate_maxage": 90}},
		{"log-shipping-apply.yml", "log-server", map[string]any{"loki_port": 3100, "loki_endpoint": "pilot-loki-backend:3100"}},
	}
	for _, c := range checks {
		for _, empty := range []any{"", nil} {
			gv := map[string]any{}
			names := make([]string, 0, len(c.want))
			for name := range c.want {
				if name != "loki_endpoint" {
					gv[name] = empty
				}
				names = append(names, name)
			}
			got := siemResolve(t, c.playbook, c.group, isDefaultsTask, gv, names...)
			for name, want := range c.want {
				if !jsonEqual(got[name], want) {
					t.Errorf("%s with %s=%#v: got %v, want %v", c.playbook, name, empty, got[name], want)
				}
			}
		}
	}
}

// logrotateSyntaxCheck is the validate of every logrotate policy the apply
// playbooks write. It fails when logrotate reports an error about the policy
// file itself ("error: <file>:..."), which makes logrotate skip the whole
// policy: with a line number ("error: x:3 argument expected after rotate
// count", "error: x:3 bad rotation count 'abc'", "error: x:4 unknown option
// 'bogusoption'") or without one ("error: x:prerotate, postrotate or
// preremove without endscript"). Captured 2026-10-14 on Ubuntu 24.04
// (logrotate 3.21.0) and AlmaLinux 9.8 (3.18.0). `logrotate -d`'s exit code
// alone is not usable: it is also 1 for Ubuntu's distro rsyslog policy, which
// relies on /etc/logrotate.conf's global `su root adm` ("error: skipping ...
// because parent directory has insecure permissions"), and for an unreadable
// state file; neither names the policy file. The playbooks install logrotate
// first; without it the check fails.
const logrotateSyntaxCheck = `/bin/sh -c 'command -v logrotate >/dev/null && ! logrotate -d "$0" 2>&1 | grep -F -e "error: $0:"' %s`

// TestRegression_LogrotatePoliciesAreValidated: every task that writes a
// logrotate policy validates it with logrotateSyntaxCheck.
func TestRegression_LogrotatePoliciesAreValidated(t *testing.T) {
	files, err := filepath.Glob("../../playbooks/apply/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	writers := map[string]bool{"copy": true, "template": true, "lineinfile": true, "blockinfile": true, "replace": true}
	found := 0
	var walk func(path string, tasks []any)
	walk = func(path string, tasks []any) {
		for _, raw := range tasks {
			task, _ := raw.(map[string]any)
			for _, key := range []string{"block", "rescue", "always"} {
				if sub, ok := task[key].([]any); ok {
					walk(path, sub)
				}
			}
			for key, args := range task {
				m, ok := args.(map[string]any)
				if !ok || !writers[strings.TrimPrefix(key, "ansible.builtin.")] {
					continue
				}
				target := fmt.Sprint(m["dest"]) + fmt.Sprint(m["path"])
				if !strings.Contains(target, "logrotate") {
					continue
				}
				if state, _ := m["state"].(string); state == "absent" && key != "ansible.builtin.lineinfile" && key != "lineinfile" {
					continue
				}
				found++
				if v, _ := m["validate"].(string); v != logrotateSyntaxCheck {
					t.Errorf("%s: task %q writes %s with validate %q, want %q", path, task["name"], target, v, logrotateSyntaxCheck)
				}
			}
		}
	}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var plays []map[string]any
		if err := yaml.Unmarshal(raw, &plays); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, play := range plays {
			for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
				if tasks, ok := play[section].([]any); ok {
					walk(path, tasks)
				}
			}
		}
	}
	// log-server Step 4, audit-log-forwarding Steps 4, 5 and 5c.
	if found < 4 {
		t.Fatalf("found only %d logrotate writers; the walker is broken", found)
	}
}

// TestRegression_LogrotateSyntaxCheckThroughAnsible runs logrotateSyntaxCheck
// as a copy task's validate on localhost: a valid policy is written, and a
// `rotate ` left empty or an unknown option fails validation.
func TestRegression_LogrotateSyntaxCheckThroughAnsible(t *testing.T) {
	for _, bin := range []string{"ansible-playbook", "logrotate"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed: %v", bin, err)
		}
	}
	dir := t.TempDir()
	policy := "%s/*.log {\n    daily\n    rotate %s\n    missingok\n}\n"
	for _, tc := range []struct {
		name, rotate string
		ok           bool
	}{{"valid", "14", true}, {"empty count", "", false}, {"bad count", "abc", false}, {"unknown option", "14\n    bogusoption", false}} {
		dest := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
		tasks := []any{
			map[string]any{"name": "write the policy", "ansible.builtin.copy": map[string]any{
				"dest": dest, "mode": "0600", "content": fmt.Sprintf(policy, dir, tc.rotate), "validate": logrotateSyntaxCheck}},
			showTask([]string{"inventory_hostname"}),
		}
		_, failed := tryInventoryPlay(t, "log-server", nil, tasks, nil)
		_, statErr := os.Stat(dest)
		switch {
		case tc.ok && (failed != "" || statErr != nil):
			t.Errorf("%s: want the policy written, got %q (stat: %v)", tc.name, failed, statErr)
		case !tc.ok && (!strings.Contains(failed, "failed to validate") || statErr == nil):
			t.Errorf("%s: want validation to fail and nothing written, got %q (stat: %v)", tc.name, failed, statErr)
		}
	}
}

// selinuxPortTasks returns tasks/rsyslog-selinux-tcp-port.yml rewritten to
// run on a localhost without SELinux: the SELinux detection is dropped and
// its condition forced true, the dnf task is dropped, the query runs under a fake seobject module
// (records from $PILOT_FAKE_SEPORTS, or ImportError when that is "missing"),
// and seport is replaced by a debug task so the test sees whether it ran.
func selinuxPortTasks(t *testing.T) []any {
	t.Helper()
	raw, err := os.ReadFile("../../playbooks/apply/tasks/rsyslog-selinux-tcp-port.yml")
	if err != nil {
		t.Fatal(err)
	}
	var tasks []map[string]any
	if err := yaml.Unmarshal(raw, &tasks); err != nil {
		t.Fatal(err)
	}
	fake := t.TempDir()
	module := "import json, os\n" +
		"if os.environ.get('PILOT_FAKE_SEPORTS') == 'missing':\n    raise ImportError('no seobject')\n" +
		"class portRecords:\n    def get_all(self):\n" +
		"        return {(r[0], r[0], 'tcp'): (r[1], 's0') for r in json.loads(os.environ.get('PILOT_FAKE_SEPORTS', '[]'))}\n"
	if err := os.WriteFile(filepath.Join(fake, "seobject.py"), []byte(module), 0o644); err != nil {
		t.Fatal(err)
	}
	const selinuxOn = "rsyslog_selinux_enforce.stat.exists"
	var out []any
	sawSeport := false
	for _, task := range tasks {
		if _, ok := task["ansible.builtin.dnf"]; ok {
			continue
		}
		if stat, ok := task["ansible.builtin.stat"].(map[string]any); ok && stat["path"] == "/sys/fs/selinux/enforce" {
			continue
		}
		switch w := task["when"].(type) {
		case string:
			if w == selinuxOn {
				task["when"] = true
			}
		case []any:
			for i, c := range w {
				if c == selinuxOn {
					w[i] = true
				}
			}
		}
		if cmd, ok := task["ansible.builtin.command"].(map[string]any); ok {
			argv := cmd["argv"].([]any)
			argv[0] = "/usr/bin/python3"
			task["environment"] = map[string]any{"PYTHONPATH": fake, "PILOT_FAKE_SEPORTS": "{{ fake_seports }}"}
		}
		if _, ok := task["community.general.seport"]; ok {
			delete(task, "community.general.seport")
			task["ansible.builtin.debug"] = map[string]any{"msg": "label"}
			sawSeport = true
		}
		out = append(out, task)
	}
	if !sawSeport || len(out) != 3 {
		t.Fatalf("expected the query, the assert and seport in the task file; got %d tasks (seport %v)", len(out), sawSeport)
	}
	return append(out, map[string]any{
		"name":                  "show",
		"ansible.builtin.debug": map[string]any{"msg": "{{ {'type': rsyslog_selinux_port_type.stdout, 'labelled': not (rsyslog_selinux_port_label.skipped | default(false))} | to_json }}"},
	})
}

// TestRegression_RsyslogSELinuxPortDecision: rsyslogd (syslogd_t) may use
// only TCP ports labelled syslogd_port_t or rsh_port_t (tcp/514) —
// `sesearch -A -s syslogd_t -c tcp_socket` on AlmaLinux 9.8,
// selinux-policy-targeted 38.1.75. A port with no record of its own (2514 is
// only in the unreserved_port_t range) must be labelled; one rsyslogd may
// already use is left alone; one another service owns (http_port_t) is
// refused rather than relabelled. Without the Python bindings the check run
// skips the label and a real run fails.
func TestRegression_RsyslogSELinuxPortDecision(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	tasks := selinuxPortTasks(t)
	inv := map[string]any{"all": map[string]any{"children": map[string]any{
		"log-server": map[string]any{"hosts": map[string]any{"localhost": localHostVars()}},
	}}}
	const gate = "SELinux: tcp/2514 is free for rsyslogd"
	cases := []struct {
		name, records string
		check         bool
		labelled      bool
		fail          string
	}{
		{"no record of its own", `[[514, "rsh_port_t"]]`, false, true, ""},
		{"already syslogd_port_t", `[[2514, "syslogd_port_t"]]`, false, false, ""},
		{"rsh_port_t", `[[2514, "rsh_port_t"]]`, false, false, ""},
		{"another service's port", `[[2514, "http_port_t"]]`, false, false, gate},
		{"another service's port, check mode", `[[2514, "http_port_t"]]`, true, false, gate},
		{"no bindings, check mode", "missing", true, false, ""},
		{"no bindings", "missing", false, false, gate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vars := map[string]any{"rsyslog_selinux_tcp_port": 2514, "fake_seports": tc.records}
			var args []string
			if tc.check {
				args = append(args, "--check")
			}
			got, failed := tryInventoryPlayIn(t, inv, nil, "log-server", vars, tasks, args...)
			switch {
			case tc.fail != "":
				if !strings.Contains(failed, tc.fail) {
					t.Errorf("want %q to fail, got %q", tc.fail, failed)
				}
			case failed != "":
				t.Errorf("want success, got %q", failed)
			case got["labelled"] != tc.labelled:
				t.Errorf("labelled = %v, want %v (port type %v)", got["labelled"], tc.labelled, got["type"])
			}
		})
	}
}

// TestRegression_RsyslogPortsAreLabelledBeforeRsyslogUsesThem: both SIEM
// playbooks include the SELinux task file for the port they configure, with
// the tags of the task that writes that port, and restart rsyslog when the
// label changes (imtcp does not retry a failed bind).
func TestRegression_RsyslogPortsAreLabelledBeforeRsyslogUsesThem(t *testing.T) {
	for _, c := range []struct {
		playbook, port, writer, restart string
	}{
		{"log-server-apply.yml", "{{ siem_receiver_tcp_port }}", "Step 3: Render 10-siem-receiver.conf", "Step 6a: Restart rsyslog"},
		{"audit-log-forwarding-apply.yml", "{{ siem_forward_port }}", "Step 7: Render 99-siem-forward.conf", "Step 9a: Restart rsyslog"},
	} {
		play := loadFirstPlay(t, c.playbook)
		var flat []map[string]any
		var walk func([]any)
		walk = func(tasks []any) {
			for _, raw := range tasks {
				task, _ := raw.(map[string]any)
				flat = append(flat, task)
				if sub, ok := task["block"].([]any); ok {
					walk(sub)
				}
			}
		}
		walk(play["tasks"].([]any))
		include, writer, restart := -1, -1, -1
		for i, task := range flat {
			name, _ := task["name"].(string)
			if inc, ok := task["ansible.builtin.include_tasks"].(map[string]any); ok && inc["file"] == "tasks/rsyslog-selinux-tcp-port.yml" {
				include = i
				vars, _ := task["vars"].(map[string]any)
				if vars["rsyslog_selinux_tcp_port"] != c.port {
					t.Errorf("%s: the SELinux include must pass rsyslog_selinux_tcp_port=%s, got %v", c.playbook, c.port, vars["rsyslog_selinux_tcp_port"])
				}
				apply, _ := inc["apply"].(map[string]any)
				if fmt.Sprint(apply["tags"]) != fmt.Sprint(task["tags"]) {
					t.Errorf("%s: include tags %v and apply tags %v differ", c.playbook, task["tags"], apply["tags"])
				}
			}
			if strings.HasPrefix(name, c.writer) {
				writer = i
				if include >= 0 && fmt.Sprint(task["tags"]) != fmt.Sprint(flat[include]["tags"]) {
					t.Errorf("%s: the SELinux include must carry the tags of %q (%v), got %v", c.playbook, c.writer, task["tags"], flat[include]["tags"])
				}
			}
			if strings.HasPrefix(name, c.restart) {
				restart = i
				if !strings.Contains(fmt.Sprint(task["when"]), "rsyslog_selinux_port_label") {
					t.Errorf("%s: %q must also restart when the SELinux port label changed, got when %v", c.playbook, name, task["when"])
				}
			}
		}
		if include < 0 || writer < 0 || restart < 0 || include >= writer || writer >= restart {
			t.Errorf("%s: want the SELinux include before %q before %q; got indexes %d, %d, %d", c.playbook, c.writer, c.restart, include, writer, restart)
		}
	}
}

// TestRegression_SIEMPortsAreTCPPortNumbers: the SIEM ports and loki_port
// are rendered into rsyslog, Wazuh and Promtail configuration and compared as
// strings. Values that preflight or YAML accept as numbers, such as 2514.0,
// 1e3, 0x9C4, 02514 or 70000, were passed through, and 0 silently became the
// default. Each playbook refuses them before its defaults task; unset, null
// and "" still mean the default. Values go in as JSON extra vars so that
// floats and booleans reach Ansible as such.
func TestRegression_SIEMPortsAreTCPPortNumbers(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	gates := []struct{ playbook, group, variable string }{
		{"log-server-apply.yml", "log-server", "siem_receiver_tcp_port"},
		{"audit-log-forwarding-apply.yml", "audit-log-forwarding", "siem_forward_port"},
		{"wazuh-manager-apply.yml", "wazuh-manager", "siem_forward_port"},
		{"log-shipping-apply.yml", "log-server", "loki_port"},
	}
	accepted := []string{`null`, `""`, `514`, `"514"`, `2514`, `"2514"`, `1`, `65535`}
	refused := []string{`0`, `"0"`, `-1`, `"-1"`, `65536`, `70000`, `2514.0`, `"2514.0"`, `1e3`, `"0x9C4"`, `"02514"`,
		`"+2514"`, `"2514 "`, `" 2514"`, `"2514\n"`, `true`, `"abc"`, `[2514]`}
	for _, g := range gates {
		g := g
		t.Run(g.variable+"/"+g.playbook, func(t *testing.T) {
			play := loadFirstPlay(t, g.playbook)
			gateName := "Gate: " + g.variable + " is a TCP port number"
			tasks := pickTasks(play, func(name string) bool { return name == gateName })
			if len(tasks) != 1 {
				t.Fatalf("%s: want exactly one %q task, got %d", g.playbook, gateName, len(tasks))
			}
			tasks = append(tasks, showTask([]string{g.variable}))
			inv := map[string]any{"all": map[string]any{"children": map[string]any{
				g.group: map[string]any{"hosts": map[string]any{"localhost": localHostVars()}},
			}}}
			try := func(value string) string {
				_, failed := tryInventoryPlayIn(t, inv, nil, g.group, nil, tasks, "-e", `{"`+g.variable+`": `+value+`}`)
				return failed
			}
			for _, v := range accepted {
				if failed := try(v); failed != "" {
					t.Errorf("%s=%s: want accepted, got %s", g.variable, v, failed)
				}
			}
			for _, v := range refused {
				if failed := try(v); !strings.Contains(failed, gateName) {
					t.Errorf("%s=%s: want %q to fail, got %q", g.variable, v, gateName, failed)
				}
			}
			// Unset: the variable is not passed at all.
			if _, failed := tryInventoryPlayIn(t, inv, nil, g.group, nil, tasks); failed != "" {
				t.Errorf("%s unset: want accepted, got %s", g.variable, failed)
			}
		})
	}
}

// TestRegression_LogrotateValidateRefusesBrokenPolicies runs
// logrotateSyntaxCheck, which TestRegression_LogrotatePoliciesAreValidated
// requires of every logrotate policy, against real logrotate. It must fail
// for an error about the policy file, with a line number or without one (a
// postrotate block without endscript), and pass for a valid policy.
func TestRegression_LogrotateValidateRefusesBrokenPolicies(t *testing.T) {
	if _, err := exec.LookPath("logrotate"); err != nil {
		t.Skipf("logrotate not installed: %v", err)
	}
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := func(body string) string {
		return logs + "/*.log {\n" + body + "}\n"
	}
	cases := []struct {
		name, body string
		ok         bool
	}{
		{"valid", policy("  daily\n  rotate 14\n  maxage 90\n  missingok\n  notifempty\n  compress\n  postrotate\n    true\n  endscript\n"), true},
		{"empty rotate count", policy("  daily\n  rotate \n"), false},
		{"non-numeric rotate count", policy("  daily\n  rotate abc\n"), false},
		{"unknown option", policy("  daily\n  bogusoption\n"), false},
		{"postrotate without endscript", policy("  daily\n  postrotate\n    true\n"), false},
	}
	for _, tc := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
		if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("/bin/sh", "-c", strings.ReplaceAll(logrotateSyntaxCheck, "%s", path)).CombinedOutput()
		switch {
		case tc.ok && err != nil:
			t.Errorf("%s: want the validate to pass, got %v\n%s", tc.name, err, out)
		case !tc.ok && err == nil:
			t.Errorf("%s: want the validate to fail, it passed", tc.name)
		}
	}
}

// TestRegression_LogServerStep2DoesNotFollowASymlink: the gates check the
// directory siem_log_root resolves to, and Step 2 then makes it owned by the
// rsyslog user. On Ubuntu that user may write /var/log, so it could put a
// symlink in place of the directory between the gates and Step 2. Step 2 must
// work on the resolved path without following a symlink: run on a symlink it
// fails and leaves the symlink's target alone.
func TestRegression_LogServerStep2DoesNotFollowASymlink(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	play := loadFirstPlay(t, "log-server-apply.yml")
	var step2 map[string]any
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if name, _ := x["name"].(string); strings.HasPrefix(name, "Step 2: Ensure") {
				step2 = x
			}
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(play)
	if step2 == nil {
		t.Fatal("log-server-apply.yml has no \"Step 2: Ensure ...\" task")
	}
	args, _ := step2["ansible.builtin.file"].(map[string]any)
	if args["path"] != "{{ siem_log_root_real }}" || args["follow"] != false {
		t.Fatalf("Step 2 must work on siem_log_root_real with follow: false, got path=%v follow=%v", args["path"], args["follow"])
	}

	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "siem")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(me.Gid)
	if err != nil {
		t.Fatal(err)
	}
	task := map[string]any{"name": step2["name"], "ansible.builtin.file": args}
	vars := map[string]any{"siem_log_root": link, "siem_log_root_real": link, "siem_log_owner": me.Username}
	// The task sets owner and group from siem_log_owner; use a group this user
	// is in so the only reason to fail is the symlink.
	argsCopy := map[string]any{}
	for k, v := range args {
		argsCopy[k] = v
	}
	argsCopy["group"] = group.Name
	task["ansible.builtin.file"] = argsCopy
	if _, failed := tryInventoryPlay(t, "log-server", vars, []any{task, showTask([]string{"siem_log_root"})}, nil); failed == "" {
		t.Fatalf("Step 2 on a symlink (%s -> %s): want it to fail, it passed", link, target)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("Step 2 changed the symlink target's mode to %o; want it left at 700", fi.Mode().Perm())
	}
}
