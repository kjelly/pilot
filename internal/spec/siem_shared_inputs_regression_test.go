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
		return isDefaultsTask(name) || strings.HasPrefix(name, "Gate: siem_log_root") ||
			name == "Gate: inspect every directory on the siem_log_root path" || name == "Gate: list an existing siem_log_root"
	}), showTask([]string{"siem_log_root"}))
	if len(tasks) != 6 {
		t.Fatalf("expected the defaults task, four gate tasks and show; got %d tasks", len(tasks))
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
// comes from inventory a value such as /var/log, a path through a symlink,
// or an existing directory this role did not create must fail before any
// mutation, while a rerun on the directory it did create passes. An
// existing directory must already be in the state Step 2 leaves it in.
func TestRegression_LogServerRefusesASharedSiemLogRoot(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(me.Gid)
	if err != nil || group.Name != me.Username {
		t.Skipf("the gate compares owner and group with one name; %s's primary group is not %s", me.Username, me.Username)
	}
	vars, tasks := logServerGateTasks(t, me.Username)
	run := func(root string) string {
		_, failed := tryInventoryPlay(t, "log-server", vars, tasks, map[string]any{"siem_log_root": root})
		return failed
	}

	// Names.
	for _, ok := range []string{"/var/log/siem-pr79-absent", "/srv/siem-pr79-absent", "/data/logs/siem_1.x"} {
		if failed := run(ok); failed != "" {
			t.Errorf("siem_log_root=%s: want accepted, got %s", ok, failed)
		}
	}
	for _, bad := range []string{"/var/log", "/var", "/", "/srv", "/home", "/usr/share/siem", "/usr/lib", "/etc/rsyslog.d",
		"/run/log", "var/log/siem", "/var/log/siem/", "/var//log/siem", "/var/log/../siem",
		"/var/log/./siem", "/var/log/siem dir", "/var/log/$(id)"} {
		if failed := run(bad); !strings.Contains(failed, "Gate: siem_log_root is a dedicated absolute directory") {
			t.Errorf("siem_log_root=%q: want the name gate to fail, got %q", bad, failed)
		}
	}

	// The filesystem: base is owned by this user and contains no symlink.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mkdir := func(path string) string {
		t.Helper()
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	const content = "Gate: siem_log_root has no symlink and is new or already this role's"
	cases := []struct {
		name string
		root func() string
		ok   bool
	}{
		{"absent", func() string { return filepath.Join(base, "absent", "siem") }, true},
		{"empty", func() string { return mkdir(filepath.Join(base, "empty")) }, true},
		{"rerun: only per-host directories", func() string {
			root := mkdir(filepath.Join(base, "rerun"))
			mkdir(filepath.Join(root, "client-1"))
			if err := os.WriteFile(filepath.Join(root, "client-1", "audit.log"), []byte("x\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return root
		}, true},
		{"a file at the top", func() string {
			root := mkdir(filepath.Join(base, "file"))
			if err := os.WriteFile(filepath.Join(root, "syslog"), []byte("x\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return root
		}, false},
		{"a hidden file at the top", func() string {
			root := mkdir(filepath.Join(base, "hidden"))
			if err := os.WriteFile(filepath.Join(root, ".profile"), []byte("x\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return root
		}, false},
		{"siem_log_root is a symlink", func() string {
			target := mkdir(filepath.Join(base, "target1"))
			link := filepath.Join(base, "link1")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link
		}, false},
		{"a parent is a symlink", func() string {
			target := mkdir(filepath.Join(base, "target2"))
			link := filepath.Join(base, "link2")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, "siem")
		}, false},
		{"an empty directory with another mode (like /var/log/private, 0700)", func() string {
			root := mkdir(filepath.Join(base, "private"))
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			return root
		}, false},
		{"a regular file", func() string {
			path := filepath.Join(base, "regular")
			if err := os.WriteFile(path, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			return path
		}, false},
	}
	if fi, err := os.Lstat("/var/run"); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		cases = append(cases, struct {
			name string
			root func() string
			ok   bool
		}{"a system symlink on the path (/var/run -> /run)", func() string { return "/var/run/siem-pr79" }, false})
	}
	for _, tc := range cases {
		root := tc.root()
		failed := run(root)
		switch {
		case tc.ok && failed != "":
			t.Errorf("%s (%s): want accepted, got %s", tc.name, root, failed)
		case !tc.ok && !strings.Contains(failed, content):
			t.Errorf("%s (%s): want %q to fail, got %q", tc.name, root, content, failed)
		}
	}

	// Directories owned by someone other than siem_log_owner, empty or not.
	otherVars, _ := logServerGateTasks(t, "nobody")
	for _, root := range []string{mkdir(filepath.Join(base, "other-empty")), mkdir(filepath.Join(base, "other", "client-1"))} {
		root = strings.TrimSuffix(root, "/client-1")
		if _, failed := tryInventoryPlay(t, "log-server", otherVars, tasks, map[string]any{"siem_log_root": root}); !strings.Contains(failed, content) {
			t.Errorf("%s not owned by siem_log_owner: want %q to fail, got %q", root, content, failed)
		}
	}
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
		"log-server":           map[string]any{"hosts": map[string]any{"siem-1": map[string]any{"ansible_host": "192.0.2.10"}}},
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

// TestRegression_LogrotatePoliciesAreValidated: every task that writes a
// logrotate policy validates it with `logrotate -d`, which exits 1 on a
// config error (captured on Ubuntu 24.04 logrotate 3.21.0 and AlmaLinux 9.8
// logrotate 3.18.0: "argument expected after rotate count", "bad rotation
// count"); logrotate otherwise skips the broken policy at every run.
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
				if v, _ := m["validate"].(string); !strings.HasPrefix(v, "logrotate -d ") {
					t.Errorf("%s: task %q writes %s without validate: logrotate -d %%s", path, task["name"], target)
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
