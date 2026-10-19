package spec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// apparmorLocal is the AppArmor local file log-server writes its rules into.
const apparmorLocal = "/etc/apparmor.d/local/usr.sbin.rsyslogd"

// apparmorBlock renders the pilot block for rules as blockinfile writes it
// (captured from /etc/apparmor.d/local/usr.sbin.rsyslogd on Ubuntu 24.04,
// 2026-10-16). No rules: Ubuntu's local file as the package ships it, 0 bytes.
func apparmorBlock(roots ...string) string {
	if len(roots) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("# BEGIN pilot log-server log root\n")
	for _, r := range roots {
		b.WriteString(r + "/ rw,\n" + r + "/** rwk,\n")
	}
	b.WriteString("# END pilot log-server log root\n")
	return b.String()
}

// withPath returns tasks with every occurrence of from replaced by to.
func withPath(t *testing.T, tasks []map[string]any, from, to string) []any {
	t.Helper()
	raw, err := yaml.Marshal(tasks)
	if err != nil {
		t.Fatal(err)
	}
	var out []any
	if err := yaml.Unmarshal([]byte(strings.ReplaceAll(string(raw), from, to)), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRegression_LogServerKeepsTheOldRootGrantedUntilRsyslogRestarts runs
// tasks/rsyslog-confined-log-root.yml, through Ansible, up to the task that
// writes the AppArmor block, on a temporary copy of the local file. On
// 56c7582 the `grant` step wrote only the new root and the reload refused
// the running rsyslogd the root it still wrote until Step 6a restarted it:
// on pr79-log two audit messages from a client were lost (2026-10-16).
// Before the restart the block must keep every rule it grants; the `narrow`
// step, once rsyslog runs the new root, keeps only the new root's.
func TestRegression_LogServerKeepsTheOldRootGrantedUntilRsyslogRestarts(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	file := loadTaskFile(t, "rsyslog-confined-log-root.yml")
	var prefix []map[string]any
	for _, task := range file {
		switch task["name"] {
		case "MAC: is the rsyslogd AppArmor profile in use":
			task = map[string]any{"ansible.builtin.set_fact": map[string]any{"rsyslog_apparmor_profile": map[string]any{"stat": map[string]any{"exists": true}}}}
		case "MAC: is AppArmor enabled":
			task = map[string]any{"ansible.builtin.set_fact": map[string]any{"rsyslog_apparmor_enabled": map[string]any{"stat": map[string]any{"exists": true}}}}
		}
		if task["name"] == "MAC: allow rsyslogd to write the log root under AppArmor" {
			// The test runs unprivileged: the owner is not what it checks.
			args := map[string]any{}
			for k, v := range task["ansible.builtin.blockinfile"].(map[string]any) {
				if k != "owner" && k != "group" {
					args[k] = v
				}
			}
			copied := map[string]any{}
			for k, v := range task {
				copied[k] = v
			}
			copied["ansible.builtin.blockinfile"] = args
			prefix = append(prefix, copied)
			break
		}
		prefix = append(prefix, task)
	}
	if last := prefix[len(prefix)-1]; last["name"] != "MAC: allow rsyslogd to write the log root under AppArmor" {
		t.Fatal("tasks/rsyslog-confined-log-root.yml has no task writing the AppArmor block")
	}

	cases := []struct {
		name, phase, root string
		before            string
		want              string
		wantChanged       bool
	}{
		{"grant: root changed, the old root stays", "grant", "/srv/siem2", apparmorBlock("/srv/siem"), apparmorBlock("/srv/siem2", "/srv/siem"), true},
		{"grant: root unchanged", "grant", "/srv/siem", apparmorBlock("/srv/siem"), apparmorBlock("/srv/siem"), false},
		{"grant: back to /var/log/siem, the old root stays", "grant", "/var/log/siem", apparmorBlock("/srv/siem"), apparmorBlock("/srv/siem"), false},
		{"grant: first custom root", "grant", "/srv/siem", "", apparmorBlock("/srv/siem"), true},
		{"grant: default root, nothing granted", "grant", "/var/log/siem", "", "", false},
		{"grant: rerun after a run that did not narrow", "grant", "/srv/siem2", apparmorBlock("/srv/siem2", "/srv/siem"), apparmorBlock("/srv/siem2", "/srv/siem"), false},
		{"narrow: the old root dropped", "narrow", "/srv/siem2", apparmorBlock("/srv/siem2", "/srv/siem"), apparmorBlock("/srv/siem2"), true},
		{"narrow: back on /var/log/siem, the block dropped", "narrow", "/var/log/siem", apparmorBlock("/srv/siem"), "", true},
		{"narrow: nothing to drop", "narrow", "/srv/siem", apparmorBlock("/srv/siem"), apparmorBlock("/srv/siem"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			local := filepath.Join(t.TempDir(), "usr.sbin.rsyslogd")
			if err := os.WriteFile(local, []byte(c.before), 0o644); err != nil {
				t.Fatal(err)
			}
			tasks := withPath(t, prefix, apparmorLocal, local)
			tasks = append(tasks,
				map[string]any{"ansible.builtin.set_fact": map[string]any{
					"block":   "{{ lookup('file', '" + local + "', rstrip=false) }}",
					"changed": "{{ rsyslog_apparmor_local is changed }}",
				}},
				showTask([]string{"block", "changed"}))
			got, failed := tryInventoryPlay(t, "log-server", map[string]any{
				"rsyslog_log_root": c.root, "rsyslog_log_root_phase": c.phase,
			}, tasks, nil)
			if failed != "" {
				t.Fatal(failed)
			}
			if got["block"] != c.want {
				t.Errorf("local file:\n%s\nwant:\n%s", got["block"], c.want)
			}
			if got["changed"] != c.wantChanged {
				t.Errorf("changed %v, want %v", got["changed"], c.wantChanged)
			}
		})
	}

	// The rescue removes a file-context rule the run added. A skipped task
	// still registers its result, so the `narrow` phase, which skips the
	// SELinux tasks, overwrites rsyslog_selinux_fcontext; the rescue reads
	// a fact set in the `grant` phase only.
	t.Run("the rescue still knows a rule was added after the narrow phase", func(t *testing.T) {
		t.Parallel()
		remember := taskNamed(t, file, "MAC: remember whether this run added the file-context rule")
		var rescue []map[string]any
		for _, task := range loadFirstPlay(t, "log-server-apply.yml")["tasks"].([]any) {
			if m, ok := task.(map[string]any); ok && m["rescue"] != nil {
				for _, x := range m["rescue"].([]any) {
					rescue = append(rescue, x.(map[string]any))
				}
			}
		}
		var rescueRemoves []string
		for _, c := range taskNamed(t, rescue, "ROLLBACK — remove the SELinux file-context rule this apply added")["when"].([]any) {
			rescueRemoves = append(rescueRemoves, "("+c.(string)+")")
		}
		label := taskNamed(t, file, "MAC: label the log root var_log_t under SELinux")
		labelWhen, _ := label["when"].([]any)
		var conds []string
		for _, c := range labelWhen {
			conds = append(conds, "("+c.(string)+")")
		}
		got, failed := tryInventoryPlay(t, "log-server", nil, []any{
			map[string]any{"ansible.builtin.set_fact": map[string]any{
				"rsyslog_log_root_phase": "grant", "rsyslog_selinux_fcontext": map[string]any{"changed": true}, "log_server_rescue_selinux_remove": true,
			}},
			remember,
			// What the narrow phase registers for the skipped sefcontext task.
			map[string]any{"ansible.builtin.set_fact": map[string]any{
				"rsyslog_log_root_phase":   "narrow",
				"rsyslog_selinux_fcontext": map[string]any{"changed": false, "skipped": true, "skip_reason": "Conditional result was False"},
				"rsyslog_selinux_enforce":  map[string]any{"stat": map[string]any{"exists": true}},
			}},
			map[string]any{"ansible.builtin.set_fact": map[string]any{
				"narrow_labels": "{{ " + strings.Join(conds, " and ") + " }}",
			}, "vars": map[string]any{"rsyslog_log_root_in_var_log": false}},
			remember,
			map[string]any{"ansible.builtin.set_fact": map[string]any{
				"rescue_removes": "{{ " + strings.Join(rescueRemoves, " and ") + " }}",
			}, "vars": map[string]any{"rsyslog_selinux_fcontext_target": "/srv/siem2(/.*)?"}},
			showTask([]string{"rsyslog_selinux_fcontext_added", "narrow_labels", "rescue_removes"}),
		}, nil)
		if failed != "" {
			t.Fatal(failed)
		}
		if got["rsyslog_selinux_fcontext_added"] != true {
			t.Errorf("after the narrow phase rsyslog_selinux_fcontext_added = %v, want true", got["rsyslog_selinux_fcontext_added"])
		}
		if got["narrow_labels"] != false {
			t.Errorf("the narrow phase must not run the SELinux rule task; its condition is %v", got["narrow_labels"])
		}
		if got["rescue_removes"] != true {
			t.Errorf("after the narrow phase the rescue must still remove the rule the grant phase added; its condition is %v", got["rescue_removes"])
		}
	})
}

// TestRegression_LogServerDropsOldRootRulesOnlyAfterTheRestart: the `narrow`
// step must run after Step 6a, under the same tags, and only when its own
// check says rsyslog runs the receiver config and listens on its port (AGENTS
// §4.4: a cleanup checks its preconditions itself under --tags). Step 6a must
// also restart an rsyslog that started before the receiver config was last
// written, and Step 7 must fail when rsyslog does not listen after it.
func TestRegression_LogServerDropsOldRootRulesOnlyAfterTheRestart(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	play := loadFirstPlay(t, "log-server-apply.yml")
	var body []map[string]any
	for _, task := range play["tasks"].([]any) {
		if m, ok := task.(map[string]any); ok && m["rescue"] != nil {
			for _, x := range m["block"].([]any) {
				body = append(body, x.(map[string]any))
			}
		}
	}
	index := func(name string) int {
		t.Helper()
		for i, task := range body {
			if task["name"] == name {
				return i
			}
		}
		t.Fatalf("log-server's block has no task %q", name)
		return -1
	}
	grant := index("Step 2a: Let a confined rsyslogd write siem_log_root")
	pending := index("Step 6a: Check whether rsyslog started before the receiver config was last written")
	restart := index("Step 6a: Restart rsyslog only if the receiver config, its SELinux port label or its log-root access changed")
	probe := index("Step 7: Check that rsyslog runs the receiver config and listens on its port")
	check := index("Step 7: rsyslog is running and listens on the receiver port")
	narrow := index("Step 7a: Drop the AppArmor rules for roots rsyslog no longer writes")
	order := []int{grant, pending, restart, probe, check, narrow}
	for i := 1; i < len(order); i++ {
		if order[i-1] >= order[i] {
			t.Fatalf("want Step 2a < the pending check < Step 6a < the probe < Step 7 < Step 7a; got %v", order)
		}
	}
	phase := func(i int) any {
		vars, _ := body[i]["vars"].(map[string]any)
		return vars["rsyslog_log_root_phase"]
	}
	if phase(grant) != "grant" || phase(narrow) != "narrow" {
		t.Errorf("Step 2a must include the task file in phase grant and Step 7a in phase narrow; got %v, %v", phase(grant), phase(narrow))
	}
	include, _ := body[narrow]["ansible.builtin.include_tasks"].(map[string]any)
	if include["file"] != "tasks/rsyslog-confined-log-root.yml" {
		t.Errorf("Step 7a must include tasks/rsyslog-confined-log-root.yml; got %v", include["file"])
	}

	conds := func(i int) string {
		var out []string
		switch w := body[i]["when"].(type) {
		case string:
			out = append(out, "("+w+")")
		case []any:
			for _, c := range w {
				out = append(out, "("+c.(string)+")")
			}
		}
		return "{{ " + strings.Join(out, " and ") + " }}"
	}
	that, _ := body[check]["ansible.builtin.assert"].(map[string]any)["that"].(string)
	if that == "" {
		t.Fatal("Step 7 must assert on the probe's result")
	}
	states := []string{"ok", "pending-restart", "not-listening", "inactive", "unknown"}
	wantNarrow := map[string]bool{"ok": true}
	wantPass := map[string]bool{"ok": true, "pending-restart": true, "unknown": true}
	var tasks []any
	for i, s := range states {
		tasks = append(tasks, map[string]any{
			"vars": map[string]any{"log_server_receiver_state": map[string]any{"stdout": s}},
			"ansible.builtin.set_fact": map[string]any{
				fmt.Sprintf("narrow%d", i): conds(narrow),
				fmt.Sprintf("pass%d", i):   "{{ " + that + " }}",
			},
		})
	}
	for i, out := range []string{"pending", ""} {
		tasks = append(tasks, map[string]any{
			"vars": map[string]any{
				"log_server_restart_pending": map[string]any{"stdout": out},
				"siem_receiver_conf_result":  map[string]any{"changed": false},
			},
			"ansible.builtin.set_fact": map[string]any{fmt.Sprintf("restart%d", i): conds(restart)},
		})
	}
	var names []string
	for i := range states {
		names = append(names, fmt.Sprintf("narrow%d", i), fmt.Sprintf("pass%d", i))
	}
	tasks = append(tasks, showTask(append(names, "restart0", "restart1")))
	got, failed := tryInventoryPlay(t, "log-server", nil, tasks, nil)
	if failed != "" {
		t.Fatal(failed)
	}
	for i, s := range states {
		if got[fmt.Sprintf("narrow%d", i)] != wantNarrow[s] {
			t.Errorf("probe %q: Step 7a runs = %v, want %v", s, got[fmt.Sprintf("narrow%d", i)], wantNarrow[s])
		}
		if got[fmt.Sprintf("pass%d", i)] != wantPass[s] {
			t.Errorf("probe %q: Step 7 passes = %v, want %v", s, got[fmt.Sprintf("pass%d", i)], wantPass[s])
		}
	}
	if got["restart0"] != true || got["restart1"] != false {
		t.Errorf("Step 6a must restart rsyslog when it started before the config was written, and only then (nothing else changed); got %v, %v", got["restart0"], got["restart1"])
	}
}

// TestRegression_LogServerReceiverProbes runs Step 6a's pending check and
// Step 7's probe as Ansible renders them, with fake systemctl and ss printing
// output captured on Ubuntu 24.04 (2026-10-16) and a receiver config whose
// mtime is set before or after rsyslog's start.
func TestRegression_LogServerReceiverProbes(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	play := loadFirstPlay(t, "log-server-apply.yml")
	var body []map[string]any
	for _, task := range play["tasks"].([]any) {
		if m, ok := task.(map[string]any); ok && m["rescue"] != nil {
			for _, x := range m["block"].([]any) {
				body = append(body, x.(map[string]any))
			}
		}
	}
	script := func(name string) string {
		t.Helper()
		shell, _ := taskNamed(t, body, name)["ansible.builtin.shell"].(map[string]any)
		cmd, _ := shell["cmd"].(string)
		if cmd == "" {
			t.Fatalf("%q has no shell cmd", name)
		}
		return cmd
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "10-siem-receiver.conf")
	if err := os.WriteFile(conf, []byte("# receiver\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, failed := tryInventoryPlay(t, "log-server", map[string]any{"siem_receiver_conf": conf, "siem_receiver_tcp_port": 514}, []any{
		map[string]any{"ansible.builtin.set_fact": map[string]any{
			"probe":   script("Step 7: Check that rsyslog runs the receiver config and listens on its port"),
			"pending": script("Step 6a: Check whether rsyslog started before the receiver config was last written"),
		}},
		showTask([]string{"probe", "pending"}),
	}, nil)
	if failed != "" {
		t.Fatal(failed)
	}

	// `systemctl show --timestamp=us -p ActiveEnterTimestamp --value rsyslog`
	// and `ss -Hlntp "( sport = :514 )"` on pr79d-log; the python3 line is
	// `python3 -m http.server` holding a port.
	const started = "Fri 2026-10-16 05:53:23.314398 UTC"
	startedAt := time.Date(2026, 10, 16, 5, 53, 23, 314398000, time.UTC)
	const rsyslogd = "LISTEN 0      25     0.0.0.0:514 0.0.0.0:* users:((\"rsyslogd\",pid=3844,fd=6))\n" +
		"LISTEN 0      25        [::]:514    [::]:* users:((\"rsyslogd\",pid=3844,fd=7))\n"
	const python = "LISTEN 0      5      0.0.0.0:514 0.0.0.0:* users:((\"python3\",pid=8120,fd=3))\n"
	cases := []struct {
		name        string
		active      bool
		written     time.Time
		ss          string
		wantProbe   string
		wantPending string
	}{
		{"running the config, listening", true, startedAt.Add(-time.Hour), rsyslogd, "ok", ""},
		{"config written after the start", true, startedAt.Add(500 * time.Millisecond), rsyslogd, "pending-restart", "pending"},
		{"another process holds the port", true, startedAt.Add(-time.Hour), python, "not-listening", ""},
		{"nothing listens", true, startedAt.Add(-time.Hour), "", "not-listening", ""},
		{"rsyslog stopped", false, startedAt.Add(-time.Hour), "", "inactive", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			conf2 := filepath.Join(dir, "10-siem-receiver.conf")
			if err := os.WriteFile(conf2, []byte("# receiver\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(conf2, c.written, c.written); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			active := "exit 0"
			if !c.active {
				active = "exit 3"
			}
			fakes := map[string]string{
				"systemctl": "#!/bin/sh\ncase \"$1\" in\n  is-active) " + active + " ;;\n  show) echo '" + started + "' ;;\nesac\n",
				"ss":        "#!/bin/sh\nprintf '%s' '" + c.ss + "'\n",
			}
			for name, body := range fakes {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			run := func(script string) string {
				t.Helper()
				cmd := exec.Command("/bin/sh", "-c", strings.ReplaceAll(script, conf, conf2))
				cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TZ=UTC")
				out, err := cmd.Output()
				if err != nil {
					t.Fatalf("%v (output %q)", err, out)
				}
				return strings.TrimSpace(string(out))
			}
			if out := run(got["probe"].(string)); out != c.wantProbe {
				t.Errorf("probe %q, want %q", out, c.wantProbe)
			}
			if out := run(got["pending"].(string)); out != c.wantPending {
				t.Errorf("pending check %q, want %q", out, c.wantPending)
			}
		})
	}
}

// TestRegression_LogServerRescueKeepsTheRootRsyslogWrites runs log-server's
// snapshot tasks and its whole rescue, through Ansible, on a temporary
// AppArmor local file, with each AppArmor reload replaced by a record of the
// file it would load. At every reload the file must grant the root the
// running rsyslog writes: the rules from before the run until rsyslog runs
// this run's configuration, and this run's too while it does. On 56c7582 the
// rescue reloaded only the rules from before the run, so after a failure
// past Step 6a the running rsyslogd was refused the root it wrote.
func TestRegression_LogServerRescueKeepsTheRootRsyslogWrites(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	play := loadFirstPlay(t, "log-server-apply.yml")
	var block map[string]any
	for _, task := range play["tasks"].([]any) {
		if m, ok := task.(map[string]any); ok && m["rescue"] != nil {
			block = m
		}
	}
	var snapshot, rescue []map[string]any
	for _, x := range block["block"].([]any) {
		if task := x.(map[string]any); strings.HasPrefix(fmt.Sprint(task["name"]), "Snapshot: ") {
			snapshot = append(snapshot, task)
		}
	}
	for _, x := range block["rescue"].([]any) {
		rescue = append(rescue, x.(map[string]any))
	}
	isReload := func(task map[string]any) bool {
		cmd, _ := task["ansible.builtin.command"].(map[string]any)
		argv, _ := cmd["argv"].(string)
		return strings.Contains(argv, "apparmor_parser")
	}

	const run = "/srv/siem2"
	cases := []struct {
		name string
		// the root rsyslog wrote before the run, and what the local file held
		// before the run (nil: no file) and after it
		before      string
		localBefore *string
		localAfter  string
		// rsyslog restarted during the run (it writes the run's root), and
		// the rescue's validation result
		restartedInRun bool
		rc             int
		wantFinal      *string
		wantReloads    int
	}{
		{"failed before the restart", "/srv/siem", ptr(apparmorBlock("/srv/siem")), apparmorBlock(run, "/srv/siem"), false, 1, ptr(apparmorBlock("/srv/siem")), 2},
		{"failed before the restart, 56c7582's block", "/srv/siem", ptr(apparmorBlock("/srv/siem")), apparmorBlock(run), false, 1, ptr(apparmorBlock("/srv/siem")), 2},
		{"failed after the restart, rescue cannot restart", "/srv/siem", ptr(apparmorBlock("/srv/siem")), apparmorBlock(run), true, 1, ptr(apparmorBlock("/srv/siem", run)), 1},
		{"failed after the restart, rescue restarts", "/srv/siem", ptr(apparmorBlock("/srv/siem")), apparmorBlock(run), true, 0, ptr(apparmorBlock("/srv/siem")), 2},
		{"failed before Step 2a changed anything", "/srv/siem", ptr(apparmorBlock("/srv/siem")), apparmorBlock("/srv/siem"), false, 1, ptr(apparmorBlock("/srv/siem")), 0},
		{"local file created by the run", "/var/log/siem", nil, apparmorBlock(run), false, 1, nil, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			local := filepath.Join(dir, "usr.sbin.rsyslogd")
			conf := filepath.Join(dir, "10-siem-receiver.conf")
			rotate := filepath.Join(dir, "siem-incoming")
			if err := os.WriteFile(conf, []byte("# receiver on "+c.before+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			// rsyslog started after this; Step 6a restarts it when the
			// config is newer than its start.
			written := time.Now().Add(-time.Hour).Truncate(time.Second)
			if err := os.Chtimes(conf, written, written); err != nil {
				t.Fatal(err)
			}
			if c.localBefore != nil {
				if err := os.WriteFile(local, []byte(*c.localBefore), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			after := filepath.Join(dir, "after")
			if err := os.WriteFile(after, []byte(c.localAfter), 0o644); err != nil {
				t.Fatal(err)
			}
			invocation := "9549b23d647e4aa88706133af6e79da5"
			now := invocation
			if c.restartedInRun {
				now = "253461967ea44e439abf152b5429d36f"
			}
			// The root the running rsyslog writes, as each reload sees it.
			writes := "{{ '" + c.before + "' if (rescue_restarted | default(false)) or not " + fmt.Sprint(c.restartedInRun) + " else '" + run + "' }}"
			var tasks []any
			for _, task := range withPath(t, snapshot, apparmorLocal, local) {
				m := task.(map[string]any)
				if m["name"] == "Snapshot: which rsyslog process is running" {
					m = map[string]any{"ansible.builtin.set_fact": map[string]any{"log_server_snapshot_rsyslog": map[string]any{"stdout": invocation, "rc": 0}}}
				}
				delete(m, "tags")
				tasks = append(tasks, m)
			}
			tasks = append(tasks,
				map[string]any{"name": "the failed run", "ansible.builtin.shell": "cp " + after + " " + local + " && printf 'receiver on " + run + "\\n' > " + conf},
				map[string]any{"ansible.builtin.set_fact": map[string]any{
					"rsyslog_apparmor_mode":   "enforce",
					"rsyslog_apparmor_local":  map[string]any{"changed": c.localAfter != *orEmpty(c.localBefore)},
					"rsyslog_apparmor_reload": map[string]any{"changed": c.localAfter != *orEmpty(c.localBefore)},
					"reloads":                 []any{},
				}})
			for _, task := range withPath(t, rescue, apparmorLocal, local) {
				m := task.(map[string]any)
				delete(m, "tags")
				switch {
				case m["name"] == "ROLLBACK — validate the restored rsyslog configuration":
					m = map[string]any{"ansible.builtin.set_fact": map[string]any{"log_server_rescue_syntax": map[string]any{"rc": c.rc}}}
				case m["name"] == "ROLLBACK — restart rsyslog with the restored configuration":
					m["ansible.builtin.set_fact"] = map[string]any{"rescue_restarted": true}
					delete(m, "ansible.builtin.systemd")
				case m["name"] == "ROLLBACK — which rsyslog process is running now":
					m = map[string]any{"ansible.builtin.set_fact": map[string]any{"log_server_rescue_rsyslog": map[string]any{
						"rc": 0, "stdout": "{{ 'restarted-by-rescue' if rescue_restarted | default(false) else '" + now + "' }}"}}}
				case m["name"] == "ROLLBACK — is rsyslog active after recovery":
					m = map[string]any{"ansible.builtin.set_fact": map[string]any{"log_server_rescue_active": map[string]any{"rc": 0}}}
				case m["name"] == "ROLLBACK — surface the original failure":
					m["ansible.builtin.set_fact"] = map[string]any{"message": m["ansible.builtin.fail"].(map[string]any)["msg"]}
					delete(m, "ansible.builtin.fail")
				case isReload(m):
					delete(m, "ansible.builtin.command")
					m["ansible.builtin.set_fact"] = map[string]any{"reloads": "{{ reloads + [{'file': lookup('file', '" + local + "', rstrip=false) if '" + local + "' is exists else '', 'writes': " + strings.Trim(writes, "{} ") + "}] }}"}
				}
				tasks = append(tasks, m)
			}
			tasks = append(tasks,
				map[string]any{"ansible.builtin.set_fact": map[string]any{
					"final":  "{{ lookup('file', '" + local + "', rstrip=false) if '" + local + "' is exists else '__absent__' }}",
					"writes": writes,
				}},
				showTask([]string{"reloads", "final", "writes", "message"}))
			got, failed := tryInventoryPlay(t, "log-server", map[string]any{
				"siem_receiver_conf": conf, "siem_logrotate_conf": rotate, "siem_log_root_real": run,
			}, tasks, nil)
			if failed != "" {
				t.Fatal(failed)
			}
			reloads, _ := got["reloads"].([]any)
			grants := func(file, root string) bool {
				return strings.HasPrefix(root+"/", "/var/log/") || strings.Contains(file, "\n"+root+"/** rwk,\n")
			}
			for i, r := range reloads {
				m := r.(map[string]any)
				file, root := fmt.Sprint(m["file"]), fmt.Sprint(m["writes"])
				if !grants(file, root) {
					t.Errorf("reload %d loads rules without %s, which the running rsyslog writes:\n%s", i+1, root, file)
				}
			}
			if len(reloads) != c.wantReloads {
				t.Errorf("%d reloads, want %d", len(reloads), c.wantReloads)
			}
			want := "__absent__"
			if c.wantFinal != nil {
				want = *c.wantFinal
			}
			if got["final"] != want {
				t.Errorf("local file after the rescue:\n%s\nwant:\n%s", got["final"], want)
			}
			if final, root := fmt.Sprint(got["final"]), fmt.Sprint(got["writes"]); c.wantFinal != nil && !grants(final, root) {
				t.Errorf("after the rescue the rules do not grant %s, which the running rsyslog writes", root)
			}
			// While rsyslog runs the configuration from before the run, the
			// put-back config keeps its time from before the run, so the
			// next run does not restart rsyslog for it; once rsyslog runs
			// this run's configuration, the config stays newer than its start.
			info, err := os.Stat(conf)
			if err != nil {
				t.Fatal(err)
			}
			stillOld := !c.restartedInRun && c.rc != 0
			if kept := info.ModTime().Equal(written); stillOld != kept {
				t.Errorf("receiver config time %v (before the run %v); want it kept: %v", info.ModTime(), written, stillOld)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// orEmpty returns s, or a pointer to "" for nil.
func orEmpty(s *string) *string {
	if s == nil {
		return ptr("")
	}
	return s
}
