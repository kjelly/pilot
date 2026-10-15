package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// loadTaskFile reads a playbooks/apply/tasks file as a task list.
func loadTaskFile(t *testing.T, name string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../playbooks/apply/tasks/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var tasks []map[string]any
	if err := yaml.Unmarshal(raw, &tasks); err != nil {
		t.Fatal(err)
	}
	return tasks
}

// taskNamed returns the task called name, or fails the test.
func taskNamed(t *testing.T, tasks []map[string]any, name string) map[string]any {
	t.Helper()
	for _, task := range tasks {
		if task["name"] == name {
			return task
		}
	}
	t.Fatalf("no task %q", name)
	return nil
}

// listedTasks runs `ansible-playbook --list-tasks` with args and returns the
// names of the tasks it lists that are not tagged always.
func listedTasks(t *testing.T, playbook string, args ...string) []string {
	t.Helper()
	cmd := exec.Command("ansible-playbook", append([]string{"--list-tasks", "-i", "localhost,", playbook}, args...)...)
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ansible-playbook --list-tasks %v: %v\n%s", args, err, out)
	}
	line := regexp.MustCompile(`^      (.+?)\tTAGS: \[(.*)\]$`)
	var names []string
	for _, l := range strings.Split(string(out), "\n") {
		m := line.FindStringSubmatch(l)
		if m == nil || m[2] == "always" {
			continue
		}
		names = append(names, m[1])
	}
	return names
}

// TestRegression_LogServerStepsRunUnderEveryRowTag: log-server's steps share
// the log root, the port and the receiver config. With per-row tags, a
// --tags run applied a changed siem_log_root only in part: `--tags C6` moved
// the AppArmor grant to the new root and restarted rsyslog, which still
// wrote the old one; `--tags C3,C5` pointed rsyslog at a root nobody created
// or granted; `--tags C7` left logrotate on the old root (PR #79 review,
// 2026-10-15). Every row tag must now select every task.
func TestRegression_LogServerStepsRunUnderEveryRowTag(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	const playbook = "../../playbooks/apply/log-server-apply.yml"
	all := listedTasks(t, playbook)
	if len(all) < 10 {
		t.Fatalf("expected the log-server steps, got %v", all)
	}
	s, err := Parse("../../docs/verification/log-server.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range s.Rows {
		t.Run(r.ID, func(t *testing.T) {
			t.Parallel()
			got := listedTasks(t, playbook, "--tags", r.ID)
			missing := map[string]bool{}
			for _, name := range all {
				missing[name] = true
			}
			for _, name := range got {
				delete(missing, name)
			}
			var names []string
			for name := range missing {
				names = append(names, name)
			}
			sort.Strings(names)
			if len(names) > 0 {
				t.Errorf("--tags %s skips: %s", r.ID, strings.Join(names, "; "))
			}
		})
	}
}

// TestRegression_LogServerReloadsAppArmorByTheLoadedProfile evaluates,
// through Ansible, how tasks/rsyslog-confined-log-root.yml reads the loaded
// profile's mode and decides to reload it, with /sys/kernel/security/
// apparmor/profiles lines captured on Ubuntu 24.04 (2026-10-15). The reload
// used to run only when the block changed in this run, so a rerun after a
// run that wrote the block and failed before the reload left the rule
// unloaded and rsyslog refused while the apply succeeded.
func TestRegression_LogServerReloadsAppArmorByTheLoadedProfile(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	file := loadTaskFile(t, "rsyslog-confined-log-root.yml")
	mode := taskNamed(t, file, "MAC: remember the mode of the loaded rsyslogd AppArmor profile")
	reload := taskNamed(t, file, "MAC: reload the rsyslogd AppArmor profile")
	var when []string
	for _, c := range reload["when"].([]any) {
		when = append(when, "("+c.(string)+")")
	}
	changedWhen, _ := reload["changed_when"].(string)
	if changedWhen == "" {
		t.Fatal("the reload must decide changed from its output")
	}

	const enforce = "tcpdump (enforce)\nwpcom (unconfined)\nrsyslogd (enforce)\n/usr/lib/snapd/snap-confine (enforce)\nman_filter (enforce)\n"
	const complain = "tcpdump (enforce)\nrsyslogd (complain)\nman_filter (enforce)\n"
	const disabled = "tcpdump (enforce)\nwpcom (unconfined)\nman_filter (enforce)\n" // after apparmor_parser -R
	cases := []struct {
		name         string
		profiles     string
		inVarLog     bool
		blockChanged bool
		reloadOutput string
		wantMode     string
		wantReload   bool
		wantChanged  bool
	}{
		{"block written by an earlier failed run", enforce, false, false, "changed", "enforce", true, true},
		{"rerun with the rule loaded", enforce, false, false, "unchanged", "enforce", true, false},
		{"block added in this run", enforce, false, true, "changed", "enforce", true, true},
		{"complain mode", complain, false, false, "unchanged", "complain", true, false},
		{"profile disabled", disabled, false, true, "changed", "", false, true},
		{"default root, nothing changed", enforce, true, false, "unchanged", "enforce", false, false},
		{"default root, earlier block removed", enforce, true, true, "changed", "enforce", true, true},
		{"no sha256 in sysfs, block changed", enforce, false, true, "unknown", "enforce", true, true},
		{"no sha256 in sysfs, block unchanged", enforce, false, false, "unknown", "enforce", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			tasks := []any{
				map[string]any{"ansible.builtin.set_fact": map[string]any{
					"rsyslog_apparmor_profiles":   map[string]any{"stdout": c.profiles},
					"rsyslog_apparmor_profile":    map[string]any{"stat": map[string]any{"exists": true}},
					"rsyslog_apparmor_enabled":    map[string]any{"stat": map[string]any{"exists": true}},
					"rsyslog_log_root_in_var_log": c.inVarLog,
					"rsyslog_apparmor_local":      map[string]any{"changed": c.blockChanged},
				}},
				map[string]any{"ansible.builtin.set_fact": mode["ansible.builtin.set_fact"]},
				map[string]any{"ansible.builtin.set_fact": map[string]any{
					"reload":                  "{{ " + strings.Join(when, " and ") + " }}",
					"rsyslog_apparmor_reload": map[string]any{"stdout": c.reloadOutput},
				}},
				map[string]any{"ansible.builtin.set_fact": map[string]any{"changed": "{{ " + changedWhen + " }}"}},
				showTask([]string{"rsyslog_apparmor_mode", "reload", "changed"}),
			}
			got, failed := tryInventoryPlay(t, "log-server", nil, tasks, nil)
			if failed != "" {
				t.Fatal(failed)
			}
			if got["rsyslog_apparmor_mode"] != c.wantMode || got["reload"] != c.wantReload {
				t.Errorf("mode %v reload %v, want %q %v", got["rsyslog_apparmor_mode"], got["reload"], c.wantMode, c.wantReload)
			}
			if c.wantReload && got["changed"] != c.wantChanged {
				t.Errorf("reload output %q, block changed %v: changed %v, want %v", c.reloadOutput, c.blockChanged, got["changed"], c.wantChanged)
			}
		})
	}
}

// TestRegression_LogServerAppArmorReloadScript runs the reload task's script
// as Ansible renders it, against a fake sysfs directory and a fake
// apparmor_parser: it must report whether the loaded profile's sha256
// changed, keep a complain-mode profile in complain mode, and fail when
// apparmor_parser fails.
func TestRegression_LogServerAppArmorReloadScript(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	reload := taskNamed(t, loadTaskFile(t, "rsyslog-confined-log-root.yml"), "MAC: reload the rsyslogd AppArmor profile")
	shell, _ := reload["ansible.builtin.shell"].(map[string]any)
	script, _ := shell["cmd"].(string)
	if !strings.Contains(script, "/sys/kernel/security/apparmor/policy/profiles/rsyslogd.") {
		t.Fatalf("the reload script must read the loaded profile's sha256:\n%s", script)
	}
	render := func(mode string) string {
		t.Helper()
		got, failed := tryInventoryPlay(t, "log-server", nil, []any{
			map[string]any{"ansible.builtin.set_fact": map[string]any{"rsyslog_apparmor_mode": mode}},
			map[string]any{"ansible.builtin.set_fact": map[string]any{"script": script}},
			showTask([]string{"script"}),
		}, nil)
		if failed != "" {
			t.Fatal(failed)
		}
		return got["script"].(string)
	}
	scripts := map[string]string{"enforce": render("enforce"), "complain": render("complain")}

	cases := []struct {
		name, mode, parser string
		sha                bool
		wantOut, wantArgs  string
		wantFail           bool
	}{
		{"rules changed", "enforce", "change", true, "changed", "-r /etc/apparmor.d/usr.sbin.rsyslogd", false},
		{"same rules", "enforce", "same", true, "unchanged", "-r /etc/apparmor.d/usr.sbin.rsyslogd", false},
		{"complain mode", "complain", "same", true, "unchanged", "-r -C /etc/apparmor.d/usr.sbin.rsyslogd", false},
		{"no sha256", "enforce", "same", false, "unknown", "-r /etc/apparmor.d/usr.sbin.rsyslogd", false},
		{"apparmor_parser fails", "enforce", "fail", true, "", "-r /etc/apparmor.d/usr.sbin.rsyslogd", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			profiles := filepath.Join(dir, "profiles")
			if err := os.MkdirAll(filepath.Join(profiles, "rsyslogd.108"), 0o755); err != nil {
				t.Fatal(err)
			}
			sha := filepath.Join(profiles, "rsyslogd.108", "sha256")
			if c.sha {
				if err := os.WriteFile(sha, []byte("564c28ae6089d730d2183070d3031a6910e8747696bd2bd9859c1af32d556db4\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			argsFile := filepath.Join(dir, "args")
			fake := "#!/bin/sh\necho \"$*\" > " + argsFile + "\n" +
				"case " + c.parser + " in\n" +
				"  change) echo 832737b8143fc7a41197e9b0661bbc00f6336110524028e025119eb5bc900a11 > " + sha + " ;;\n" +
				"  fail) echo 'AppArmor parser error' >&2; exit 1 ;;\n" +
				"esac\n"
			if err := os.WriteFile(filepath.Join(bin, "apparmor_parser"), []byte(fake), 0o755); err != nil {
				t.Fatal(err)
			}
			body := strings.ReplaceAll(scripts[c.mode], "/sys/kernel/security/apparmor/policy/profiles", profiles)
			cmd := exec.Command("/bin/sh", "-c", body)
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
			out, err := cmd.Output()
			if c.wantFail != (err != nil) {
				t.Fatalf("want failure %v, got %v (output %q)", c.wantFail, err, out)
			}
			if !c.wantFail && strings.TrimSpace(string(out)) != c.wantOut {
				t.Errorf("output %q, want %q", strings.TrimSpace(string(out)), c.wantOut)
			}
			args, _ := os.ReadFile(argsFile)
			if strings.TrimSpace(string(args)) != c.wantArgs {
				t.Errorf("apparmor_parser %q, want %q", strings.TrimSpace(string(args)), c.wantArgs)
			}
		})
	}
}

// TestRegression_LogServerRescueRestoresWhatItChanged runs log-server's
// snapshot tasks and the rescue's file tasks, through Ansible, on temporary
// copies of the three files the apply may change. The rescue used to delete
// the receiver config even when it had existed before the run (a failed
// `--tags C7` rerun on pr79-el removed the running receiver's config,
// 2026-10-15), and left the AppArmor local file as the failed run wrote it.
func TestRegression_LogServerRescueRestoresWhatItChanged(t *testing.T) {
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
	if block == nil {
		t.Fatal("log-server has no block with a rescue")
	}
	asTasks := func(v any) []map[string]any {
		var out []map[string]any
		for _, x := range v.([]any) {
			out = append(out, x.(map[string]any))
		}
		return out
	}
	body, rescue := asTasks(block["block"]), asTasks(block["rescue"])
	stat := taskNamed(t, body, "Snapshot: is each file this apply may change there")
	slurp := taskNamed(t, body, "Snapshot: keep the content of those that are")
	restore := taskNamed(t, rescue, "ROLLBACK — put back the content of the files this apply changed")
	remove := taskNamed(t, rescue, "ROLLBACK — remove the files this apply created")
	// The rescue restarts rsyslog only if rsyslogd accepts the restored
	// configuration: after a failure caused by another package's invalid
	// drop-in, the unconditional restart left rsyslog without the drop-ins
	// sorting after it, and the next run reported changed=0 (2026-10-15).
	validate, restart := -1, -1
	for i, task := range rescue {
		switch task["name"] {
		case "ROLLBACK — validate the restored rsyslog configuration":
			validate = i
			if cmd, _ := task["ansible.builtin.command"].(string); !strings.Contains(cmd, "rsyslogd -N1") || task["register"] != "log_server_rescue_syntax" {
				t.Errorf("the rescue's validation must run rsyslogd -N1 into log_server_rescue_syntax; got %v", task)
			}
		case "ROLLBACK — restart rsyslog with the restored configuration":
			restart = i
			if when, _ := task["when"].(string); !strings.Contains(when, "log_server_rescue_syntax.rc") {
				t.Errorf("the rescue must restart rsyslog only when the restored configuration validates; when = %v", task["when"])
			}
		}
	}
	if validate < 0 || restart < 0 || validate > restart {
		t.Errorf("the rescue must validate the restored configuration before restarting rsyslog; got indexes %d, %d", validate, restart)
	}
	if loop, _ := stat["loop"].([]any); len(loop) != 3 || loop[2] != "/etc/apparmor.d/local/usr.sbin.rsyslogd" {
		t.Fatalf("the snapshot must cover the receiver config, the logrotate policy and the AppArmor local file; got %v", stat["loop"])
	}

	dir := t.TempDir()
	conf := filepath.Join(dir, "10-siem-receiver.conf")
	rotate := filepath.Join(dir, "siem-incoming")
	local := filepath.Join(dir, "usr.sbin.rsyslogd")
	if err := os.WriteFile(conf, []byte("# the receiver config before the run\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, nil, 0o644); err != nil { // 0 bytes, as Ubuntu ships it
		t.Fatal(err)
	}
	statCopy := map[string]any{}
	for k, v := range stat {
		statCopy[k] = v
	}
	statCopy["loop"] = []any{conf, rotate, local}
	without := func(task map[string]any, key string) map[string]any {
		c := map[string]any{}
		for k, v := range task {
			if k != key {
				c[k] = v
			}
		}
		return c
	}
	tasks := []any{
		without(statCopy, "tags"), without(slurp, "tags"),
		map[string]any{"name": "the failed run changes them", "ansible.builtin.shell": "printf 'new root\\n' > " + conf +
			" && printf 'rotate\\n' > " + rotate + " && printf '/srv/siem/ rw,\\n' > " + local},
		without(restore, "tags"), without(remove, "tags"),
		map[string]any{"ansible.builtin.set_fact": map[string]any{
			"conf":       "{{ lookup('file', '" + conf + "') }}",
			"local":      "{{ lookup('file', '" + local + "') }}",
			"rotate":     "{{ '" + rotate + "' is exists }}",
			"conf_mode":  "{{ lookup('pipe', 'stat -c %a " + conf + "') }}",
			"local_size": "{{ lookup('pipe', 'stat -c %s " + local + "') }}",
		}},
		showTask([]string{"conf", "local", "rotate", "conf_mode", "local_size"}),
	}
	got, failed := tryInventoryPlay(t, "log-server", map[string]any{
		"siem_receiver_conf": conf, "siem_logrotate_conf": rotate,
	}, tasks, nil)
	if failed != "" {
		t.Fatal(failed)
	}
	want := map[string]any{
		"conf": "# the receiver config before the run", "local": "", "rotate": false,
		"conf_mode": "640", "local_size": "0",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("after the rescue %s = %#v, want %#v", k, got[k], v)
		}
	}
}

// TestRegression_LogServerRescueRestartsOnlyAValidConfiguration evaluates,
// through Ansible, the rescue's restart condition and its failure message for
// each result of the `rsyslogd -N1` check: a configuration rsyslogd accepts,
// one it rejects (rsyslog's message for an invalid drop-in, captured on
// 640362e's pr79-log), rsyslogd missing (the result Ansible registers for a
// command that does not exist, captured with ansible-core 2.19.2), and the
// check skipped. On 640362e the rescue restarted rsyslog in every case.
func TestRegression_LogServerRescueRestartsOnlyAValidConfiguration(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	play := loadFirstPlay(t, "log-server-apply.yml")
	var rescue []map[string]any
	for _, task := range play["tasks"].([]any) {
		if m, ok := task.(map[string]any); ok && m["rescue"] != nil {
			for _, x := range m["rescue"].([]any) {
				rescue = append(rescue, x.(map[string]any))
			}
		}
	}
	restart := taskNamed(t, rescue, "ROLLBACK — restart rsyslog with the restored configuration")
	failure := taskNamed(t, rescue, "ROLLBACK — surface the original failure")
	when, _ := restart["when"].(string)
	msg, _ := failure["ansible.builtin.fail"].(map[string]any)["msg"].(string)
	if when == "" || msg == "" {
		t.Fatalf("the restart needs a when and the failure a msg; got %q, %q", when, msg)
	}

	cases := []struct {
		name        string
		result      map[string]any
		wantRestart bool
		wantMsg     string
	}{
		{"accepted", map[string]any{"rc": 0, "stderr_lines": []any{}}, true, "rsyslog was restarted with the restored configuration."},
		{"rejected", map[string]any{"rc": 1, "stderr_lines": []any{
			"rsyslogd: error during parsing file /etc/rsyslog.d/99-pr79-broken.conf, on or before line 1: syntax error on token '{' [v8.2312.0 try https://www.rsyslog.com/e/2207 ]",
		}}, false, "did not pass (rc=1: rsyslogd: error during parsing file /etc/rsyslog.d/99-pr79-broken.conf"},
		{"rsyslogd missing", map[string]any{"rc": 2, "msg": "Error executing command.", "stderr_lines": []any{}}, false, "did not pass (rc=2: Error executing command.)"},
		{"check skipped", map[string]any{"skipped": true}, false, "did not pass (rc=?: no output)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			tasks := []any{
				map[string]any{"ansible.builtin.set_fact": map[string]any{"log_server_rescue_syntax": c.result}},
				map[string]any{"ansible.builtin.set_fact": map[string]any{
					"restart": "{{ " + when + " }}",
					"message": msg,
				}},
				showTask([]string{"restart", "message"}),
			}
			got, failed := tryInventoryPlay(t, "log-server", nil, tasks, nil)
			if failed != "" {
				t.Fatal(failed)
			}
			if got["restart"] != c.wantRestart {
				t.Errorf("restart = %v, want %v", got["restart"], c.wantRestart)
			}
			if m, _ := got["message"].(string); !strings.Contains(m, c.wantMsg) {
				t.Errorf("message %q does not contain %q", m, c.wantMsg)
			}
		})
	}
}
