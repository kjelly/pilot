package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The three sshd configuration writes that
// TestRegression_SshdConfigWritesAreValidatedAndReverted allowlisted until
// 2026-10-12, run on localhost with the stand-ins runFCTasks uses: sshd -t
// is fc_sshd_cmd, the copy's validate is fc_validate_cmd, the reload is a
// debug task, and dir stands in for /etc/ssh.
//   - freeipa-client-apply.yml wrote its password-auth drop-in without
//     validating it and restarted sshd; with another file in sshd_config.d
//     broken, the restart failed and sshd stayed down, and the next run,
//     finding the drop-in unchanged, did not try again.
//   - freeipa-client-decommission.yml removed it and restarted sshd the same
//     way; a resume found it gone and never restarted.
//   - pilot-access-target-policy-apply.yml's absent path removed its drop-in,
//     and reloaded only when the removal changed something: after a failed
//     sshd -t no later run reloaded, and sshd kept the policy.

// sshdSite is one sshd configuration write and the task range around it.
type sshdSite struct {
	name, path  string
	first, last string // the snapshot task and the block, in one task list
	dropin      string
	backup      string // a file the site removes only after a reload, or ""
	write       bool   // writes content; otherwise removes the drop-in
	content     string // a line the written drop-in contains
	vars        map[string]any
}

var sshdSites = []sshdSite{
	{name: "freeipa-client", path: "../../playbooks/apply/freeipa-client-apply.yml",
		first:  "FreeIPA client — snapshot the password-auth drop-in this run may replace",
		last:   "FreeIPA client — allow password/keyboard-interactive SSH, validated and reloaded",
		dropin: "/etc/ssh/sshd_config.d/05-freeipa-client-password-auth.conf", write: true,
		content: "PasswordAuthentication yes", vars: map[string]any{"ansible_os_family": "Debian"}},
	{name: "freeipa-client-decommission", path: "../../playbooks/decommission/freeipa-client-decommission.yml",
		first:  "FreeIPA client decommission — snapshot the password-auth drop-in",
		last:   "FreeIPA client decommission — remove the password-auth drop-in, validated and reloaded",
		dropin: "/etc/ssh/sshd_config.d/05-freeipa-client-password-auth.conf",
		vars:   map[string]any{"ansible_os_family": "RedHat"}},
	{name: "pilot-access-target-policy absent", path: "../../playbooks/apply/pilot-access-target-policy-apply.yml",
		first: "Snapshot the policy drop-in before removing it", last: "Remove the policy (put back on failure)",
		dropin: "/etc/ssh/sshd_config.d/06-pilot-access-target-policy.conf",
		backup: "/etc/ssh/sshd_config.d/06-pilot-access-target-policy.conf.pre-pilot-access-target-policy.bak",
		vars:   map[string]any{"ansible_os_family": "Debian"}},
}

// sshdSiteTasks returns the site's play vars and its task range, wherever
// in the play's task tree it sits.
func sshdSiteTasks(t *testing.T, site sshdSite) (map[string]any, []map[string]any) {
	t.Helper()
	doc, _ := loadYAML(t, site.path).([]any)
	for _, item := range doc {
		play, ok := item.(map[string]any)
		if !ok {
			continue
		}
		vars, _ := play["vars"].(map[string]any)
		for _, section := range []string{"pre_tasks", "tasks"} {
			if tasks := taskRange(play[section], site.first, site.last); tasks != nil {
				return vars, tasks
			}
		}
	}
	t.Fatalf("%s: no task list holds %q through %q", site.path, site.first, site.last)
	return nil, nil
}

// taskRange finds the task list, at any depth, that holds a task named
// first, and returns its tasks from first through last.
func taskRange(list any, first, last string) []map[string]any {
	tasks, _ := list.([]any)
	start := -1
	for i, item := range tasks {
		task, _ := item.(map[string]any)
		if fcName(task) == first {
			start = i
		}
		if start >= 0 && fcName(task) == last {
			var out []map[string]any
			for _, it := range tasks[start : i+1] {
				out = append(out, it.(map[string]any))
			}
			return out
		}
	}
	for _, item := range tasks {
		task, _ := item.(map[string]any)
		for _, key := range []string{"block", "rescue", "always"} {
			if out := taskRange(task[key], first, last); out != nil {
				return out
			}
		}
	}
	return nil
}

func runSshdSite(t *testing.T, site sshdSite, dir string, extra map[string]any) fcRun {
	t.Helper()
	playVars, tasks := sshdSiteTasks(t, site)
	var keep []map[string]any
	for _, task := range tasks {
		keep = append(keep, fcRewrite(task))
	}
	vars := map[string]any{}
	for k, v := range site.vars {
		vars[k] = v
	}
	for k, v := range extra {
		vars[k] = v
	}
	return runLocalTasks(t, playVars, keep, dir, vars)
}

func (r fcRun) sshdChecked() bool {
	for name := range r.ran {
		if strings.HasSuffix(name, "sshd -t") || strings.Contains(name, "sshd -t ") ||
			strings.Contains(name, "sshd configuration is valid") {
			return true
		}
	}
	return false
}

func (r fcRun) reloaded() bool {
	for _, m := range r.messages {
		if strings.Contains(m, "SYSTEMD ") && strings.Contains(m, " reloaded") {
			return true
		}
	}
	return false
}

func sshdSitePath(dir, real string) string {
	return filepath.Join(dir, "sshd_config.d", filepath.Base(real))
}

// TestRegression_SshdConfigWritesPutBackOnFailure: each site validates,
// reloads, and puts the drop-in back when sshd -t fails, and the run after
// a failure validates and reloads again.
func TestRegression_SshdConfigWritesPutBackOnFailure(t *testing.T) {
	const previous = "# a previous drop-in\nPasswordAuthentication no\n"
	type tc struct {
		name     string
		before   string // drop-in before the run, "" for none
		extra    map[string]any
		fail     bool
		wantSshd bool
	}
	for _, site := range sshdSites {
		var cases []tc
		if site.write {
			cases = []tc{
				{name: "writes, validates and reloads", wantSshd: true},
				{name: "sshd -t fails, no drop-in before", extra: map[string]any{"fc_sshd_cmd": fcSshdFails}, fail: true, wantSshd: true},
				{name: "sshd -t fails, a previous drop-in", before: previous, extra: map[string]any{"fc_sshd_cmd": fcSshdFails}, fail: true, wantSshd: true},
				{name: "the drop-in fails its own validation", extra: map[string]any{"fc_validate_cmd": "false"}, fail: true},
			}
		} else {
			cases = []tc{
				{name: "removes, validates and reloads", before: previous, wantSshd: true},
				{name: "sshd -t fails after removing", before: previous, extra: map[string]any{"fc_sshd_cmd": fcSshdFails}, fail: true, wantSshd: true},
			}
		}
		for _, c := range cases {
			t.Run(site.name+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				if err := os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0o755); err != nil {
					t.Fatal(err)
				}
				dropin := sshdSitePath(dir, site.dropin)
				if c.before != "" {
					if err := os.WriteFile(dropin, []byte(c.before), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				var backup string
				if site.backup != "" {
					backup = sshdSitePath(dir, site.backup)
					if err := os.WriteFile(backup, []byte("snapshot\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				res := runSshdSite(t, site, dir, c.extra)
				failures := strings.Join(res.failures, "\n")
				if (res.rc != 0) != c.fail || res.sshdChecked() != c.wantSshd || res.reloaded() == c.fail {
					t.Fatalf("rc=%d sshd -t ran=%v reloaded=%v failures=%v; want failed=%v, sshd -t ran=%v, reloaded=%v",
						res.rc, res.sshdChecked(), res.reloaded(), res.failures, c.fail, c.wantSshd, !c.fail)
				}
				got, err := os.ReadFile(dropin)
				switch {
				case c.fail && c.before == "" && err == nil:
					t.Errorf("the failed run left a drop-in:\n%s", got)
				case c.fail && c.before != "" && string(got) != c.before:
					t.Errorf("drop-in after the failed run = %q (err %v), want the previous %q", got, err, c.before)
				case !c.fail && site.write && !strings.Contains(string(got), site.content):
					t.Errorf("drop-in = %q (err %v), want it to contain %q", got, err, site.content)
				case !c.fail && !site.write && err == nil:
					t.Errorf("the drop-in is still there:\n%s", got)
				}
				if c.fail {
					if !strings.Contains(failures, "back") && !strings.Contains(failures, "left no") {
						t.Errorf("failures=%v; want the message to say the drop-in was put back", res.failures)
					}
					if c.wantSshd && !strings.Contains(failures, "Bad configuration option") {
						t.Errorf("failures=%v; want sshd's own message", res.failures)
					}
				}
				if backup != "" {
					_, err := os.Stat(backup)
					if c.fail && err != nil {
						t.Errorf("the failed run removed the pre-change snapshot: %v", err)
					}
					if !c.fail && err == nil {
						t.Errorf("the pre-change snapshot is still there")
					}
				}
			})
		}
	}
}

// TestRegression_SshdConfigWritesRetryAfterAFailure: the run after one whose
// sshd -t failed validates and reloads, because the failed run put the
// drop-in back. Before, the drop-in was already as wanted and nothing ran.
func TestRegression_SshdConfigWritesRetryAfterAFailure(t *testing.T) {
	for _, site := range sshdSites {
		t.Run(site.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0o755); err != nil {
				t.Fatal(err)
			}
			dropin := sshdSitePath(dir, site.dropin)
			if !site.write {
				if err := os.WriteFile(dropin, []byte("PasswordAuthentication yes\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			first := runSshdSite(t, site, dir, map[string]any{"fc_sshd_cmd": fcSshdFails})
			if first.rc == 0 {
				t.Fatalf("first run passed with a failing sshd -t: %v", first.failures)
			}
			second := runSshdSite(t, site, dir, nil)
			_, err := os.Stat(dropin)
			if second.rc != 0 || !second.sshdChecked() || !second.reloaded() || (err == nil) != site.write {
				t.Errorf("rerun: rc=%d failures=%v sshd -t=%v reload=%v drop-in present=%v; want it validated and reloaded",
					second.rc, second.failures, second.sshdChecked(), second.reloaded(), err == nil)
			}
		})
	}
}

func TestSshdSitesExist(t *testing.T) {
	for _, site := range sshdSites {
		_, tasks := sshdSiteTasks(t, site)
		if len(tasks) < 3 {
			t.Errorf("%s: %d tasks from %q to %q, want the snapshot, the read and the block", site.name, len(tasks), site.first, site.last)
		}
		if got := fmt.Sprint(tasks[len(tasks)-1]["rescue"]); got == "<nil>" {
			t.Errorf("%s: %q has no rescue", site.name, site.last)
		}
	}
}

// ipaGateSite is a FreeIPA installer run and the sshd -t gate before it:
// tasks first through last in one task list, plus the installer named
// installer when it sits elsewhere in the play (the realm replacement's gate
// is in pre_tasks, its installer in a block in tasks).
type ipaGateSite struct {
	name, path, first, last, installer, refusal string
	// enrolled returns the vars that make the installer due or not; nil
	// when the gate always runs.
	enrolled func(dir string, due bool) map[string]any
}

// markerVar is an enrolled func for a gate and installer sharing
// `creates: {{ name }}`.
func markerVar(name string) func(dir string, due bool) map[string]any {
	return func(dir string, due bool) map[string]any {
		marker := filepath.Join(dir, name)
		if !due {
			_ = os.WriteFile(marker, []byte("done\n"), 0o644)
		}
		return map[string]any{name: marker, "ipa_realm": "IPA.TEST"}
	}
}

var ipaGateSites = []ipaGateSite{
	{name: "freeipa-client enroll", path: "../../playbooks/apply/freeipa-client-apply.yml",
		first:   "FreeIPA client — sshd -t before ipa-client-install restarts sshd",
		last:    "FreeIPA client — run ipa-client-install (enroll into {{ ipa_realm }})",
		refusal: "Refusing to run ipa-client-install", enrolled: markerVar("ipa_config_marker")},
	{name: "freeipa-client decommission uninstall", path: "../../playbooks/decommission/freeipa-client-decommission.yml",
		first:   "FreeIPA client decommission — sshd -t before the uninstall restarts sshd",
		last:    "FreeIPA client decommission — remove FreeIPA client enrollment",
		refusal: "Refusing to run ipa-client-install --uninstall",
		enrolled: func(dir string, due bool) map[string]any {
			return map[string]any{"freeipa_decom_cfg": map[string]any{"stat": map[string]any{"exists": due}}}
		}},
	{name: "freeipa-server install", path: "../../playbooks/apply/freeipa-server-apply.yml",
		first:   "FreeIPA — sshd -t before ipa-server-install restarts sshd",
		last:    "FreeIPA — run ipa-server-install (native; first run is 8–12 min)",
		refusal: "Refusing to run ipa-server-install", enrolled: markerVar("ipa_config_marker")},
	{name: "freeipa-server-replica enroll", path: "../../playbooks/apply/freeipa-server-replica-apply.yml",
		first:   "FreeIPA replica — sshd -t before ipa-client-install restarts sshd",
		last:    "FreeIPA replica — step 1/2: ipa-client-install (enroll into {{ ipa_realm }})",
		refusal: "Refusing to run ipa-client-install", enrolled: markerVar("ipa_client_log_marker")},
	{name: "freeipa-server-replica promote", path: "../../playbooks/apply/freeipa-server-replica-apply.yml",
		first:   "FreeIPA replica — sshd -t before ipa-replica-install restarts sshd",
		last:    "FreeIPA replica — step 2/2: ipa-replica-install (promote; first run 8-12 min)",
		refusal: "Refusing to run ipa-replica-install", enrolled: markerVar("ipa_replica_config_marker")},
	{name: "freeipa-realm-replacement", path: "../../playbooks/apply/freeipa-realm-replacement-apply.yml",
		first:     "Realm replacement — sshd -t before ipa-client-install restarts sshd",
		last:      "Gate: the sshd configuration is valid before replacing the realm",
		installer: "Realm replacement — remove old client enrollment",
		refusal:   "Refusing to replace the realm"},
}

// TestRegression_IpaInstallersCheckSshdFirst: the installer, which restarts
// sshd, runs only after sshd -t passes; with sshd -t failing the run stops
// before it. A host the installer would skip (already enrolled, or no longer
// enrolled) is not blocked.
func TestRegression_IpaInstallersCheckSshdFirst(t *testing.T) {
	cases := []struct {
		name      string
		due       bool
		sshdFails bool
		wantRan   bool
		wantFail  bool
	}{
		{name: "sshd -t passes", due: true, wantRan: true},
		{name: "sshd -t fails", due: true, sshdFails: true, wantFail: true},
		{name: "installer would skip, sshd -t fails", due: false, sshdFails: true},
	}
	for _, site := range ipaGateSites {
		for _, c := range cases {
			if site.enrolled == nil && !c.due {
				continue
			}
			t.Run(site.name+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				vars := map[string]any{}
				if site.enrolled != nil {
					vars = site.enrolled(dir, c.due)
				}
				ran := filepath.Join(dir, "installer-ran")
				vars["fc_installer_ran"] = ran
				if c.sshdFails {
					vars["fc_sshd_cmd"] = fcSshdFails
				}
				playVars, tasks := sshdSiteTasks(t, sshdSite{name: site.name, path: site.path, first: site.first, last: site.last})
				if site.installer != "" {
					_, more := sshdSiteTasks(t, sshdSite{name: site.name, path: site.path, first: site.installer, last: site.installer})
					tasks = append(tasks, more...)
				}
				var keep []map[string]any
				for _, task := range tasks {
					keep = append(keep, ipaRewrite(task))
				}
				res := runLocalTasks(t, playVars, keep, dir, vars)
				_, err := os.Stat(ran)
				failures := strings.Join(res.failures, "\n")
				if (res.rc != 0) != c.wantFail || (err == nil) != c.wantRan {
					t.Fatalf("rc=%d installer ran=%v failures=%v; want failed=%v, installer ran=%v", res.rc, err == nil, res.failures, c.wantFail, c.wantRan)
				}
				if c.wantFail && (!strings.Contains(failures, site.refusal) || !strings.Contains(failures, "Bad configuration option")) {
					t.Errorf("failures=%v; want %q with sshd's own message", res.failures, site.refusal)
				}
			})
		}
	}
}

// ipaRewrite is fcRewrite plus: an installer run becomes `touch
// {{ fc_installer_ran }}`, keeping its `creates:`.
func ipaRewrite(task map[string]any) map[string]any {
	c := fcRewrite(task)
	if !runsIpaInstaller(task) {
		return c
	}
	for _, key := range []string{"ansible.builtin.command", "command"} {
		args, ok := c[key].(map[string]any)
		if !ok {
			continue
		}
		a := map[string]any{"argv": []any{"touch", "{{ fc_installer_ran }}"}}
		if creates, ok := args["creates"]; ok {
			a["creates"] = creates
		}
		c[key] = a
		delete(c, "vars")
	}
	return c
}
