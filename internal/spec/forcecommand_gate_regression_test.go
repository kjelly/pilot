package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The gateway and the Directory install an sshd ForceCommand drop-in that
// sends every portal user into a wrapper. Their checks that the service
// is healthy, that the gateway's pilot-target-<scope> hostgroup exists and
// that the wrapper is there carried only the service tags, and so did
// `sshd -t` and the reload. So `--tags AG43` (gateway) or `--tags AD18`
// (Directory) wrote the drop-in without any check, and without validating
// or loading it; with the install variable false it did not remove it
// either. A failed `sshd -t` left the drop-in on disk, and the next run,
// finding it unchanged, skipped `sshd -t` and the reload. These tests lock
// the tags and run the playbooks' own ForceCommand tasks on localhost.

// fcPlaybook describes one playbook's ForceCommand tasks.
type fcPlaybook struct {
	name, path, rowTag, groupTag, wrapper, dropin, installVar string
}

var fcPlaybooks = []fcPlaybook{
	{"gateway", "../../playbooks/apply/pilot-access-gateway-apply.yml", "AG43", "AG_forcecommand",
		"/usr/local/libexec/pilot-session", "/etc/ssh/sshd_config.d/90-pilot-access-gateway.conf",
		"pilot_access_gateway_effective_install_forcecommand"},
	{"directory", "../../playbooks/apply/pilot-access-directory-apply.yml", "AD18", "AD_forcecommand",
		"/usr/local/libexec/pilot-directory-session", "/etc/ssh/sshd_config.d/91-pilot-access-directory.conf",
		"pilot_access_directory_effective_install_forcecommand"},
}

func fcPlay(t *testing.T, pb fcPlaybook) (map[string]any, []map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(pb.path)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	vars, _ := plays[0]["vars"].(map[string]any)
	var tasks []map[string]any
	for _, raw := range plays[0]["tasks"].([]any) {
		tasks = append(tasks, raw.(map[string]any))
	}
	return vars, tasks
}

func fcName(task map[string]any) string {
	name, _ := task["name"].(string)
	return name
}

func isFCInstall(name string) bool {
	return strings.Contains(name, "install sshd ForceCommand drop-in")
}

func isFCApply(name string) bool {
	return !strings.Contains(name, "rollback") && (strings.HasSuffix(name, ": sshd -t") || strings.HasSuffix(name, ": reload sshd"))
}

// TestRegression_ForceCommandInstallFollowsItsChecks: every tag of the
// drop-in install selects the checks before it and the sshd -t and reload
// after it; the checks run only when installing, so they never block the
// rollback, and every check but the read-only stat skips check mode, where
// a fresh host has neither the files nor the service yet.
func TestRegression_ForceCommandInstallFollowsItsChecks(t *testing.T) {
	for _, pb := range fcPlaybooks {
		t.Run(pb.name, func(t *testing.T) {
			_, tasks := fcPlay(t, pb)
			type flat struct {
				task map[string]any
				tags []string
			}
			var all []flat
			walkTaskTree(fcTaskList(tasks), nil, func(task map[string]any, tags []string) {
				all = append(all, flat{task, tags})
			})
			var install []string
			gates, applied, rollback := 0, 0, 0
			for _, f := range all {
				if isFCInstall(fcName(f.task)) {
					install = f.tags
				}
			}
			if !slices.Contains(install, pb.rowTag) {
				t.Fatalf("install task tags = %v, want %s", install, pb.rowTag)
			}
			seenInstall := false
			for _, f := range all {
				task, name := f.task, fcName(f.task)
				switch {
				case isFCInstall(name):
					seenInstall = true
					continue
				case strings.HasPrefix(name, "ForceCommand gate: "):
					gates++
					if seenInstall {
						t.Errorf("%q runs after the drop-in install", name)
					}
					when, _ := yaml.Marshal(task["when"])
					if !strings.Contains(string(when), pb.installVar) {
						t.Errorf("%q does not depend on %s, so it would block the rollback", name, pb.installVar)
					}
					if _, isStat := task["ansible.builtin.stat"]; !isStat && !strings.Contains(string(when), "not ansible_check_mode") {
						t.Errorf("%q runs in check mode, where a fresh host has no wrapper, CLI or service to check", name)
					}
				case isFCApply(name):
					applied++
				case strings.Contains(name, " rollback: ") && task["block"] == nil:
					// `--tags AG43` with the install variable false must
					// remove the drop-in, not silently do nothing.
					rollback++
				default:
					continue
				}
				if missing := missingFCTags(f.tags, install); len(missing) > 0 {
					t.Errorf("%q lacks %v, which select the drop-in install", name, missing)
				}
			}
			if gates < 6 || applied != 2 || rollback != 3 {
				t.Errorf("found %d ForceCommand gate tasks, %d sshd -t/reload tasks and %d rollback tasks, want at least 6, 2 and 3",
					gates, applied, rollback)
			}
		})
	}
}

// fcTaskList turns fcPlay's tasks back into the []any walkTaskTree takes.
func fcTaskList(tasks []map[string]any) []any {
	list := make([]any, len(tasks))
	for i, task := range tasks {
		list[i] = task
	}
	return list
}

func missingFCTags(have, want []string) []string {
	var missing []string
	for _, tag := range want {
		if !slices.Contains(have, tag) {
			missing = append(missing, tag)
		}
	}
	return missing
}

// fcRun is the outcome of one localhost run.
type fcRun struct {
	rc       int
	failures []string
	ran      map[string]bool
	messages []string
	raw      string
}

// runFCTasks runs pb's ForceCommand section, from the first gate to the
// rollback, on localhost with dir standing in for /etc/ssh,
// /usr/local/libexec and /usr/bin. curl, getent and sshd run the commands
// in vars fc_health_cmd, fc_getent_cmd and fc_sshd_cmd, and the copy's
// `validate` runs fc_validate_cmd; the systemd reload becomes a debug
// task; owner/group are dropped and the gate's root-owner check expects
// the test's user.
func runFCTasks(t *testing.T, pb fcPlaybook, dir string, extra map[string]any, args ...string) fcRun {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	playVars, tasks := fcPlay(t, pb)
	first, last := -1, -1
	for i, task := range tasks {
		name := fcName(task)
		if first < 0 && strings.HasPrefix(name, "ForceCommand gate: ") {
			first = i
		}
		if strings.Contains(name, "rollback") {
			last = i
		}
	}
	if first < 0 || last < first {
		t.Fatalf("no ForceCommand section (gates %d, rollback %d) in %s", first, last, pb.path)
	}
	var keep []map[string]any
	for _, task := range tasks[first : last+1] {
		keep = append(keep, fcRewrite(task))
	}
	if len(keep) < 6 {
		t.Fatalf("found %d ForceCommand tasks in %s, want at least 6", len(keep), pb.path)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]any{}
	for k, v := range playVars {
		vars[k] = v
	}
	for k, v := range map[string]any{
		"fc_health_cmd":   []any{"printf", "%s", `{"status":"ok"}`},
		"fc_getent_cmd":   []any{"printf", "%s", "role-pilot-portal-user:*:1000:"},
		"fc_sshd_cmd":     []any{"true"},
		"fc_validate_cmd": "true",
	} {
		vars[k] = v
	}
	for k, v := range extra {
		vars[k] = v
	}
	play := []map[string]any{{
		"name": "forcecommand tasks", "hosts": "localhost", "connection": "local",
		"gather_facts": false, "become": false, "vars": vars, "tasks": keep,
	}}
	body, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.NewReplacer(
		"/etc/ssh/sshd_config.d/", filepath.Join(dir, "sshd_config.d")+"/",
		"/usr/local/libexec/", filepath.Join(dir, "libexec")+"/",
		"/usr/bin/pilot", filepath.Join(dir, "bin", "pilot"),
		"selectattr('stat.pw_name', 'equalto', 'root')", "selectattr('stat.pw_name', 'equalto', '"+me.Username+"')",
	).Replace(string(body))
	path := filepath.Join(t.TempDir(), "fc.yml")
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", append([]string{"-i", "localhost,", path}, args...)...)
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1",
		"ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_INVENTORY_UNPARSED_WARNING=False")
	out, runErr := cmd.Output()
	res := fcRun{raw: string(out), ran: map[string]bool{}}
	if ee, ok := runErr.(*exec.ExitError); ok {
		res.rc = ee.ExitCode()
	} else if runErr != nil {
		t.Fatalf("ansible-playbook did not run: %v", runErr)
	}
	var cb struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]struct {
					Failed  bool `json:"failed"`
					Skipped bool `json:"skipped"`
					Msg     any  `json:"msg"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &cb); err != nil {
		t.Fatalf("parse JSON callback output: %v\n%s", err, out)
	}
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			for _, h := range task.Hosts {
				msg, _ := json.Marshal(h.Msg)
				if h.Failed {
					res.failures = append(res.failures, task.Task.Name+": "+string(msg))
				}
				if !h.Skipped {
					res.ran[task.Task.Name] = true
					if h.Msg != nil {
						res.messages = append(res.messages, task.Task.Name+": "+string(msg))
					}
				}
			}
		}
	}
	return res
}

// fcRewrite returns a copy of task, and of the tasks in its block, rescue
// and always sections, with the substitutions runFCTasks describes.
func fcRewrite(task map[string]any) map[string]any {
	c := map[string]any{}
	for k, v := range task {
		c[k] = v
	}
	for _, key := range []string{"block", "rescue", "always"} {
		if list, ok := c[key].([]any); ok {
			sub := make([]any, len(list))
			for i, item := range list {
				sub[i] = fcRewrite(item.(map[string]any))
			}
			c[key] = sub
		}
	}
	for _, mod := range []string{"ansible.builtin.copy", "ansible.builtin.file"} {
		if args, ok := c[mod].(map[string]any); ok {
			a := map[string]any{}
			for k, v := range args {
				if k != "owner" && k != "group" {
					a[k] = v
				}
			}
			if _, ok := a["validate"]; ok {
				a["validate"] = "{{ fc_validate_cmd }} %s"
			}
			c[mod] = a
		}
	}
	if args, ok := c["ansible.builtin.systemd"].(map[string]any); ok {
		delete(c, "ansible.builtin.systemd")
		c["ansible.builtin.debug"] = map[string]any{"msg": fmt.Sprintf("SYSTEMD %v %v", args["name"], args["state"])}
	}
	if args, ok := c["ansible.builtin.command"].(map[string]any); ok {
		argv, _ := args["argv"].([]any)
		if len(argv) > 0 {
			switch argv[0] {
			case "curl":
				c["ansible.builtin.command"] = map[string]any{"argv": "{{ fc_health_cmd }}"}
				delete(c, "retries")
				delete(c, "delay")
			case "getent":
				c["ansible.builtin.command"] = map[string]any{"argv": "{{ fc_getent_cmd }}"}
			case "sshd":
				c["ansible.builtin.command"] = map[string]any{"argv": "{{ fc_sshd_cmd }}"}
			}
		}
	}
	return c
}

// fcHost lays out dir like a host that ran the full playbook: the wrapper
// and the CLI, 0755.
func fcHost(t *testing.T, pb fcPlaybook, dir string) (dropin string) {
	t.Helper()
	for _, d := range []string{"sshd_config.d", "libexec", "bin"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(dir, "libexec", filepath.Base(pb.wrapper)), filepath.Join(dir, "bin", "pilot")} {
		if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "sshd_config.d", filepath.Base(pb.dropin))
}

func fcExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func (r fcRun) applied(t *testing.T) (validated, reloaded bool) {
	t.Helper()
	for name := range r.ran {
		if isFCApply(name) && strings.HasSuffix(name, "sshd -t") {
			validated = true
		}
	}
	return validated, strings.Contains(strings.Join(r.messages, "\n"), "SYSTEMD ssh reloaded")
}

// TestRegression_ForceCommandInstallIsCheckedUnderItsRowTag: under the
// install's row tag and under the ForceCommand group tag, a missing or
// writable wrapper, an unhealthy service and a portal-user group that does
// not resolve each refuse the install with nothing written; a healthy host
// gets the drop-in validated and loaded. On main, `--tags AG43`/`AD18`
// wrote the drop-in in every case and never ran sshd -t or the reload.
func TestRegression_ForceCommandInstallIsCheckedUnderItsRowTag(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T, pb fcPlaybook, dir string)
		extra  map[string]any
		refuse string
	}{
		{name: "healthy"},
		{name: "service down", extra: map[string]any{"fc_health_cmd": []any{"sh", "-c", "echo 'curl: (7) Failed to connect' >&2; exit 7"}},
			refuse: "did not pass its health check"},
		{name: "service degraded", extra: map[string]any{"fc_health_cmd": []any{"sh", "-c", `printf '%s' '{"status":"degraded","target_scope":"missing"}'; exit 22`}},
			refuse: `target_scope`},
		{name: "wrapper missing", setup: func(t *testing.T, pb fcPlaybook, dir string) {
			if err := os.Remove(filepath.Join(dir, "libexec", filepath.Base(pb.wrapper))); err != nil {
				t.Fatal(err)
			}
		}, refuse: "Missing: ['"},
		{name: "wrapper group-writable", setup: func(t *testing.T, pb fcPlaybook, dir string) {
			if err := os.Chmod(filepath.Join(dir, "libexec", filepath.Base(pb.wrapper)), 0o775); err != nil {
				t.Fatal(err)
			}
		}, refuse: "or writable by group or others: ['"},
		{name: "portal group does not resolve", extra: map[string]any{"fc_getent_cmd": []any{"sh", "-c", "exit 2"}},
			refuse: "does not resolve"},
	}
	for _, pb := range fcPlaybooks {
		for _, tags := range []string{pb.rowTag, pb.groupTag} {
			for _, tc := range cases {
				t.Run(pb.name+"/"+tags+"/"+tc.name, func(t *testing.T) {
					t.Parallel()
					dir := t.TempDir()
					dropin := fcHost(t, pb, dir)
					if tc.setup != nil {
						tc.setup(t, pb, dir)
					}
					res := runFCTasks(t, pb, dir, tc.extra, "--tags", tags)
					validated, reloaded := res.applied(t)
					if tc.refuse == "" {
						if res.rc != 0 || !fcExists(dropin) || !validated || !reloaded {
							t.Errorf("rc=%d failures=%v drop-in=%v sshd -t=%v reload=%v; want the drop-in validated and loaded",
								res.rc, res.failures, fcExists(dropin), validated, reloaded)
						}
						return
					}
					if res.rc == 0 || !strings.Contains(strings.Join(res.failures, "\n"), tc.refuse) {
						t.Errorf("rc=%d failures=%v; want a refusal mentioning %q", res.rc, res.failures, tc.refuse)
					}
					if fcExists(dropin) || reloaded {
						t.Errorf("refused run wrote the drop-in (%v) or reloaded sshd (%v)", fcExists(dropin), reloaded)
					}
				})
			}
		}
	}
}

// TestRegression_ForceCommandGatesPreviewAFreshHost: `--check` on a host
// the playbook never ran on (no wrapper, no CLI, no service, no portal
// group yet) previews the install instead of failing in the gates, with no
// tags, the row tag or the group tag (AGENTS.md §4.0, §4.5 point 4).
func TestRegression_ForceCommandGatesPreviewAFreshHost(t *testing.T) {
	for _, pb := range fcPlaybooks {
		for _, tags := range []string{"", pb.rowTag, pb.groupTag} {
			t.Run(pb.name+"/"+tags, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				if err := os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0o755); err != nil {
					t.Fatal(err)
				}
				dropin := filepath.Join(dir, "sshd_config.d", filepath.Base(pb.dropin))
				args := []string{"--check", "--diff"}
				if tags != "" {
					args = append(args, "--tags", tags)
				}
				res := runFCTasks(t, pb, dir, map[string]any{
					"fc_health_cmd": []any{"sh", "-c", "echo 'curl: (7) Failed to connect' >&2; exit 7"},
					"fc_getent_cmd": []any{"sh", "-c", "exit 2"},
				}, args...)
				if res.rc != 0 || len(res.failures) > 0 {
					t.Errorf("--check on a fresh host: rc=%d failures=%v; want the install previewed", res.rc, res.failures)
				}
				if fcExists(dropin) {
					t.Errorf("--check wrote the drop-in")
				}
			})
		}
	}
}

// TestRegression_ForceCommandRollbackIsNeverBlocked: disabling ForceCommand
// removes the drop-in and reloads sshd, under the row tag as well as the
// group tag, even when the service is down, the wrapper is gone and the
// group does not resolve. On 8635152 `--tags AG43`/`AD18` left the drop-in.
func TestRegression_ForceCommandRollbackIsNeverBlocked(t *testing.T) {
	for _, pb := range fcPlaybooks {
		for _, tags := range []string{pb.rowTag, pb.groupTag} {
			t.Run(pb.name+"/"+tags, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				dropin := fcHost(t, pb, dir)
				if err := os.WriteFile(dropin, []byte("Match Group x\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(dir, "libexec", filepath.Base(pb.wrapper))); err != nil {
					t.Fatal(err)
				}
				res := runFCTasks(t, pb, dir, map[string]any{
					pb.installVar:   false,
					"fc_health_cmd": []any{"sh", "-c", "exit 7"},
					"fc_getent_cmd": []any{"sh", "-c", "exit 2"},
				}, "--tags", tags)
				_, reloaded := res.applied(t)
				if res.rc != 0 || fcExists(dropin) || !reloaded {
					t.Errorf("rollback: rc=%d failures=%v drop-in left=%v reloaded=%v", res.rc, res.failures, fcExists(dropin), reloaded)
				}
				for name := range res.ran {
					if strings.HasPrefix(name, "ForceCommand gate: ") {
						t.Errorf("%q ran while disabling ForceCommand", name)
					}
				}
			})
		}
	}
}

// fcSshdFails is an `sshd -t` that rejects the configuration, with the
// message sshd prints for an unknown keyword.
var fcSshdFails = []any{"sh", "-c", "echo '/etc/ssh/sshd_config.d/00-other.conf line 1: Bad configuration option: Bogus' >&2; exit 255"}

// TestRegression_ForceCommandFailedSshdCheckLeavesNoDropin: when the drop-in
// fails its own validation, or `sshd -t` rejects the whole configuration,
// the run fails, sshd is not reloaded, and the drop-in is what the run
// found: absent, or the previous content. So the next run sees a change
// and validates and loads it. On 8635152 the drop-in stayed, and the next
// run, finding it unchanged, skipped `sshd -t` and the reload and passed.
// Removing it is undone the same way.
func TestRegression_ForceCommandFailedSshdCheckLeavesNoDropin(t *testing.T) {
	const previous = "Match Group role-pilot-portal-user\n    ForceCommand /usr/local/libexec/previous\n"
	cases := []struct {
		name     string
		before   string // drop-in content before the run, "" for none
		extra    map[string]any
		install  bool
		wantMsg  string
		wantSshd bool // whether the whole-configuration sshd -t ran
	}{
		{name: "sshd -t fails, no drop-in before", extra: map[string]any{"fc_sshd_cmd": fcSshdFails},
			install: true, wantMsg: "was not installed", wantSshd: true},
		{name: "sshd -t fails, a previous drop-in", before: previous, extra: map[string]any{"fc_sshd_cmd": fcSshdFails},
			install: true, wantMsg: "is back to what this run found", wantSshd: true},
		{name: "the drop-in fails its own validation", extra: map[string]any{"fc_validate_cmd": "false"},
			install: true, wantMsg: "was not installed"},
		{name: "sshd -t fails after removing the drop-in", before: previous, extra: map[string]any{"fc_sshd_cmd": fcSshdFails},
			wantMsg: "was not removed", wantSshd: true},
	}
	for _, pb := range fcPlaybooks {
		for _, tags := range []string{pb.rowTag, pb.groupTag} {
			for _, tc := range cases {
				t.Run(pb.name+"/"+tags+"/"+tc.name, func(t *testing.T) {
					t.Parallel()
					dir := t.TempDir()
					dropin := fcHost(t, pb, dir)
					if tc.before != "" {
						if err := os.WriteFile(dropin, []byte(tc.before), 0o644); err != nil {
							t.Fatal(err)
						}
					}
					extra := map[string]any{pb.installVar: tc.install}
					for k, v := range tc.extra {
						extra[k] = v
					}
					res := runFCTasks(t, pb, dir, extra, "--tags", tags)
					sshdRan := false
					for name := range res.ran {
						if strings.HasSuffix(name, "sshd -t") || strings.HasSuffix(name, "sshd -t after removing the drop-in") {
							sshdRan = true
						}
					}
					_, reloaded := res.applied(t)
					failures := strings.Join(res.failures, "\n")
					if res.rc == 0 || !strings.Contains(failures, tc.wantMsg) || reloaded || sshdRan != tc.wantSshd {
						t.Errorf("rc=%d reloaded=%v sshd -t ran=%v failures=%v; want a failed run mentioning %q, no reload, sshd -t ran=%v",
							res.rc, reloaded, sshdRan, res.failures, tc.wantMsg, tc.wantSshd)
					}
					if tc.wantSshd && !strings.Contains(failures, "Bad configuration option") {
						t.Errorf("failures=%v; want sshd's own message", res.failures)
					}
					got, err := os.ReadFile(dropin)
					switch {
					case tc.before == "" && err == nil:
						t.Errorf("the failed run left a drop-in:\n%s", got)
					case tc.before != "" && string(got) != tc.before:
						t.Errorf("drop-in after the failed run = %q (err %v), want the previous %q", got, err, tc.before)
					}
				})
			}
		}
	}
}

// TestRegression_ForceCommandRetriesAfterAFailedSshdCheck: a run after one
// whose `sshd -t` failed validates and loads the drop-in. On 8635152 the
// second run found the drop-in already written and did neither.
func TestRegression_ForceCommandRetriesAfterAFailedSshdCheck(t *testing.T) {
	for _, pb := range fcPlaybooks {
		for _, tags := range []string{pb.rowTag, pb.groupTag} {
			t.Run(pb.name+"/"+tags, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				dropin := fcHost(t, pb, dir)
				first := runFCTasks(t, pb, dir, map[string]any{"fc_sshd_cmd": fcSshdFails}, "--tags", tags)
				if first.rc == 0 {
					t.Fatalf("first run passed with a failing sshd -t: %v", first.failures)
				}
				second := runFCTasks(t, pb, dir, nil, "--tags", tags)
				validated, reloaded := second.applied(t)
				if second.rc != 0 || !fcExists(dropin) || !validated || !reloaded {
					t.Errorf("rerun: rc=%d failures=%v drop-in=%v sshd -t=%v reload=%v; want the drop-in validated and loaded",
						second.rc, second.failures, fcExists(dropin), validated, reloaded)
				}
			})
		}
	}
}
