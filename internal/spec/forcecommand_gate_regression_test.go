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
// or loading it. These tests lock the tags and run the playbooks' own
// ForceCommand tasks on localhost.

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

func fcTags(task map[string]any) []string {
	var tags []string
	raw, _ := task["tags"].([]any)
	for _, tag := range raw {
		tags = append(tags, tag.(string))
	}
	return tags
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
// rollback.
func TestRegression_ForceCommandInstallFollowsItsChecks(t *testing.T) {
	for _, pb := range fcPlaybooks {
		t.Run(pb.name, func(t *testing.T) {
			_, tasks := fcPlay(t, pb)
			var install []string
			gates, applied := 0, 0
			for _, task := range tasks {
				name := fcName(task)
				if isFCInstall(name) {
					install = fcTags(task)
				}
			}
			if !slices.Contains(install, pb.rowTag) {
				t.Fatalf("install task tags = %v, want %s", install, pb.rowTag)
			}
			seenInstall := false
			for _, task := range tasks {
				name := fcName(task)
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
				case isFCApply(name):
					applied++
				default:
					continue
				}
				if missing := missingFCTags(fcTags(task), install); len(missing) > 0 {
					t.Errorf("%q lacks %v, which select the drop-in install", name, missing)
				}
			}
			if gates < 6 || applied != 2 {
				t.Errorf("found %d ForceCommand gate tasks and %d sshd -t/reload tasks, want at least 6 and 2", gates, applied)
			}
		})
	}
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

// runFCTasks runs pb's ForceCommand gate, install, sshd -t, reload and
// rollback tasks on localhost with dir standing in for /etc/ssh,
// /usr/local/libexec and /usr/bin. curl, getent and sshd run the commands
// in vars fc_health_cmd, fc_getent_cmd and fc_sshd_cmd; the systemd reload
// becomes a debug task; owner/group are dropped and the gate's root-owner
// check expects the test's user.
func runFCTasks(t *testing.T, pb fcPlaybook, dir string, extra map[string]any, args ...string) fcRun {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	playVars, tasks := fcPlay(t, pb)
	var keep []map[string]any
	for _, task := range tasks {
		name := fcName(task)
		if !strings.HasPrefix(name, "ForceCommand gate: ") && !strings.Contains(name, "sshd ForceCommand drop-in") &&
			!strings.Contains(name, "sshd -t") && !strings.Contains(name, "reload sshd") {
			continue
		}
		c := map[string]any{}
		for k, v := range task {
			c[k] = v
		}
		for _, mod := range []string{"ansible.builtin.copy", "ansible.builtin.file"} {
			if args, ok := c[mod].(map[string]any); ok {
				a := map[string]any{}
				for k, v := range args {
					if k != "owner" && k != "group" {
						a[k] = v
					}
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
		keep = append(keep, c)
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
		"fc_health_cmd": []any{"printf", "%s", `{"status":"ok"}`},
		"fc_getent_cmd": []any{"printf", "%s", "role-pilot-portal-user:*:1000:"},
		"fc_sshd_cmd":   []any{"true"},
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

// TestRegression_ForceCommandRollbackIsNeverBlocked: disabling ForceCommand
// removes the drop-in even when the service is down, the wrapper is gone
// and the group does not resolve.
func TestRegression_ForceCommandRollbackIsNeverBlocked(t *testing.T) {
	for _, pb := range fcPlaybooks {
		t.Run(pb.name, func(t *testing.T) {
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
			}, "--tags", pb.groupTag)
			if res.rc != 0 || fcExists(dropin) {
				t.Errorf("rollback: rc=%d failures=%v drop-in left=%v", res.rc, res.failures, fcExists(dropin))
			}
			for name := range res.ran {
				if strings.HasPrefix(name, "ForceCommand gate: ") {
					t.Errorf("%q ran while disabling ForceCommand", name)
				}
			}
		})
	}
}
