package spec

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// rewritePaths returns v with every string's occurrences of each key of
// paths replaced by its value.
func rewritePaths(v any, paths map[string]string) any {
	switch x := v.(type) {
	case string:
		for from, to := range paths {
			x = strings.ReplaceAll(x, from, to)
		}
		return x
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = rewritePaths(item, paths)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, item := range x {
			out[k] = rewritePaths(item, paths)
		}
		return out
	}
	return v
}

// runRealmTasks runs the named tasks of freeipa-realm-replacement-apply.yml
// (pre_tasks, then tasks), in playbook order, on localhost: module
// arguments and loop items have the real paths replaced by paths' values,
// owner/group and notify are dropped. vars adds to the default new-server
// variables. It returns the exit code and, per task, whether it changed
// anything and its failure message.
func runRealmTasks(t *testing.T, names []string, paths map[string]string, vars map[string]any) (int, map[string]bool, []string) {
	t.Helper()
	return runRealmTasksArgs(t, names, paths, vars, nil, nil)
}

// runRealmTasksEnv is runRealmTasks with env added to ansible-playbook's
// environment, which the tasks' commands inherit.
func runRealmTasksEnv(t *testing.T, names []string, paths map[string]string, vars map[string]any, env []string) (int, map[string]bool, []string) {
	t.Helper()
	return runRealmTasksArgs(t, names, paths, vars, env, nil)
}

// runRealmTasksArgs is runRealmTasksEnv with args added to the
// ansible-playbook command line, such as --check --diff.
func runRealmTasksArgs(t *testing.T, names []string, paths map[string]string, vars map[string]any, env, args []string) (int, map[string]bool, []string) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	doc, _ := loadYAML(t, "../../playbooks/apply/freeipa-realm-replacement-apply.yml").([]any)
	play := doc[0].(map[string]any)
	var keep []any
	collect := func(task map[string]any, _ []string) {
		name, _ := task["name"].(string)
		if !slices.Contains(names, name) {
			return
		}
		c := map[string]any{}
		for k, v := range task {
			switch k {
			case "notify", "tags", "no_log":
			case "loop":
				c[k] = rewritePaths(v, paths)
			default:
				if args, ok := v.(map[string]any); ok && strings.HasPrefix(k, "ansible.builtin.") {
					a := map[string]any{}
					for ak, av := range args {
						if ak != "owner" && ak != "group" {
							a[ak] = rewritePaths(av, paths)
						}
					}
					c[k] = a
				} else if s, ok := v.(string); ok && strings.HasPrefix(k, "ansible.builtin.") {
					c[k] = rewritePaths(s, paths) // free-form shell/command
				} else {
					c[k] = v
				}
			}
		}
		keep = append(keep, c)
	}
	walkTaskTree(play["pre_tasks"], nil, collect)
	walkTaskTree(play["tasks"], nil, collect)
	if len(keep) != len(names) {
		t.Fatalf("found %d of the %d tasks %q", len(keep), len(names), names)
	}
	allVars := map[string]any{
		"freeipa_realm_replacement_new_server_fqdn": "ipa1.new.example.test",
		"freeipa_realm_replacement_new_server_ip":   "192.0.2.10",
	}
	for k, v := range vars {
		allVars[k] = v
	}
	body, err := yaml.Marshal([]map[string]any{{
		"hosts": "localhost", "connection": "local", "gather_facts": false, "become": false,
		"vars": allVars, "tasks": keep,
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "realm.yml")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", append([]string{"-i", "localhost,", path}, args...)...)
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1",
		"ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_INVENTORY_UNPARSED_WARNING=False")
	cmd.Env = append(cmd.Env, env...)
	out, runErr := cmd.Output()
	rc := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if runErr != nil {
		t.Fatalf("ansible-playbook did not run: %v", runErr)
	}
	var cb struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]struct {
					Changed bool   `json:"changed"`
					Failed  bool   `json:"failed"`
					Msg     string `json:"msg"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &cb); err != nil {
		t.Fatalf("parse JSON callback output: %v\n%s", err, out)
	}
	changed := map[string]bool{}
	var failures []string
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			for _, h := range task.Hosts {
				changed[task.Task.Name] = changed[task.Task.Name] || h.Changed
				if h.Failed {
					failures = append(failures, task.Task.Name+": "+h.Msg)
				}
			}
		}
	}
	return rc, changed, failures
}
