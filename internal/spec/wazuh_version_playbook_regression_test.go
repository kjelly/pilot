package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #244 part A: playbook-level properties of the Wazuh version contract
// that no single Python graph run pins down. Each has a negative control in
// TestWazuhVersionPlaybookInvariantsFire, which feeds the same checker the
// shape it must reject.

func loadWazuhTaskFile(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tasks []map[string]any
	if err := yaml.Unmarshal(raw, &tasks); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return tasks
}

// flattenWazuhTasks returns every task, descending into block/rescue/always.
func flattenWazuhTasks(items []any) []map[string]any {
	var out []map[string]any
	for _, item := range items {
		task, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, task)
		for _, section := range []string{"block", "rescue", "always"} {
			children, _ := task[section].([]any)
			out = append(out, flattenWazuhTasks(children)...)
		}
	}
	return out
}

func wazuhTaskText(task map[string]any) string {
	raw, _ := json.Marshal(task)
	return string(raw)
}

func wazuhTaskTags(task map[string]any) string {
	raw, _ := json.Marshal(task["tags"])
	return string(raw)
}

// checkWazuhVersionPlaybook reports every violated property of one play.
func checkWazuhVersionPlaybook(play map[string]any, all []map[string]any, verifyTag, verifyName string) []string {
	var problems []string
	for _, task := range all {
		text := wazuhTaskText(task)
		name, _ := task["name"].(string)
		if strings.Contains(text, "wazuh-transaction") {
			// The coordinator's output is secret-free and typed; no_log would hide the
			// only explanation an operator gets for a refusal.
			if v, ok := task["no_log"]; ok && v != false {
				problems = append(problems, fmt.Sprintf("coordinator task %q hides its typed failure with no_log", name))
			}
		}
		if copyArgs, ok := task["ansible.builtin.copy"].(map[string]any); ok && copyArgs["dest"] == "/usr/local/sbin/pilot-wazuh-transaction" {
			if copyArgs["mode"] != "0700" || copyArgs["owner"] != "root" || copyArgs["group"] != "root" {
				problems = append(problems, fmt.Sprintf("coordinator copy %q must be root:root 0700", name))
			}
		}
		// Read-only observations run in check mode and never report a change.
		if script, ok := task["ansible.builtin.script"].(map[string]any); ok {
			cmd, _ := script["cmd"].(string)
			for _, readOnly := range []string{" manager-version", " agent-check ", " agent-policy-check ", " central --version"} {
				if strings.Contains(" "+strings.Join(strings.Fields(cmd), " ")+" ", readOnly) {
					if task["check_mode"] != false || task["changed_when"] != false {
						problems = append(problems, fmt.Sprintf("read-only observation %q must set check_mode: false and changed_when: false", name))
					}
				}
			}
		}
	}
	// The native verification must sit outside the block whose rescue reverts
	// configuration: a failed verification is a failed run, not a rollback.
	var verify map[string]any
	for _, task := range all {
		if task["name"] == verifyName {
			verify = task
		}
	}
	top, _ := play["tasks"].([]any)
	found := false
	for _, item := range top {
		if task, ok := item.(map[string]any); ok && task["name"] == verifyName {
			found = true
		}
	}
	switch {
	case verify == nil:
		problems = append(problems, "missing verification task "+verifyName)
	case !found:
		problems = append(problems, verifyName+" is nested in a block/rescue scope; a failed verification would trigger the configuration rollback")
	case wazuhTaskTags(verify) != fmt.Sprintf(`["%s"]`, verifyTag):
		problems = append(problems, verifyName+" must carry exactly its row tag "+verifyTag)
	}
	return problems
}

func TestRegression_WazuhVersionPlaybookInvariants(t *testing.T) {
	for _, tc := range []struct {
		playbook, verifyTag, verifyName string
		files                           []string
	}{
		{"wazuh-fim-apply.yml", "C10", "Step 12: Verify the native agent release, version pin and availability (spec C10)",
			[]string{"../../playbooks/apply/tasks/wazuh-agent-pin.yml"}},
		{"wazuh-manager-apply.yml", "C12", "Verify native releases, retained-agent compatibility and readiness (spec C12)", nil},
	} {
		t.Run(tc.playbook, func(t *testing.T) {
			play := loadFirstPlay(t, tc.playbook)
			var all []map[string]any
			for _, section := range []string{"pre_tasks", "tasks"} {
				children, _ := play[section].([]any)
				all = append(all, flattenWazuhTasks(children)...)
			}
			for _, file := range tc.files {
				all = append(all, loadWazuhTaskFile(t, file)...)
			}
			if problems := checkWazuhVersionPlaybook(play, all, tc.verifyTag, tc.verifyName); len(problems) > 0 {
				t.Fatalf("%s: %s", tc.playbook, strings.Join(problems, "; "))
			}
		})
	}
}

// Each shape below is the property's violation; the checker must reject it.
func TestWazuhVersionPlaybookInvariantsFire(t *testing.T) {
	verify := map[string]any{"name": "verify", "tags": []any{"C10"}, "ansible.builtin.command": map[string]any{"argv": []any{"/usr/local/sbin/pilot-wazuh-transaction", "agent-verify"}}}
	good := func() (map[string]any, []map[string]any) {
		play := map[string]any{"tasks": []any{map[string]any{"name": "block", "block": []any{}}, verify}}
		return play, []map[string]any{verify}
	}
	if play, all := good(); len(checkWazuhVersionPlaybook(play, all, "C10", "verify")) != 0 {
		t.Fatalf("a conforming play was rejected: %v", checkWazuhVersionPlaybook(play, all, "C10", "verify"))
	}
	cases := map[string]func() (map[string]any, []map[string]any){
		"no_log hides a refusal": func() (map[string]any, []map[string]any) {
			play, all := good()
			all = append(all, map[string]any{"name": "gate", "no_log": true, "ansible.builtin.script": map[string]any{"cmd": "files/wazuh-transaction.py agent-check --family x"}})
			return play, all
		},
		"coordinator copy is world readable": func() (map[string]any, []map[string]any) {
			play, all := good()
			all = append(all, map[string]any{"name": "copy", "ansible.builtin.copy": map[string]any{"dest": "/usr/local/sbin/pilot-wazuh-transaction", "owner": "root", "group": "root", "mode": "0755"}})
			return play, all
		},
		"observation reports changes": func() (map[string]any, []map[string]any) {
			play, all := good()
			all = append(all, map[string]any{"name": "check", "check_mode": false, "ansible.builtin.script": map[string]any{"cmd": "files/wazuh-transaction.py agent-check --family x"}})
			return play, all
		},
		"observation skipped in check mode": func() (map[string]any, []map[string]any) {
			play, all := good()
			all = append(all, map[string]any{"name": "manager", "changed_when": false, "ansible.builtin.script": map[string]any{"cmd": "files/wazuh-transaction.py manager-version"}})
			return play, all
		},
		"verification inside the rollback block": func() (map[string]any, []map[string]any) {
			play, all := good()
			play["tasks"] = []any{map[string]any{"name": "block", "block": []any{verify}, "rescue": []any{}}}
			return play, all
		},
		"verification loses its row tag": func() (map[string]any, []map[string]any) {
			play, _ := good()
			all := []map[string]any{{"name": "verify", "tags": []any{"always"}}}
			play["tasks"] = []any{all[0]}
			return play, all
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			play, all := build()
			if len(checkWazuhVersionPlaybook(play, all, "C10", "verify")) == 0 {
				t.Fatal("the violation was accepted")
			}
		})
	}
}
