package spec

import (
	"fmt"
	"strings"
	"testing"
)

// Issue #323: an ordinary wazuh-fim apply on EL installed only `audit`. The af_wazuh plugin the agent writes was
// `active = yes` but /sbin/audisp-af_unix (provided by audispd-plugins on EL) was absent and
// nothing made the running auditd load the plugin (EL's auditd refuses `systemctl restart`, minimal EL9 has no
// `service`), so no who-data endpoint ever existed, wazuh-syscheckd fell back to real-time, and every spec row still
// passed. The apply must install the plugin package on the RedHat family, and last among the agent-service changes
// make the endpoint live or fail the run. Playbook-level properties that no single Python graph run pins down, each
// with a negative control that feeds the same checker the shape it must reject.

// wazuhNode is a task together with the blocks that enclose it, outermost first, and for each of those blocks the
// section ("block", "rescue" or "always") the path to the task runs through.
type wazuhNode struct {
	task  map[string]any
	chain []map[string]any
	via   []string
}

// wazuhNodes returns every task of a play in document order with its ancestors.
func wazuhNodes(play map[string]any) []wazuhNode {
	var out []wazuhNode
	var walk func(items []any, chain []map[string]any, via []string)
	walk = func(items []any, chain []map[string]any, via []string) {
		for _, item := range items {
			task, ok := item.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, wazuhNode{task: task, chain: chain, via: via})
			for _, section := range []string{"block", "rescue", "always"} {
				children, _ := task[section].([]any)
				walk(children, append(append([]map[string]any{}, chain...), task), append(append([]string{}, via...), section))
			}
		}
	}
	for _, section := range []string{"pre_tasks", "tasks"} {
		top, _ := play[section].([]any)
		walk(top, nil, nil)
	}
	return out
}

func wazuhIndex(nodes []wazuhNode, name string) int {
	for i, node := range nodes {
		if node.task["name"] == name {
			return i
		}
	}
	return -1
}

// wazuhWhenText is the JSON of a task's own `when` (a string or a list).
func wazuhWhenText(task map[string]any) string {
	return wazuhTaskText(map[string]any{"when": task["when"]})
}

// wazuhScopeWhen is the `when` of the task and of every block that encloses it.
func wazuhScopeWhen(n wazuhNode) string {
	text := wazuhWhenText(n.task)
	for _, scope := range n.chain {
		text += wazuhWhenText(scope)
	}
	return text
}

func wazuhTagList(task map[string]any) []string {
	var out []string
	switch tags := task["tags"].(type) {
	case []any:
		for _, tag := range tags {
			out = append(out, fmt.Sprint(tag))
		}
	case string:
		out = append(out, tags)
	}
	return out
}

func hasAllTags(have []string, want ...string) bool {
	set := map[string]bool{}
	for _, tag := range have {
		set[tag] = true
	}
	for _, tag := range want {
		if !set[tag] {
			return false
		}
	}
	return true
}

const (
	fimStep11  = "Step 11: Restart wazuh-agent if config changed or a new enrollment just happened"
	fimEnsure  = "Step 11a: Ensure the who-data endpoint is live and connected (RedHat; spec C11)"
	fimInspect = "Step 11b: Inspect native agent version and enrollment after all selected operations"
	fimVerify  = "Step 12: Verify the native agent release, version pin and availability (spec C10)"
	fimDNF     = "Step 4: Install audit provider, its af_unix plugin and the native versionlock prerequisite (RedHat dnf; spec C2)"
	fimApt     = "Step 4: Install auditd (Debian apt; spec C2)"
)

// checkWazuhFimWhodata reports every violated property of the wazuh-fim play.
func checkWazuhFimWhodata(play map[string]any) []string {
	var problems []string
	nodes := wazuhNodes(play)

	// 1. The EL plugin package is part of the apply (spec C2); Debian's list is unchanged.
	dnf, apt := -1, wazuhIndex(nodes, fimApt)
	for i, node := range nodes {
		if module, ok := node.task["ansible.builtin.dnf"].(map[string]any); ok {
			text := wazuhTaskText(map[string]any{"name": module["name"]})
			if strings.Contains(text, "python3-dnf-plugin-versionlock") {
				dnf = i
				if !strings.Contains(text, `"audispd-plugins"`) || !strings.Contains(text, `"audit"`) {
					problems = append(problems, "the RedHat package task must install audit and audispd-plugins (the af_unix plugin binary)")
				}
			}
		}
	}
	if dnf < 0 {
		problems = append(problems, "no RedHat dnf task installs the audit packages")
	}
	if apt < 0 {
		problems = append(problems, "the Debian auditd install task is missing")
	} else if vars, _ := nodes[apt].task["vars"].(map[string]any); wazuhTaskText(map[string]any{"v": vars["pilot_apt_packages"]}) != `{"v":["auditd"]}` {
		problems = append(problems, "the Debian package list must stay exactly [auditd] (the fix is RedHat-family only)")
	}

	// 2. The endpoint task: present, tagged C11, reports its change, never hides the typed refusal, and passes the
	// family the action itself checks.
	ensure := -1
	for i, node := range nodes {
		if strings.Contains(wazuhTaskText(node.task), "agent-whodata-ensure") {
			ensure = i
		}
	}
	if ensure < 0 {
		return append(problems, "no task runs the coordinator's agent-whodata-ensure")
	}
	task, chain := nodes[ensure].task, nodes[ensure].chain
	if !hasAllTags(wazuhTagList(task), "C11") && (len(chain) == 0 || !hasAllTags(wazuhTagList(chain[len(chain)-1]), "C11")) {
		problems = append(problems, "the endpoint task must carry the C11 row tag")
	}
	if v, ok := task["no_log"]; ok && v != false {
		problems = append(problems, "the endpoint task hides its typed refusal with no_log")
	}
	changed := fmt.Sprint(task["changed_when"])
	if task["changed_when"] == nil || task["changed_when"] == false || !strings.Contains(changed, "changed") {
		problems = append(problems, "the endpoint task must report the repair it made (changed_when from the coordinator's `changed`)")
	}
	argv := wazuhTaskText(task)
	if !strings.Contains(argv, `"--family"`) || !strings.Contains(argv, "ansible_os_family") {
		problems = append(problems, "the endpoint task must pass --family {{ ansible_os_family }}: the action refuses every family but RedHat")
	}

	// 3. It is the last agent-service change: after the Step 11 restart, before the Step 11b inspection and the C10
	// verification. It runs for RedHat only, only for ordinary applies (a controlled version transaction owns its own
	// audit proof and journal), and never in check mode.
	restart, inspect, verify := wazuhIndex(nodes, fimStep11), wazuhIndex(nodes, fimInspect), wazuhIndex(nodes, fimVerify)
	if restart < 0 || inspect < 0 || verify < 0 {
		problems = append(problems, "the Step 11 restart, Step 11b inspection or Step 12 verification task is missing")
	} else if restart >= ensure || ensure >= inspect || ensure >= verify {
		problems = append(problems, "the endpoint task must come after the Step 11 agent restart and before the Step 11b inspection and the Step 12 verification")
	}
	when := wazuhScopeWhen(nodes[ensure])
	if !strings.Contains(when, "ansible_os_family == 'RedHat'") {
		problems = append(problems, "the endpoint task must run for the RedHat family only (the Debian family is not changed by this fix)")
	}
	if !strings.Contains(when, "wazuh_agent_transaction_reserved") {
		problems = append(problems, "the endpoint task must be skipped for a controlled version transaction")
	}
	if !strings.Contains(when, "not ansible_check_mode") {
		problems = append(problems, "the endpoint task must not run in check mode")
	}

	// 4. Its service mutation is snapshotted first, in the same block, and sits inside the rollback scope of the
	// ordinary apply.
	snap := func(resource string) bool {
		for i := 0; i < ensure; i++ {
			text := wazuhTaskText(nodes[i].task)
			if strings.Contains(text, "agent-config-save") && strings.Contains(text, resource) &&
				len(nodes[i].chain) > 0 && len(chain) > 0 && nodes[i].chain[len(nodes[i].chain)-1]["name"] == chain[len(chain)-1]["name"] {
				return true
			}
		}
		return false
	}
	for _, resource := range []string{"agent-service", "audit-service"} {
		if !snap(resource) {
			problems = append(problems, "the "+resource+" snapshot must be taken before the endpoint task in the same block")
		}
	}
	rescued := false
	for _, scope := range chain {
		if _, ok := scope["rescue"]; ok {
			rescued = true
		}
	}
	if !rescued {
		problems = append(problems, "the endpoint task must run inside the rollback scope of the ordinary apply")
	}

	// 5. The rescue never restarts, reloads or signals auditd: EL refuses a restart, and a failed apply must not
	// bounce the audit daemon under the other roles that share it.
	for _, node := range nodes {
		inRescue := false
		for _, section := range node.via {
			if section == "rescue" {
				inRescue = true
			}
		}
		text := wazuhTaskText(node.task)
		if inRescue && strings.Contains(text, "auditd") &&
			(strings.Contains(text, "restart") || strings.Contains(text, "reload") || strings.Contains(text, "HUP") || strings.Contains(text, "kill")) {
			problems = append(problems, fmt.Sprintf("rescue task %q must never restart, reload or signal auditd", node.task["name"]))
		}
	}
	return problems
}

func TestRegression_WazuhFimApplyEnsuresTheWhoDataEndpoint(t *testing.T) {
	play := loadFirstPlay(t, "wazuh-fim-apply.yml")
	if problems := checkWazuhFimWhodata(play); len(problems) > 0 {
		t.Fatalf("wazuh-fim-apply.yml: %s", strings.Join(problems, "; "))
	}
}

// TestWazuhFimWhodataInvariantsFire feeds the checker the pre-fix play and each single violation.
func TestWazuhFimWhodataInvariantsFire(t *testing.T) {
	ensureTask := func(extra map[string]any) map[string]any {
		task := map[string]any{"name": fimEnsure, "tags": []any{"C11"},
			"ansible.builtin.command": map[string]any{"argv": []any{"/usr/local/sbin/pilot-wazuh-transaction", "agent-whodata-ensure", "--family", "{{ ansible_os_family }}"}},
			"changed_when":            "wazuh_whodata_ensure.rc == 0 and ((wazuh_whodata_ensure.stdout | from_json).changed | default(false) | bool)"}
		for k, v := range extra {
			task[k] = v
		}
		return task
	}
	save := func(resource string) map[string]any {
		return map[string]any{"name": "Snapshot " + resource, "ansible.builtin.command": map[string]any{
			"argv": []any{"/usr/local/sbin/pilot-wazuh-transaction", "agent-config-save", "--resource", resource}}}
	}
	dnf := func(names ...any) map[string]any {
		return map[string]any{"name": fimDNF, "ansible.builtin.dnf": map[string]any{"name": names}}
	}
	apt := func(names ...any) map[string]any {
		return map[string]any{"name": fimApt, "vars": map[string]any{"pilot_apt_packages": names}}
	}
	restart := map[string]any{"name": fimStep11}
	inspect := map[string]any{"name": fimInspect}
	verify := map[string]any{"name": fimVerify}
	rollback := func() map[string]any {
		return map[string]any{"name": "ROLLBACK", "ansible.builtin.command": map[string]any{"argv": []any{"/usr/local/sbin/pilot-wazuh-transaction", "agent-config-restore"}}}
	}
	good := func() map[string]any {
		own := map[string]any{"name": "own", "tags": []any{"C11"},
			"when":  []any{"ansible_os_family == 'RedHat'", "not (wazuh_agent_transaction_reserved | default(false) | bool)"},
			"block": []any{save("agent-service"), save("audit-service"), ensureTask(nil)}}
		main := map[string]any{"name": "main", "when": "not ansible_check_mode",
			"block":  []any{dnf("audit", "audispd-plugins", "python3-dnf-plugin-versionlock"), restart, own, inspect},
			"rescue": []any{rollback()}}
		return map[string]any{"tasks": []any{apt("auditd"), main, verify}}
	}
	if problems := checkWazuhFimWhodata(good()); len(problems) != 0 {
		t.Fatalf("a conforming play was rejected: %v", problems)
	}
	// The pre-fix shape of the play: no plugin package and no endpoint task.
	prefix := map[string]any{"tasks": []any{apt("auditd"), map[string]any{"name": "main", "when": "not ansible_check_mode",
		"block":  []any{dnf("audit", "python3-dnf-plugin-versionlock"), restart, inspect},
		"rescue": []any{rollback()}}, verify}}
	if len(checkWazuhFimWhodata(prefix)) == 0 {
		t.Fatal("the pre-fix play (audit only, no endpoint task) was accepted")
	}
	edit := func(mutate func(own, main, play map[string]any)) map[string]any {
		play := good()
		main := play["tasks"].([]any)[1].(map[string]any)
		own := main["block"].([]any)[2].(map[string]any)
		mutate(own, main, play)
		return play
	}
	cases := map[string]map[string]any{
		"plugin package missing": edit(func(own, main, play map[string]any) {
			main["block"].([]any)[0] = dnf("audit", "python3-dnf-plugin-versionlock")
		}),
		"debian list gains the plugin package": edit(func(own, main, play map[string]any) {
			play["tasks"].([]any)[0] = apt("auditd", "audispd-plugins")
		}),
		"endpoint task before the agent restart": edit(func(own, main, play map[string]any) {
			blocks := main["block"].([]any)
			main["block"] = []any{blocks[0], blocks[2], blocks[1], blocks[3]}
		}),
		"endpoint task after the version inspection": edit(func(own, main, play map[string]any) {
			blocks := main["block"].([]any)
			main["block"] = []any{blocks[0], blocks[1], blocks[3], blocks[2]}
		}),
		"runs on every family": edit(func(own, main, play map[string]any) {
			own["when"] = []any{"not (wazuh_agent_transaction_reserved | default(false) | bool)"}
		}),
		"runs during a controlled version transaction": edit(func(own, main, play map[string]any) {
			own["when"] = []any{"ansible_os_family == 'RedHat'"}
		}),
		"runs in check mode": edit(func(own, main, play map[string]any) { delete(main, "when") }),
		"hides the typed refusal": edit(func(own, main, play map[string]any) {
			own["block"].([]any)[2].(map[string]any)["no_log"] = true
		}),
		"never reports its repair": edit(func(own, main, play map[string]any) {
			own["block"].([]any)[2].(map[string]any)["changed_when"] = false
		}),
		"does not pass the family": edit(func(own, main, play map[string]any) {
			own["block"].([]any)[2].(map[string]any)["ansible.builtin.command"] = map[string]any{
				"argv": []any{"/usr/local/sbin/pilot-wazuh-transaction", "agent-whodata-ensure"}}
		}),
		"no audit-service snapshot": edit(func(own, main, play map[string]any) {
			own["block"] = []any{save("agent-service"), ensureTask(nil)}
		}),
		"outside the rollback scope": edit(func(own, main, play map[string]any) { delete(main, "rescue") }),
		"loses its row tag": edit(func(own, main, play map[string]any) {
			delete(own, "tags")
			delete(own["block"].([]any)[2].(map[string]any), "tags")
		}),
		"the rescue restarts auditd": edit(func(own, main, play map[string]any) {
			main["rescue"] = []any{rollback(), map[string]any{"name": "ROLLBACK restart audit", "ansible.builtin.systemd": map[string]any{"name": "auditd", "state": "restarted"}}}
		}),
		"the rescue signals auditd": edit(func(own, main, play map[string]any) {
			main["rescue"] = []any{rollback(), map[string]any{"name": "ROLLBACK reload audit", "ansible.builtin.command": "pkill -HUP -x auditd"}}
		}),
	}
	for name, play := range cases {
		t.Run(name, func(t *testing.T) {
			if len(checkWazuhFimWhodata(play)) == 0 {
				t.Fatal("the violation was accepted")
			}
		})
	}
}
