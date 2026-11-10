package spec

import (
	"fmt"
	"strings"
	"testing"
)

// Issue #244 native run 19cfe69b, defects D1 and D2: playbook-level properties that no Python graph run pins
// down. Each has a negative control that feeds the same checker the pre-fix shape it must reject.
//
// D1: an ordinary wazuh-fim apply on EL installed only `audit`, so the af_wazuh plugin was `active = yes` with no
// binary, no who-data endpoint ever existed and wazuh-syscheckd fell back to real-time, yet every spec row passed.
// The apply must install the plugin package and, last among the agent-service changes, make the endpoint live.
//
// D2: the manager playbook fetched the wazuh-docker bundle for the REQUESTED version even when the active project
// (kept at the old release by a controlled upgrade) did not need it, so the first identical rerun after an upgrade
// reported changed=1.

// flatWazuhPlay returns every task of a play in document order with its ancestor blocks.
type wazuhNode struct {
	task  map[string]any
	chain []map[string]any
}

func wazuhNodes(play map[string]any) []wazuhNode {
	var out []wazuhNode
	var walk func(items []any, chain []map[string]any)
	walk = func(items []any, chain []map[string]any) {
		for _, item := range items {
			task, ok := item.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, wazuhNode{task: task, chain: chain})
			for _, section := range []string{"block", "rescue", "always"} {
				children, _ := task[section].([]any)
				walk(children, append(append([]map[string]any{}, chain...), task))
			}
		}
	}
	for _, section := range []string{"pre_tasks", "tasks"} {
		top, _ := play[section].([]any)
		walk(top, nil)
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

func wazuhWhenText(task map[string]any) string {
	return wazuhTaskText(map[string]any{"when": task["when"]})
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
	fimStep11 = "Step 11: Restart wazuh-agent if config changed or a new enrollment just happened"
	fimEnsure = "Step 11a: Ensure the who-data endpoint is live and connected (spec C11)"
	fimVerify = "Step 12: Verify the native agent release, version pin and availability (spec C10)"
	fimDNF    = "Step 4: Install audit provider, its af_unix plugin and the native versionlock prerequisite (RedHat dnf; spec C2)"
)

// checkWazuhFimWhodata reports every violated D1 property of the wazuh-fim play.
func checkWazuhFimWhodata(play map[string]any) []string {
	var problems []string
	nodes := wazuhNodes(play)

	// 1. The EL plugin package is part of the apply (spec C2).
	dnf := -1
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

	// 2. The endpoint task: present, tagged C11, reports its change, and never hides the typed refusal.
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
	if !hasAllTags(wazuhTagList(task), "C11") && !hasAllTags(wazuhTagList(chain[len(chain)-1]), "C11") {
		problems = append(problems, "the endpoint task must carry the C11 row tag")
	}
	if v, ok := task["no_log"]; ok && v != false {
		problems = append(problems, "the endpoint task hides its typed refusal with no_log")
	}
	changed := fmt.Sprint(task["changed_when"])
	if task["changed_when"] == nil || task["changed_when"] == false || !strings.Contains(changed, "changed") {
		problems = append(problems, "the endpoint task must report the repair it made (changed_when from the coordinator's `changed`)")
	}

	// 3. It is the last agent-service change: after the Step 11 restart, before the C10 verification, and only for
	// ordinary applies (a controlled version transaction owns its own audit proof and journal).
	restart, verify := wazuhIndex(nodes, fimStep11), wazuhIndex(nodes, fimVerify)
	if restart < 0 || verify < 0 {
		problems = append(problems, "the Step 11 restart or Step 12 verification task is missing")
	} else if restart >= ensure || ensure >= verify {
		problems = append(problems, "the endpoint task must come after the Step 11 agent restart and before the Step 12 verification")
	}
	guarded, outsideCheckMode := false, false
	for _, scope := range chain {
		when := wazuhWhenText(scope)
		if strings.Contains(when, "wazuh_agent_transaction_reserved") {
			guarded = true
		}
		if strings.Contains(when, "not ansible_check_mode") {
			outsideCheckMode = true
		}
	}
	if !guarded && !strings.Contains(wazuhWhenText(task), "wazuh_agent_transaction_reserved") {
		problems = append(problems, "the endpoint task must be skipped for a controlled version transaction")
	}
	if !outsideCheckMode && !strings.Contains(wazuhWhenText(task), "ansible_check_mode") {
		problems = append(problems, "the endpoint task must not run in check mode")
	}

	// 4. Its service mutation is snapshotted first and sits inside the rollback scope of the ordinary apply.
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
			"ansible.builtin.command": map[string]any{"argv": []any{"/usr/local/sbin/pilot-wazuh-transaction", "agent-whodata-ensure"}},
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
	restart := map[string]any{"name": fimStep11}
	verify := map[string]any{"name": fimVerify}
	good := func() map[string]any {
		own := map[string]any{"name": "own", "tags": []any{"C11"}, "when": "not (wazuh_agent_transaction_reserved | default(false) | bool)",
			"block": []any{save("agent-service"), save("audit-service"), ensureTask(nil)}}
		main := map[string]any{"name": "main", "when": "not ansible_check_mode",
			"block":  []any{dnf("audit", "audispd-plugins", "python3-dnf-plugin-versionlock"), restart, own},
			"rescue": []any{map[string]any{"name": "ROLLBACK"}}}
		return map[string]any{"tasks": []any{main, verify}}
	}
	if problems := checkWazuhFimWhodata(good()); len(problems) != 0 {
		t.Fatalf("a conforming play was rejected: %v", problems)
	}
	// The pre-fix shape of the play: no plugin package and no endpoint task.
	prefix := map[string]any{"tasks": []any{map[string]any{"name": "main", "when": "not ansible_check_mode",
		"block":  []any{dnf("audit", "python3-dnf-plugin-versionlock"), restart},
		"rescue": []any{map[string]any{"name": "ROLLBACK"}}}, verify}}
	if len(checkWazuhFimWhodata(prefix)) == 0 {
		t.Fatal("the pre-fix play (audit only, no endpoint task) was accepted")
	}
	edit := func(mutate func(own, main map[string]any)) map[string]any {
		play := good()
		main := play["tasks"].([]any)[0].(map[string]any)
		own := main["block"].([]any)[2].(map[string]any)
		mutate(own, main)
		return play
	}
	cases := map[string]map[string]any{
		"plugin package missing": edit(func(own, main map[string]any) {
			main["block"].([]any)[0] = dnf("audit", "python3-dnf-plugin-versionlock")
		}),
		"endpoint task before the agent restart": edit(func(own, main map[string]any) {
			blocks := main["block"].([]any)
			main["block"] = []any{blocks[0], blocks[2], blocks[1]}
		}),
		"runs during a controlled version transaction": edit(func(own, main map[string]any) { delete(own, "when") }),
		"runs in check mode":                           edit(func(own, main map[string]any) { delete(main, "when") }),
		"hides the typed refusal":                      edit(func(own, main map[string]any) { own["block"].([]any)[2].(map[string]any)["no_log"] = true }),
		"never reports its repair": edit(func(own, main map[string]any) {
			own["block"].([]any)[2].(map[string]any)["changed_when"] = false
		}),
		"no audit-service snapshot": edit(func(own, main map[string]any) {
			own["block"] = []any{save("agent-service"), ensureTask(nil)}
		}),
		"outside the rollback scope": edit(func(own, main map[string]any) { delete(main, "rescue") }),
		"loses its row tag": edit(func(own, main map[string]any) {
			delete(own, "tags")
			delete(own["block"].([]any)[2].(map[string]any), "tags")
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

const (
	mgrStat     = "Step 3: Check whether the active project already exists (spec C1-C3)"
	mgrDownload = "Step 3: Download the official wazuh-docker release bundle (spec C1-C3)"
)

// checkWazuhBundleDownload reports every violated D2 property: the download is decided from the ACTIVE project
// directory (the one a controlled upgrade keeps), by a fact whose setter carries the reader's tags.
func checkWazuhBundleDownload(play map[string]any) []string {
	var problems []string
	nodes := wazuhNodes(play)
	download, stat := wazuhIndex(nodes, mgrDownload), -1
	if download < 0 {
		return []string{"the bundle download task is missing"}
	}
	get := nodes[download].task
	when := wazuhWhenText(get)
	// The register the download reads.
	register := ""
	for i, node := range nodes {
		if module, ok := node.task["ansible.builtin.stat"].(map[string]any); ok {
			path, _ := module["path"].(string)
			if strings.Contains(path, "{{ wazuh_single_node_dir }}/docker-compose.yml") {
				stat = i
				register, _ = node.task["register"].(string)
			}
		}
	}
	if stat < 0 || register == "" {
		return append(problems, "the download is not decided from a stat of the active project's docker-compose.yml (wazuh_single_node_dir)")
	}
	if !strings.Contains(when, register+".stat.exists") || !strings.Contains(when, "not (") {
		problems = append(problems, "the download must be skipped when the active project's compose file exists (`not (<register>.stat.exists ...)`)")
	}
	if stat > download {
		problems = append(problems, "the active-project stat must run before the download")
	}
	// §4.4: the setter must carry every tag its reader runs under.
	if !hasAllTags(wazuhTagList(nodes[stat].task), wazuhTagList(get)...) {
		problems = append(problems, fmt.Sprintf("the stat (tags %v) must carry the download's tags %v, or a tag-scoped run reads an unset fact", wazuhTagList(nodes[stat].task), wazuhTagList(get)))
	}
	if strings.Contains(wazuhTaskText(nodes[stat].task), "wazuh_docker_version") {
		problems = append(problems, "the active project must not be derived from the requested version string")
	}
	return problems
}

func TestRegression_WazuhManagerBundleIsFetchedOnlyForAMissingActiveProject(t *testing.T) {
	play := loadFirstPlay(t, "wazuh-manager-apply.yml")
	if problems := checkWazuhBundleDownload(play); len(problems) > 0 {
		t.Fatalf("wazuh-manager-apply.yml: %s", strings.Join(problems, "; "))
	}
}

func TestWazuhBundleDownloadInvariantsFire(t *testing.T) {
	get := func(when any) map[string]any {
		return map[string]any{"name": mgrDownload, "tags": []any{"C1", "C2", "C3"}, "when": when, "ansible.builtin.get_url": map[string]any{"url": "x"}}
	}
	stat := func(path string, tags ...any) map[string]any {
		return map[string]any{"name": mgrStat, "tags": tags, "register": "active_project",
			"ansible.builtin.stat": map[string]any{"path": path}}
	}
	whenOK := []any{"not ansible_check_mode", "not (active_project.stat.exists | default(false))"}
	play := func(tasks ...map[string]any) map[string]any {
		var items []any
		for _, task := range tasks {
			items = append(items, task)
		}
		return map[string]any{"tasks": items}
	}
	good := play(stat("{{ wazuh_single_node_dir }}/docker-compose.yml", "C1", "C2", "C3"), get(whenOK))
	if problems := checkWazuhBundleDownload(good); len(problems) != 0 {
		t.Fatalf("a conforming play was rejected: %v", problems)
	}
	cases := map[string]map[string]any{
		// The pre-fix shape: download whenever the run is real, whatever the active project is.
		"pre-fix: unconditional download":    play(get("not ansible_check_mode")),
		"stat of a requested-version path":   play(stat("{{ wazuh_docker_root }}/wazuh-docker-{{ wazuh_docker_version }}/single-node/docker-compose.yml", "C1", "C2", "C3"), get(whenOK)),
		"download not negated":               play(stat("{{ wazuh_single_node_dir }}/docker-compose.yml", "C1", "C2", "C3"), get([]any{"not ansible_check_mode", "active_project.stat.exists"})),
		"setter lacks the reader's tags":     play(stat("{{ wazuh_single_node_dir }}/docker-compose.yml", "C1"), get(whenOK)),
		"stat after the download":            play(get(whenOK), stat("{{ wazuh_single_node_dir }}/docker-compose.yml", "C1", "C2", "C3")),
		"download decided from another fact": play(stat("{{ wazuh_single_node_dir }}/docker-compose.yml", "C1", "C2", "C3"), get([]any{"not ansible_check_mode", "not (other.stat.exists | default(false))"})),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if len(checkWazuhBundleDownload(p)) == 0 {
				t.Fatal("the violation was accepted")
			}
		})
	}
}
