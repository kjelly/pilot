package spec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const (
	hotfixSpecPath     = "../../docs/verification/wazuh-fim-agent-skew-hotfix.md"
	hotfixPlaybookPath = "../../playbooks/apply/wazuh-fim-agent-skew-hotfix.yml"
	hotfixTasksPath    = "../../playbooks/apply/tasks/wazuh-agent-hotfix-deregister.yml"
	hotfixScriptPath   = "../../playbooks/apply/files/wazuh-agent-hotfix.py"
	wazuhTxPath        = "../../playbooks/apply/files/wazuh-transaction.py"
)

// TestWazuhAgentHotfixPythonControls runs the helper script's unit controls: the only comparison
// of "agent newer than manager", the removal order, purge-not-remove, and the fail-closed
// refusals, each with a passing twin.
func TestWazuhAgentHotfixPythonControls(t *testing.T) {
	// Deliberately not runWazuhHarness: these controls need only python3 (no Ansible, no
	// Python 3.11 requirement), so they run wherever the Go tests do. They must still prove
	// they executed: a count of tests run, no skips.
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 is required for the hotfix helper's controls: %v", err)
	}
	cmd := exec.Command(python, "-B", "-I", "testdata/wazuh_agent_hotfix_test.py")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wazuh-agent-hotfix.py controls failed: %v\n%s", err, output)
	}
	ran := regexp.MustCompile(`(?m)^Ran ([0-9]+) tests?`).FindSubmatch(output)
	if ran == nil || string(ran[1]) == "0" {
		t.Fatalf("no unittest summary, so nothing proves the controls ran:\n%s", output)
	}
	if regexp.MustCompile(`(?m)^OK \(.*skipped=`).Match(output) {
		t.Fatalf("the controls skipped tests; every control must execute:\n%s", output)
	}
}

// withoutYAMLComments drops whole-line comments, which mention the scripts without calling them.
func withoutYAMLComments(text string) string {
	var keep []string
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}

func readHotfixFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func pyConst(t *testing.T, source, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^[ ]*` + regexp.QuoteMeta(name) + ` = (.+)$`).FindStringSubmatch(source)
	if m == nil {
		t.Fatalf("no constant %s", name)
	}
	return strings.TrimSpace(m[1])
}

// The helper deliberately does not import wazuh-transaction.py (a durable transaction that is not
// modified), so every fact it duplicates is locked equal here (AGENTS.md section 5.7). Break any
// one of them in either file and this fails.
func TestWazuhAgentHotfixConstantsMatchTheTransactionCoordinator(t *testing.T) {
	hot := readHotfixFile(t, hotfixScriptPath)
	tx := readHotfixFile(t, wazuhTxPath)
	for _, name := range []string{"ROOT", "PREF", "LOCKS", "BEGIN", "END", "DPKG_ABSENT", "RPM_ABSENT"} {
		hotValue := pyConst(t, hot, name)
		switch name {
		case "DPKG_ABSENT", "RPM_ABSENT":
			// the coordinator spells these inline in Agent.installed(); compare the literal text
			literal := strings.Trim(strings.TrimPrefix(hotValue, "r"), "'\"")
			if !strings.Contains(tx, literal) {
				t.Errorf("%s = %q is not the answer wazuh-transaction.py Agent.installed() recognises", name, literal)
			}
		case "PREF", "LOCKS", "ROOT":
			// the coordinator spells these Path('...') or '...'; compare the path itself
			bare := func(v string) string {
				return strings.Trim(strings.TrimSuffix(strings.TrimPrefix(v, "Path("), ")"), "'\"")
			}
			if bare(hotValue) != bare(pyConst(t, tx, name)) {
				t.Errorf("%s differs: hotfix %s, coordinator %s", name, hotValue, pyConst(t, tx, name))
			}
		default:
			if hotValue != pyConst(t, tx, name) {
				t.Errorf("%s differs: hotfix %s, coordinator %s", name, hotValue, pyConst(t, tx, name))
			}
		}
	}
	// The files pilot writes for the guard, in the exact shape the coordinator verifies.
	for _, snippet := range []string{
		`Package: wazuh-agent\nPin: version 4\.14\.(?:0|[1-9][0-9]*)-[1-9][0-9]*\nPin-Priority: 1000\n\n`,
		`Package: wazuh-agent\nPin: version \*\nPin-Priority: -1\n`,
		`wazuh-agent-0:4\.14\.(?:0|[1-9][0-9]*)-[1-9][0-9]*\.x86_64`,
	} {
		if !strings.Contains(hot, snippet) || !strings.Contains(tx, snippet) {
			t.Errorf("the guard format %q is not identical in both files", snippet)
		}
	}
	// The writer markers the coordinator creates: writer-active.json and <kind>-active.json.
	for _, marker := range []string{"writer-active.json", "agent-active.json", "central-active.json"} {
		if !strings.Contains(hot, "'"+marker+"'") {
			t.Errorf("the hotfix does not check the %s marker", marker)
		}
	}
	if !strings.Contains(tx, "'writer-active.json'") || !strings.Contains(tx, "(kind + '-active.json')") {
		t.Error("the coordinator no longer names its markers the way the hotfix checks for them")
	}
	// The manager/agent release grammar.
	if pyConst(t, hot, "MANAGER_RELEASE") != pyConst(t, tx, "VERSION") {
		t.Error("the hotfix's manager release grammar differs from the coordinator's VERSION")
	}
	// The who-data endpoint, the audit plugin config the agent writes and the enrollment file each live in
	// more than one file (the helper, audit-whodata.py, the coordinator, wazuh-fim-apply.yml); the helper's
	// copies must be the same paths, or its notion of "orphaned plugin" or "enrolled" drifts from the
	// playbooks that create them.
	bare := func(v string) string {
		return strings.Trim(strings.TrimSuffix(strings.TrimPrefix(v, "Path("), ")"), "'\"")
	}
	capture := func(source, pattern, what string) string {
		m := regexp.MustCompile(pattern).FindStringSubmatch(source)
		if m == nil {
			t.Fatalf("cannot find %s", what)
		}
		return m[1]
	}
	endpoint := bare(pyConst(t, hot, "AUDIT_ENDPOINT"))
	whodata := readHotfixFile(t, "../../playbooks/apply/files/audit-whodata.py")
	for label, other := range map[string]string{
		"audit-whodata.py ENDPOINT":               bare(pyConst(t, whodata, "ENDPOINT")),
		"wazuh-transaction.py Central.endpoint()": capture(tx, `def endpoint\(\): return Path\('([^']+)'\)`, "the coordinator's endpoint()"),
	} {
		if other != endpoint {
			t.Errorf("AUDIT_ENDPOINT %s differs from %s %s", endpoint, label, other)
		}
	}
	if got, want := bare(pyConst(t, hot, "AUDIT_PLUGIN")), capture(tx, `def plugin\(\): return Path\('([^']+)'\)`, "the coordinator's plugin()"); got != want {
		t.Errorf("AUDIT_PLUGIN %s differs from wazuh-transaction.py plugin() %s", got, want)
	}
	// and spec C8 (and C5, for client.keys) name the same paths the helper acts on
	spec, err := Parse(hotfixSpecPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range spec.Rows {
		switch row.ID {
		case "C8":
			if !strings.Contains(row.Command, strings.TrimPrefix(endpoint, "/var/")) {
				t.Errorf("spec C8 does not look for the endpoint %s the helper retires: %s", endpoint, row.Command)
			}
		case "C5":
			if !strings.Contains(row.Command, bare(pyConst(t, hot, "CLIENT_KEYS"))) {
				t.Errorf("spec C5 does not check the client.keys path the helper removes: %s", row.Command)
			}
		}
	}
	fim := readHotfixFile(t, "../../playbooks/apply/wazuh-fim-apply.yml")
	if got, want := bare(pyConst(t, hot, "CLIENT_KEYS")), capture(fim, `(?m)^\s+wazuh_client_keys: (\S+)`, "wazuh-fim-apply.yml wazuh_client_keys"); got != want {
		t.Errorf("CLIENT_KEYS %s differs from wazuh-fim-apply.yml wazuh_client_keys %s", got, want)
	}
}

// Every action the playbook invokes on either script must exist there.
func TestWazuhAgentHotfixPlaybookCallsOnlyRealActions(t *testing.T) {
	playbook := withoutYAMLComments(readHotfixFile(t, hotfixPlaybookPath))
	hot := readHotfixFile(t, hotfixScriptPath)
	tx := readHotfixFile(t, wazuhTxPath)
	own := regexp.MustCompile(`files/wazuh-agent-hotfix\.py (\S+)`).FindAllStringSubmatch(playbook, -1)
	if len(own) != 4 {
		t.Fatalf("the playbook calls the helper %d times, want inspect/quiesce/remove/verify = 4", len(own))
	}
	choices := regexp.MustCompile(`choices=\[([^\]]*)\]`).FindStringSubmatch(hot)[1]
	for _, m := range own {
		if !strings.Contains(choices, "'"+m[1]+"'") {
			t.Errorf("helper action %q does not exist", m[1])
		}
	}
	txChoices := regexp.MustCompile(`(?s)add_argument\('action', choices=\[(.*?)\]\)`).FindStringSubmatch(tx)[1]
	for _, m := range regexp.MustCompile(`files/wazuh-transaction\.py (\S+)`).FindAllStringSubmatch(playbook, -1) {
		if !strings.Contains(txChoices, "'"+m[1]+"'") {
			t.Errorf("coordinator action %q does not exist", m[1])
		}
	}
}

type hotfixPlay struct {
	Name           string           `yaml:"name"`
	Hosts          string           `yaml:"hosts"`
	AnyErrorsFatal bool             `yaml:"any_errors_fatal"`
	Serial         int              `yaml:"serial"`
	Vars           map[string]any   `yaml:"vars"`
	PreTasks       []map[string]any `yaml:"pre_tasks"`
	Tasks          []map[string]any `yaml:"tasks"`
}

func hotfixPlays(t *testing.T) []hotfixPlay {
	t.Helper()
	var plays []hotfixPlay
	if err := yaml.Unmarshal([]byte(readHotfixFile(t, hotfixPlaybookPath)), &plays); err != nil {
		t.Fatal(err)
	}
	if len(plays) != 2 {
		t.Fatalf("plays = %d, want observe + remove", len(plays))
	}
	return plays
}

// taskTags are the tags a task declares itself.
func taskTags(task map[string]any) []string {
	var out []string
	tags, _ := task["tags"].([]any)
	for _, tag := range tags {
		out = append(out, tag.(string))
	}
	return out
}

// The whole-run fail-closed guarantee lives in the structure: the read-only play stops the entire
// run on its first error, and the mutating play sees only hosts that play judged, one at a time,
// stopping at the first failure.
func TestWazuhAgentHotfixPlaybookStructureGivesFailClosed(t *testing.T) {
	plays := hotfixPlays(t)
	observe, remove := plays[0], plays[1]
	if !observe.AnyErrorsFatal {
		t.Error("the observe play must be any_errors_fatal so one unjudgeable host stops the whole run before Play B")
	}
	if !remove.AnyErrorsFatal || remove.Serial != 1 {
		t.Errorf("the remove play must be serial 1 and any_errors_fatal (got serial=%d fatal=%v)", remove.Serial, remove.AnyErrorsFatal)
	}
	if !strings.Contains(remove.Hosts, "pilot_hotfix_actionable") || !strings.Contains(remove.Hosts, "pilot_hotfix_mode") {
		t.Errorf("the remove play must target only the hosts the observe play collected, and only in apply mode: %q", remove.Hosts)
	}
	var observeText strings.Builder
	for _, task := range observe.PreTasks {
		observeText.WriteString(taskText(t, task))
	}
	for _, task := range observe.Tasks {
		observeText.WriteString(taskText(t, task))
	}
	for _, mutating := range []string{"quiesce", "remove --family", "writer-claim", "writer-release", "manage_agents -r", "apt-get", "dnf remove", "wazuh-agent-hotfix-deregister"} {
		if strings.Contains(observeText.String(), mutating) {
			t.Errorf("the read-only play contains %q", mutating)
		}
	}
	if !strings.Contains(observeText.String(), "key: pilot_hotfix_actionable") {
		t.Error("the observe play no longer collects the actionable hosts for the remove play")
	}
}

// Every refusal that does not need a change first is made in Play A, tagged always, evaluated only in apply
// mode and only for the hosts that run would change (the observation must be able to plan a mixed-stage
// inventory); Play B keeps the same stage gates as defence in depth. The behaviour is proved by
// wazuh_agent_hotfix_playbook_test.go; this locks the shape so an edit that moves a gate back is seen here.
func TestWazuhAgentHotfixStageGate(t *testing.T) {
	plays := hotfixPlays(t)
	gatesOf := func(tasks []map[string]any, name string) (gates []string, byName map[string]map[string]any) {
		byName = map[string]map[string]any{}
		for _, task := range tasks {
			if _, ok := task["ansible.builtin.assert"]; !ok {
				continue
			}
			if tags := taskTags(task); len(tags) != 1 || tags[0] != "always" {
				t.Errorf("%s gate %q is not tagged always: a --tags run would skip it", name, task["name"])
			}
			gates = append(gates, task["name"].(string))
			byName[task["name"].(string)] = task
		}
		return gates, byName
	}
	wantStage := []string{"explicit confirm", "environment group", "manager this run", "staging attestation"}
	playBGates, _ := gatesOf(plays[1].PreTasks, "Play B")
	joinedB := strings.Join(playBGates, "\n")
	for _, want := range wantStage {
		if !strings.Contains(joinedB, want) {
			t.Errorf("Play B lost its defence-in-depth gate: %s\n%s", want, joinedB)
		}
	}
	playAGates, byName := gatesOf(plays[0].Tasks, "Play A")
	joinedA := strings.Join(playAGates, "\n")
	for _, want := range append(append([]string{}, wantStage...), "in the plan the operator confirmed", "pilot_hotfix_mode is apply or observe") {
		if !strings.Contains(joinedA, want) {
			t.Errorf("Play A (before any change) lacks the gate: %s\n%s", want, joinedA)
		}
	}
	for name, task := range byName {
		if !strings.HasPrefix(name, "Gate: staging") && !strings.Contains(name, "environment group") && !strings.Contains(name, "manager this run") &&
			!strings.Contains(name, "attestation") && !strings.Contains(name, "plan the operator confirmed") {
			continue
		}
		when := fmt.Sprint(task["when"])
		if !strings.Contains(when, "hotfix_apply_mode") || !strings.Contains(when, "hotfix_actionable") {
			t.Errorf("Play A gate %q must be evaluated only in apply mode and only for the hosts this run would change: when = %s", name, when)
		}
	}
	text := readHotfixFile(t, hotfixPlaybookPath)
	if strings.Count(text, "hostvars[hotfix_manager_host].group_names") < 6 {
		t.Error("the manager's environment group is not checked against the stage in both plays")
	}
	for _, task := range plays[0].Tasks {
		if task["name"] == "Check the manager's registry against this host's recorded enrollment (read-only; refuses before any change)" {
			return
		}
	}
	t.Error("Play A no longer checks the manager registry before any change")
}

// Resumability by order: the steps that make a host unselectable by a rerun come last. Play B's block runs the
// writer claim, quiesce, the deregistration (which re-checks the registry), the single remove action, the
// verification and the outcome report in that order, then releases the writer. And the tags follow
// AGENTS.md section 4.4's reverse direction: every step that must precede a mutation carries the tags of every
// mutation after it, so a --tags run never reaches one without the steps guarding it.
func TestWazuhAgentHotfixBlockReleasesTheWriterAndKeepsFailures(t *testing.T) {
	remove := hotfixPlays(t)[1]
	var block map[string]any
	for _, task := range remove.Tasks {
		if _, ok := task["block"]; ok {
			block = task
		}
	}
	if block == nil {
		t.Fatal("no block")
	}
	rescue, _ := block["rescue"].([]any)
	always, _ := block["always"].([]any)
	if len(rescue) == 0 || len(always) == 0 {
		t.Fatalf("rescue=%d always=%d", len(rescue), len(always))
	}
	last, _ := rescue[len(rescue)-1].(map[string]any)
	if _, ok := last["ansible.builtin.fail"]; !ok {
		t.Error("the rescue must end in fail: it must never turn a failed hotfix into a success")
	}
	for _, item := range rescue {
		tags, _ := item.(map[string]any)["tags"].([]any)
		if len(tags) == 0 || tags[0] != "always" {
			t.Errorf("rescue task %v must be tagged always (a --tags run filters rescue tasks too)", item.(map[string]any)["name"])
		}
	}
	release, _ := always[0].(map[string]any)
	if !strings.Contains(release["name"].(string), "Release") || release["when"] == nil {
		t.Error("the always section must release the writer, only when this play claimed it")
	}
	// the order of the steps: claim, quiesce, deregister, remove, verify
	steps := []struct{ label, marker string }{
		{"claim", "writer-claim"}, {"quiesce", "wazuh-agent-hotfix.py quiesce"}, {"deregister", "wazuh-agent-hotfix-deregister.yml"},
		{"remove", "wazuh-agent-hotfix.py remove"}, {"verify", "wazuh-agent-hotfix.py verify"},
	}
	tasks, _ := block["block"].([]any)
	position := map[string]int{}
	tagsOf := map[string][]string{}
	for i, item := range tasks {
		task := item.(map[string]any)
		text := taskText(t, task)
		for _, step := range steps {
			if strings.Contains(text, step.marker) {
				if _, dup := position[step.label]; dup {
					t.Errorf("step %s appears twice", step.label)
				}
				position[step.label] = i
				tagsOf[step.label] = taskTags(task)
			}
		}
	}
	prev := -1
	for _, step := range steps {
		idx, ok := position[step.label]
		if !ok || idx < prev {
			t.Errorf("step %q is missing or out of order (claim, quiesce, deregister, remove, verify)", step.label)
		}
		prev = idx
	}
	// the reverse-direction tag rule: a mutation's tags are carried by every step before it
	mutations := []string{"claim", "quiesce", "deregister", "remove"}
	for i, before := range mutations {
		for _, after := range mutations[i+1:] {
			for _, tag := range tagsOf[after] {
				if !slices.Contains(tagsOf[before], tag) {
					t.Errorf("step %s (tags %v) runs before %s (tags %v) but lacks tag %s: --tags %s would reach the later mutation without it",
						before, tagsOf[before], after, tagsOf[after], tag, tag)
				}
			}
		}
	}
	for _, own := range []struct{ step, tag string }{{"quiesce", "C2"}, {"deregister", "C6"}, {"claim", "C7"}} {
		if !slices.Contains(tagsOf[own.step], own.tag) {
			t.Errorf("step %s lost its own row tag %s: %v", own.step, own.tag, tagsOf[own.step])
		}
	}
	for _, tag := range []string{"C1", "C3", "C4", "C5", "C8"} {
		if !slices.Contains(tagsOf["remove"], tag) {
			t.Errorf("the remove step lost row tag %s: %v", tag, tagsOf["remove"])
		}
	}
}

// The registry check refuses a recorded enrollment the manager contradicts (another name under the ID, or the
// name under another ID) and reads case-insensitively; the deregistration only acts on an ID the check found
// exactly once, and treats "already gone" as success so a rerun after an interruption finishes. The behaviour
// is proved in wazuh_agent_hotfix_playbook_test.go; this locks the expressions so an edit is seen here.
func TestWazuhAgentHotfixDeregisterIsExactAndIdempotent(t *testing.T) {
	check := readHotfixFile(t, "../../playbooks/apply/tasks/wazuh-agent-hotfix-registry-check.yml")
	for _, want := range []string{
		"selectattr('0', 'equalto', hotfix_state.registration.id)",
		"selectattr('1', 'equalto', hotfix_state.registration.name | lower)",
		"rejectattr('0', 'equalto', hotfix_state.registration.id)",
		"hotfix_registry_by_id[0][1] == (hotfix_state.registration.name | lower)",
		"hotfix_registry_elsewhere | length == 0",
		"hotfix_registry_listing.stdout | lower",
		"check_mode: false",
	} {
		if !strings.Contains(check, want) {
			t.Errorf("registry check lacks %q", want)
		}
	}
	if regexp.MustCompile(`(?m)^\s+(ansible\.builtin\.)?(shell|command|script):.*manage_agents -r`).MatchString(check) {
		t.Error("the registry check must be read-only; the deregistration lives in the deregister file")
	}
	text := readHotfixFile(t, hotfixTasksPath)
	for _, want := range []string{
		"file: wazuh-agent-hotfix-registry-check.yml",
		"'does not exist' not in",
		"hotfix_registry_by_id | length == 1",
		"set -o pipefail",
		"executable: /bin/bash",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("deregister tasks lack %q", want)
		}
	}
	for name, body := range map[string]string{"check": check, "deregister": text} {
		if regexp.MustCompile(`(?i)(hostname|inventory_hostname)\s*(in|==)`).MatchString(body) {
			t.Errorf("the %s tasks must never match by hostname; only by the recorded ID and name", name)
		}
	}
}

// The matcher trap this spec's C6 hit (section 2, #332): when a command writes anything but a lone
// integer to the text `pilot verify --local` matches, it cannot read an rc from that text and falls back to the process rc,
// which is 0, so a missing coordinator PASSES. Every row must print exactly 0 or 1 even when
// nothing it inspects exists. C6 is strict only where a manager stack runs: with no manager it is
// vacuous (0), and with one (a fake docker below stands in for it) a missing coordinator must read 1.
func TestWazuhAgentHotfixSpecRowsPrintALoneIntegerEvenWhenToolsAreMissing(t *testing.T) {
	s, err := Parse(hotfixSpecPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Rows) != 8 {
		t.Fatalf("rows = %d, want C1..C8", len(s.Rows))
	}
	if _, err := os.Stat("/usr/local/sbin/pilot-wazuh-transaction"); err == nil {
		t.Skip("this host has the Wazuh coordinator installed; the missing-tool case cannot be observed")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\necho 0123456789ab\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(row Row, withManager bool) string {
		cmd := exec.Command("sh", "-c", row.Command)
		if withManager {
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		}
		// pilot verify --local folds stderr into the text it matches (the `not found` the shell itself
		// prints for a missing tool is what broke the original C6), so read both, as it does.
		out, runErr := cmd.CombinedOutput()
		if runErr != nil {
			t.Errorf("%s: sh exited non-zero: %v (rows must absorb their own failure into the printed integer)", row.ID, runErr)
		}
		got := strings.TrimSpace(string(out))
		if got != "0" && got != "1" {
			t.Errorf("%s printed %q; stdout must be a lone 0 or 1 so pilot verify reads the printed rc, not the shell's", row.ID, got)
		}
		return got
	}
	for i, row := range s.Rows {
		if want := "C" + string(rune('1'+i)); row.ID != want {
			t.Fatalf("row %d is %s, want %s", i, row.ID, want)
		}
		got := run(row, false)
		if row.ID == "C6" && got != "0" {
			t.Errorf("C6 printed %q on a host with no manager stack; it must be vacuous there", got)
		}
		if row.ID == "C6" {
			if withManager := run(row, true); withManager != "1" {
				t.Errorf("C6 printed %q on a host with a manager stack but no coordinator; that must FAIL the row", withManager)
			}
		}
	}
	// C8 with no `ss` at all on PATH (only sh and grep): still a lone integer, and 1 (FAIL), not the 0 a
	// missing tool used to give. TestWazuhAgentHotfixSpecC8FailsWhenSsCannotAnswer has the other ss cases.
	noSS := t.TempDir()
	for _, name := range []string{"sh", "grep"} {
		path, lookErr := exec.LookPath(name)
		if lookErr != nil {
			t.Fatal(lookErr)
		}
		if err := os.Symlink(path, filepath.Join(noSS, name)); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", "-c", s.Rows[7].Command)
	cmd.Env = []string{"PATH=" + noSS}
	out, runErr := cmd.CombinedOutput()
	if runErr != nil || strings.TrimSpace(string(out)) != "1" {
		t.Errorf("C8 on a host with no ss printed %q (err %v); it must be a lone 1", strings.TrimSpace(string(out)), runErr)
	}
}

// C8 asks whether any unix socket still listens on Wazuh's who-data endpoint, which only `ss -xl` can say. A
// host where ss is missing, or where it fails, has not said "no listener", so the row must FAIL there (print
// 1) instead of passing because grep found nothing in an empty answer. The ss outputs are the real AlmaLinux
// 9.8 `ss -xl` shapes (the helper's own control uses the same ones); every failing case has its passing twin.
func TestWazuhAgentHotfixSpecC8FailsWhenSsCannotAnswer(t *testing.T) {
	s, err := Parse(hotfixSpecPath)
	if err != nil {
		t.Fatal(err)
	}
	var row Row
	for _, r := range s.Rows {
		if r.ID == "C8" {
			row = r
		}
	}
	if row.ID == "" {
		t.Fatal("no C8 row")
	}
	tools := map[string]string{}
	for _, name := range []string{"grep", "sh"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("%s not found: %v", name, err)
		}
		tools[name] = path
	}
	const header = "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n" +
		"u_str LISTEN 0      4096               /run/systemd/private 12 * 0\n"
	const listener = "u_str LISTEN 0      1                  /var/ossec/queue/sockets/audit 41824             * 0\n"
	for _, tc := range []struct {
		name string
		ss   string // the fake ss script body; "" means no ss on PATH at all
		want string
	}{
		{"ss is missing", "", "1"},
		{"ss fails with no output", "exit 1\n", "1"},
		{"ss fails after printing a header", "printf '%s' '" + header + "'\nexit 1\n", "1"},
		{"twin: ss answers and nothing listens on the endpoint", "printf '%s' '" + header + "'\n", "0"},
		{"ss answers and the stale listener is there", "printf '%s' '" + header + listener + "'\n", "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := t.TempDir()
			for name, path := range tools {
				if err := os.Symlink(path, filepath.Join(bin, name)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.ss != "" {
				if err := os.WriteFile(filepath.Join(bin, "ss"), []byte("#!/bin/sh\n"+tc.ss), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("sh", "-c", row.Command)
			// only sh, grep and (maybe) ss on PATH: every other tool the row uses must be a shell builtin, which
			// is also what makes "ss missing" real here instead of depending on the machine running the test
			cmd.Env = []string{"PATH=" + bin}
			out, runErr := cmd.CombinedOutput()
			if runErr != nil {
				t.Errorf("sh exited non-zero: %v (the row must absorb its own failure into the printed integer)", runErr)
			}
			if got := strings.TrimSpace(string(out)); got != tc.want {
				t.Errorf("C8 printed %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWazuhAgentHotfixSpecIsLintClean(t *testing.T) {
	s, err := Parse(hotfixSpecPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range Lint(s) {
		if f.Severity == SeverityError {
			t.Errorf("lint error: %+v", f)
		}
	}
}
