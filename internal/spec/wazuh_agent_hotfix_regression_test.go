package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	if !strings.Contains(remove.Hosts, "pilot_hotfix_skewed") || !strings.Contains(remove.Hosts, "pilot_hotfix_mode") {
		t.Errorf("the remove play must target only the hosts the observe play collected, and only in apply mode: %q", remove.Hosts)
	}
	text := readHotfixFile(t, hotfixPlaybookPath)
	observeText := text[:strings.Index(text, "- name: Wazuh agent skew hotfix — remove")]
	for _, mutating := range []string{"quiesce", "remove --family", "writer-claim", "writer-release", "manage_agents -r", "apt-get", "dnf remove"} {
		if strings.Contains(observeText, mutating) {
			t.Errorf("the read-only play contains %q", mutating)
		}
	}
	if !strings.Contains(observeText, "group_by") {
		t.Error("the observe play no longer collects the skewed hosts for the remove play")
	}
}

// The complete stage gate of AGENTS.md section 4.3 sits in the mutating play, tagged always, and
// the manager the run deregisters from is held to the same stage as the agent host.
func TestWazuhAgentHotfixStageGate(t *testing.T) {
	remove := hotfixPlays(t)[1]
	var gates []string
	for _, task := range remove.PreTasks {
		if _, ok := task["ansible.builtin.assert"]; !ok {
			continue
		}
		tags, _ := task["tags"].([]any)
		if len(tags) != 1 || tags[0] != "always" {
			t.Errorf("gate %q is not tagged always: a --tags run would skip it", task["name"])
		}
		gates = append(gates, task["name"].(string))
	}
	joined := strings.Join(gates, "\n")
	for _, want := range []string{"explicit confirm", "environment group", "manager this run deregisters", "staging attestation"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing stage gate: %s\n%s", want, joined)
		}
	}
	text := readHotfixFile(t, hotfixPlaybookPath)
	if !strings.Contains(text, "hostvars[hotfix_manager_host].group_names") {
		t.Error("the manager's environment group is not checked against the stage")
	}
}

// Mutation and rollback semantics: no rollback by design, but the writer is always released and a
// failure is never turned into success.
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
	// the manager registration is removed before the package, so an interruption never loses
	// the enrollment record (the only copy of the agent ID is in client.keys, removed last)
	text := readHotfixFile(t, hotfixPlaybookPath)
	order := []string{"writer-claim", "quiesce", "wazuh-agent-hotfix-deregister.yml", "remove --family", "verify --family", "writer-release"}
	prev := -1
	for _, step := range order {
		idx := strings.Index(text, step)
		if idx < 0 || idx < prev {
			t.Errorf("step %q is missing or out of order (claim, quiesce, deregister, remove, verify, release)", step)
		}
		prev = idx
	}
}

// The deregistration only acts on an ID whose recorded name matches, and treats "already gone"
// as success so a rerun after an interruption finishes.
func TestWazuhAgentHotfixDeregisterIsExactAndIdempotent(t *testing.T) {
	text := readHotfixFile(t, hotfixTasksPath)
	for _, want := range []string{
		"selectattr('0', 'equalto', hotfix_state.registration.id)",
		"(hotfix_registry_match[0][1] | lower) == (hotfix_state.registration.name | lower)",
		"'does not exist' not in",
		"hotfix_registry_match | length == 1",
		"set -o pipefail",
		"executable: /bin/bash",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("deregister tasks lack %q", want)
		}
	}
	if regexp.MustCompile(`(?i)(hostname|inventory_hostname)\s*(in|==)`).MatchString(text) {
		t.Error("the deregistration must never match by hostname; only by the recorded ID and name")
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
