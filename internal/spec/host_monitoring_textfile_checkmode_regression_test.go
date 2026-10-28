package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #76: site.yml runs host-monitoring-apply.yml and then
// detection-engine-apply.yml in one ansible-playbook call. Under --check,
// host-monitoring's Step 9b creates nothing, so on a fresh host
// detection-engine's always-tagged gate on the textfile collector directory
// failed every full-site preview (topology test L3, `pilot deploy`'s
// default preview). Step 9b now records that it previewed creating the
// directory, and the consumers' gates accept that record in check mode only.

const (
	textfileHostMonitoringApply = "../../playbooks/apply/host-monitoring-apply.yml"
	textfileBlockName           = "Node_exporter install + systemd service"
	textfileStep9bName          = "Step 9b: Ensure the node_exporter textfile collector directory exists"
	textfileSetterName          = "Step 9b: Record that this --check run only previewed the textfile directory"
	textfileStatName            = "Gate: host-monitoring textfile collector directory exists on this host"
	textfileAssertName          = "Gate: assert host-monitoring's textfile directory is present and a directory"
	textfilePreviewedFact       = "host_monitoring_textfile_dir_previewed"
)

// textfileConsumers are the apply playbooks that refuse to run without
// host-monitoring's textfile collector directory on the same host.
var textfileConsumers = []struct{ component, playbook string }{
	{"detection-engine", "../../playbooks/apply/detection-engine-apply.yml"},
	{"agent-controller", "../../playbooks/apply/agent-controller-apply.yml"},
}

func textfileLoadPlays(t *testing.T, path string) []map[string]any {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(src, &plays); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if len(plays) == 0 {
		t.Fatalf("%s has no plays", path)
	}
	return plays
}

func textfileTaskList(v any) []map[string]any {
	items, _ := v.([]any)
	var out []map[string]any
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// textfileStrings returns a tags/when value as a list of strings.
func textfileStrings(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return out
	default:
		return []string{fmt.Sprint(x)}
	}
}

// textfileHostMonitoring returns host-monitoring's play, its install block,
// Step 9b and the setter that follows it in that block.
func textfileHostMonitoring(t *testing.T) (play, block, step9b, setter map[string]any) {
	t.Helper()
	play = textfileLoadPlays(t, textfileHostMonitoringApply)[0]
	for _, task := range textfileTaskList(play["tasks"]) {
		if task["name"] == textfileBlockName {
			block = task
		}
	}
	if block == nil {
		t.Fatalf("host-monitoring-apply.yml has no %q block", textfileBlockName)
	}
	inner := textfileTaskList(block["block"])
	for i, task := range inner {
		if task["name"] != textfileStep9bName {
			continue
		}
		step9b = task
		if i+1 < len(inner) && inner[i+1]["name"] == textfileSetterName {
			setter = inner[i+1]
		}
	}
	if step9b == nil {
		t.Fatalf("block %q has no %q", textfileBlockName, textfileStep9bName)
	}
	return play, block, step9b, setter
}

// textfileConsumerGate returns the consumer's play and its stat and assert
// pre_tasks on the textfile directory.
func textfileConsumerGate(t *testing.T, playbook string) (play, stat, assert map[string]any) {
	t.Helper()
	play = textfileLoadPlays(t, playbook)[0]
	for _, task := range textfileTaskList(play["pre_tasks"]) {
		switch task["name"] {
		case textfileStatName:
			if stat != nil {
				t.Fatalf("%s has two %q pre_tasks", playbook, textfileStatName)
			}
			stat = task
		case textfileAssertName:
			if assert != nil {
				t.Fatalf("%s has two %q pre_tasks", playbook, textfileAssertName)
			}
			assert = task
		}
	}
	if stat == nil || assert == nil {
		t.Fatalf("%s: missing the textfile directory gate (stat %v, assert %v)", playbook, stat != nil, assert != nil)
	}
	return play, stat, assert
}

// textfileSiteImports returns site.yml's import_playbook entries in order.
func textfileSiteImports(t *testing.T) []map[string]any {
	t.Helper()
	return textfileLoadPlays(t, "../../playbooks/site.yml")
}

func textfileSiteImportIndex(imports []map[string]any, component string) int {
	for i, imp := range imports {
		if imp["import_playbook"] == "apply/"+component+"-apply.yml" {
			return i
		}
	}
	return -1
}

// textfileSiteTags returns the tags site.yml imports component with, or
// just the component name for a playbook site.yml does not import.
func textfileSiteTags(t *testing.T, component string) []string {
	t.Helper()
	imports := textfileSiteImports(t)
	if i := textfileSiteImportIndex(imports, component); i >= 0 {
		return textfileStrings(imports[i]["tags"])
	}
	return []string{component}
}

var textfileSpaces = regexp.MustCompile(`\s+`)

// TestRegression_HostMonitoringTextfileCheckModeStructure locks the shape
// of the fix: Step 9b registers its result and the next task in the same
// block records a check-mode-only preview fact with Step 9b's tags; each
// consumer gate is always-tagged, stats host-monitoring's default directory
// and accepts the fact only in check mode; site.yml runs host-monitoring
// first.
func TestRegression_HostMonitoringTextfileCheckModeStructure(t *testing.T) {
	play, _, step9b, setter := textfileHostMonitoring(t)
	if setter == nil {
		t.Fatalf("%q is not directly followed by %q in the same block", textfileStep9bName, textfileSetterName)
	}
	vars, _ := play["vars"].(map[string]any)
	dir, _ := vars["node_exporter_textfile_dir"].(string)
	if dir == "" {
		t.Fatal("host-monitoring-apply.yml play vars no longer define node_exporter_textfile_dir")
	}

	if step9b["register"] != "node_exporter_textfile_dir_result" {
		t.Errorf("Step 9b register = %v, want node_exporter_textfile_dir_result", step9b["register"])
	}
	if _, ok := step9b["check_mode"]; ok {
		t.Error("Step 9b must not override check_mode: --check must not create the directory")
	}
	if !reflect.DeepEqual(textfileStrings(setter["tags"]), textfileStrings(step9b["tags"])) {
		t.Errorf("setter tags %v != Step 9b tags %v: the record must run whenever Step 9b does",
			textfileStrings(setter["tags"]), textfileStrings(step9b["tags"]))
	}
	args, _ := setter["ansible.builtin.set_fact"].(map[string]any)
	want := map[string]any{textfilePreviewedFact: "{{ node_exporter_textfile_dir }}"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("setter set_fact = %v, want exactly %v (in particular not cacheable: the record must not outlive the run)", args, want)
	}
	when := textfileStrings(setter["when"])
	for _, cond := range []string{"ansible_check_mode", "node_exporter_textfile_dir_result is changed"} {
		found := false
		for _, w := range when {
			found = found || strings.TrimSpace(w) == cond
		}
		if !found {
			t.Errorf("setter when %v lacks %q", when, cond)
		}
	}

	for _, c := range textfileConsumers {
		_, stat, assert := textfileConsumerGate(t, c.playbook)
		for _, task := range []map[string]any{stat, assert} {
			if tags := textfileStrings(task["tags"]); !reflect.DeepEqual(tags, []string{"always"}) {
				t.Errorf("%s %q tags = %v, want [always]", c.component, task["name"], tags)
			}
		}
		statArgs, _ := stat["ansible.builtin.stat"].(map[string]any)
		if statArgs["path"] != dir {
			t.Errorf("%s stats %v, host-monitoring creates %q by default", c.component, statArgs["path"], dir)
		}
		assertArgs, _ := assert["ansible.builtin.assert"].(map[string]any)
		that := textfileSpaces.ReplaceAllString(strings.Join(textfileStrings(assertArgs["that"]), " and "), " ")
		reg, _ := stat["register"].(string)
		tie := fmt.Sprintf("ansible_check_mode and not %s.stat.get('exists', false) and (%s | default('')) == '%s'", reg, textfilePreviewedFact, dir)
		if !strings.Contains(that, tie) {
			t.Errorf("%s gate must accept a missing directory only in check mode with the preview record:\n that: %s\n want clause: %s", c.component, that, tie)
		}
	}

	imports := textfileSiteImports(t)
	hm := textfileSiteImportIndex(imports, "host-monitoring")
	if hm < 0 {
		t.Fatal("site.yml no longer imports host-monitoring-apply.yml")
	}
	for _, c := range textfileConsumers {
		if i := textfileSiteImportIndex(imports, c.component); i >= 0 && i < hm {
			t.Errorf("site.yml imports %s (#%d) before host-monitoring (#%d)", c.component, i, hm)
		}
	}
	if textfileSiteImportIndex(imports, "detection-engine") < 0 {
		t.Error("site.yml no longer imports detection-engine-apply.yml; issue #76 is about that pair")
	}
}

// textfilePlays builds the two plays of one run: host-monitoring's real
// Step 9b and the setter after it (if any; the structure test requires it)
// inside its block's real `when`, then the consumer's real stat and assert
// with the directory rewritten to dir. Each play has its real hosts pattern
// and its site.yml import tags. stripOwner drops Step 9b's owner/group so a
// real run can create dir unprivileged.
func textfilePlays(t *testing.T, component, playbook, dir string, withHostMonitoring, stripOwner bool) []map[string]any {
	t.Helper()
	hmPlay, block, step9b, setter := textfileHostMonitoring(t)
	consumerPlay, stat, assert := textfileConsumerGate(t, playbook)
	defaultDir := hmPlay["vars"].(map[string]any)["node_exporter_textfile_dir"].(string)
	if stripOwner {
		// step9b is freshly parsed for this call; editing it is local.
		args := step9b["ansible.builtin.file"].(map[string]any)
		delete(args, "owner")
		delete(args, "group")
	}
	blockTasks := []map[string]any{step9b}
	if setter != nil {
		blockTasks = append(blockTasks, setter)
	}

	// Rewrite the consumer's literal path everywhere in both tasks (stat
	// path, check-mode comparison, message).
	if statArgs, _ := stat["ansible.builtin.stat"].(map[string]any); statArgs["path"] != defaultDir {
		t.Fatalf("%s gate stats %v, not host-monitoring's %s", component, statArgs["path"], defaultDir)
	}
	gate, err := yaml.Marshal([]map[string]any{stat, assert})
	if err != nil {
		t.Fatal(err)
	}
	var rewritten []map[string]any
	if err := yaml.Unmarshal([]byte(strings.ReplaceAll(string(gate), defaultDir, dir)), &rewritten); err != nil {
		t.Fatal(err)
	}

	var plays []map[string]any
	if withHostMonitoring {
		plays = append(plays, map[string]any{
			"name":         "host-monitoring-apply.yml Step 9b",
			"hosts":        hmPlay["hosts"],
			"gather_facts": false,
			"become":       false,
			"tags":         textfileSiteTags(t, "host-monitoring"),
			"vars":         map[string]any{"node_exporter_textfile_dir": dir, "node_exporter_port_occupied_by_other": false},
			"tasks": []map[string]any{{
				"name":  block["name"],
				"when":  block["when"],
				"block": blockTasks,
			}},
		})
	}
	plays = append(plays, map[string]any{
		"name":         component + " textfile gate",
		"hosts":        consumerPlay["hosts"],
		"gather_facts": false,
		"become":       false,
		"tags":         textfileSiteTags(t, component),
		"pre_tasks":    rewritten,
		"tasks": []map[string]any{{
			"ansible.builtin.debug": map[string]any{"msg": "GATE-PASSED previewed={{ " + textfilePreviewedFact + " | default('unset') }}"},
		}},
	})
	return plays
}

// textfileInventory puts localhost in the consumers' groups and, when
// inHostMonitoring, in host-monitoring's.
func textfileInventory(inHostMonitoring bool) string {
	inv := `all:
  hosts:
    localhost:
      ansible_connection: local
      ansible_python_interpreter: "{{ ansible_playbook_python }}"
  children:
    detection-engine: {hosts: {localhost: {}}}
    agent-controller: {hosts: {localhost: {}}}
`
	if inHostMonitoring {
		inv += "    host-monitoring: {hosts: {localhost: {}}}\n"
	}
	return inv
}

// TestRegression_HostMonitoringTextfileCheckModeRuns runs host-monitoring's
// real Step 9b and setter and each consumer's real gate with the local
// ansible-playbook. A --check run of both on a fresh host must pass the gate
// without creating anything; every other way of reaching the gate without
// the directory — host outside host-monitoring, --tags selecting only the
// consumer, the consumer alone, Step 9b's block skipped, a different
// directory previewed, or any real run — must still fail it.
func TestRegression_HostMonitoringTextfileCheckModeRuns(t *testing.T) {
	for _, consumer := range textfileConsumers {
		// --tags <component> selects the consumer's play and none of
		// host-monitoring's tasks.
		onlyConsumer := consumer.component
		hasTag := func(tags []string) bool {
			for _, tag := range tags {
				if tag == onlyConsumer {
					return true
				}
			}
			return false
		}
		if !hasTag(textfileSiteTags(t, consumer.component)) || hasTag(textfileSiteTags(t, "host-monitoring")) {
			t.Fatalf("--tags %s must select %s and not host-monitoring", onlyConsumer, consumer.component)
		}
		for _, c := range []struct {
			name             string
			check            bool
			inHostMonitoring bool
			withHM           bool
			stripOwner       bool
			preCreate        bool
			extra            []string
			pass             bool
		}{
			{name: "check: same run on a fresh host", check: true, inHostMonitoring: true, withHM: true, pass: true},
			{name: "check: directory already exists", check: true, inHostMonitoring: true, withHM: true, preCreate: true, pass: true},
			{name: "check: host not in host-monitoring", check: true, withHM: true},
			{name: "check: --tags selects only the consumer", check: true, inHostMonitoring: true, withHM: true, extra: []string{"--tags", onlyConsumer}},
			{name: "check: consumer alone", check: true, inHostMonitoring: true},
			{name: "check: Step 9b block skipped (port served by another exporter)", check: true, inHostMonitoring: true, withHM: true,
				extra: []string{"-e", `{"node_exporter_port_occupied_by_other": true}`}},
			{name: "check: a different directory was previewed", check: true, inHostMonitoring: true, withHM: true,
				extra: []string{"-e", "node_exporter_textfile_dir=OTHER"}},
			{name: "real: consumer alone without the directory, record forced", inHostMonitoring: true,
				extra: []string{"-e", textfilePreviewedFact + "=DIR"}},
			{name: "real: host not in host-monitoring, record forced", withHM: true,
				extra: []string{"-e", textfilePreviewedFact + "=DIR"}},
			{name: "real: --tags selects only the consumer, record forced", inHostMonitoring: true, withHM: true,
				extra: []string{"--tags", onlyConsumer, "-e", textfilePreviewedFact + "=DIR"}},
			{name: "real: directory exists", inHostMonitoring: true, preCreate: true, pass: true},
			{name: "real: same run creates the directory", inHostMonitoring: true, withHM: true, stripOwner: true, pass: true},
		} {
			// Sequential on purpose: load makes ansible-core 2.19.2's
			// results-thread race (see localPlayCrashWatch) more likely.
			t.Run(consumer.component+"/"+c.name, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "textfile")
				if c.preCreate {
					if err := os.Mkdir(dir, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				var extra []string
				for _, e := range c.extra {
					e = strings.ReplaceAll(e, "OTHER", dir+"-other")
					extra = append(extra, strings.ReplaceAll(e, "DIR", dir))
				}
				if c.check {
					extra = append(extra, "--check")
				}
				plays := textfilePlays(t, consumer.component, consumer.playbook, dir, c.withHM, c.stripOwner)
				out, ok := runLocalPlays(t, textfileInventory(c.inHostMonitoring), plays, extra...)
				passed := strings.Contains(out, "GATE-PASSED")
				refused := strings.Contains(out, dir+" does not exist.")
				switch {
				case c.pass && (!ok || !passed):
					t.Fatalf("gate refused (ansible-playbook ok=%v):\n%s", ok, out)
				case !c.pass && (ok || passed || !refused):
					t.Fatalf("gate did not refuse with its own message (ansible-playbook ok=%v, passed=%v):\n%s", ok, passed, out)
				}
				if c.check && !c.preCreate {
					if _, err := os.Stat(dir); !os.IsNotExist(err) {
						t.Errorf("--check created %s (err=%v)", dir, err)
					}
				}
				if !c.check && c.pass {
					if !strings.Contains(out, "GATE-PASSED previewed=unset") {
						t.Errorf("a real run recorded %s:\n%s", textfilePreviewedFact, out)
					}
					if info, err := os.Stat(dir); err != nil || !info.IsDir() {
						t.Errorf("%s is not a directory after the real run: %v", dir, err)
					}
				}
			})
		}
	}
}
