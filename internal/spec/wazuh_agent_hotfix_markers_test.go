package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const hotfixMarkerFixture = "../hotfix/testdata/ansible-debug-markers.txt"

// The Go parser in internal/hotfix reads the marker lines this playbook prints through
// ansible.builtin.debug, and its fixture must be a REAL capture (AGENTS.md section 5.6), not a hand-typed
// guess that agrees with the parser. This builds that capture from the playbook's OWN debug tasks (taken
// out of the file, not retyped) over four localhost connections that carry the host variables the real
// run would have, runs real ansible-playbook, and requires the marker lines to equal the fixture's. Change
// a marker in the playbook (a new field, a reordered one) and this fails until the fixture is regenerated:
//
//	PILOT_WRITE_HOTFIX_MARKERS=1 go test -count=1 -run TestWazuhAgentHotfixMarkersAreTheRealCapture ./internal/spec/
//
// The fixture is ansible's own default-callback output of that run (ANSIBLE_NOCOLOR=1). Only whitespace at
// the ends of lines (ansible pads the PLAY RECAP rows) and the trailing blank line are dropped, so the
// committed file passes `git diff --check`; no marker line is touched.
func TestWazuhAgentHotfixMarkersAreTheRealCapture(t *testing.T) {
	python := requireHotfixAnsible(t)
	plays := hotfixPlays(t)

	// the real debug tasks, unnamed so ansible prints `TASK [ansible.builtin.debug]` like the fixture
	var debugTasks []map[string]any
	collect := func(tasks []map[string]any) {
		for _, task := range tasks {
			debug, ok := task["ansible.builtin.debug"].(map[string]any)
			if !ok {
				continue
			}
			if msg, _ := debug["msg"].(string); strings.Contains(msg, "PILOT_HOTFIX_") {
				debugTasks = append(debugTasks, map[string]any{"ansible.builtin.debug": debug})
			}
		}
	}
	collect(plays[0].Tasks)
	for _, task := range plays[1].Tasks {
		if block, ok := task["block"].([]any); ok {
			var inner []map[string]any
			for _, item := range block {
				inner = append(inner, item.(map[string]any))
			}
			collect(inner)
		}
	}
	if len(debugTasks) != 3 {
		t.Fatalf("found %d marker debug tasks in the playbook, want the manager, state and result markers", len(debugTasks))
	}
	// The result marker is only printed for hosts that went through the removal block, so it gets the
	// `when` of the host being actionable; the other two are printed for every host.
	debugTasks[2]["when"] = "hotfix_actionable | bool"

	type host struct {
		name, installed        string
		skewed, residue        bool
		registration, removing string
	}
	hosts := []host{
		{"agent-ok", "4.14.1-1", false, false, "002:agent-ok", ""},
		{"agent-new", "4.14.9-1", true, false, "003:agent-new", "removed"},
		{"agent-none", "", false, false, "", ""},
		{"agent-left", "", false, true, "", "removed"},
	}
	var inventory strings.Builder
	inventory.WriteString("all:\n  hosts:\n")
	for _, h := range hosts {
		state := map[string]any{"installed": h.installed, "registration": nil}
		if h.registration != "" {
			parts := strings.SplitN(h.registration, ":", 2)
			state["registration"] = map[string]any{"id": parts[0], "name": parts[1]}
		}
		vars := map[string]any{
			"ansible_connection": "local", "ansible_python_interpreter": python,
			"hotfix_manager_host":     "mgr-1",
			"hotfix_manager_observed": map[string]any{"stdout": `{"version": "4.14.1"}`},
			"hotfix_state":            state, "hotfix_skewed": h.skewed, "hotfix_residue": h.residue,
			"hotfix_actionable": h.skewed || h.residue, "hotfix_removed": h.removing == "removed",
		}
		data, err := yaml.Marshal(map[string]any{h.name: vars})
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			inventory.WriteString("    " + line + "\n")
		}
	}
	playbook := []map[string]any{{
		"hosts": "all", "gather_facts": false,
		"tasks": []any{debugTasks[0], debugTasks[1], debugTasks[2]},
	}}
	data, err := yaml.Marshal(playbook)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{"inventory.yml": inventory.String(), "capture.yml": string(data), "ansible.cfg": "[defaults]\nhost_key_checking = False\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("ansible-playbook", "-i", filepath.Join(dir, "inventory.yml"), filepath.Join(dir, "capture.yml"))
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+filepath.Join(dir, "ansible.cfg"), "ANSIBLE_NOCOLOR=1", "ANSIBLE_FORKS=1",
		"ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_INVENTORY_UNPARSED_WARNING=False", "ANSIBLE_HOME="+filepath.Join(dir, "home"),
		"ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "local"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("capture playbook failed: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t\r")
	}
	capture := strings.Join(lines, "\n") + "\n"
	if os.Getenv("PILOT_WRITE_HOTFIX_MARKERS") == "1" {
		if err := os.WriteFile(hotfixMarkerFixture, []byte(capture), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	markers := func(text string) []string {
		var out []string
		for _, m := range regexp.MustCompile(`"msg": "(PILOT_HOTFIX_[A-Z]+ [^"]*)"`).FindAllStringSubmatch(text, -1) {
			out = append(out, m[1])
		}
		sort.Strings(out)
		return out
	}
	fixture, err := os.ReadFile(hotfixMarkerFixture)
	if err != nil {
		t.Fatal(err)
	}
	got, want := markers(capture), markers(string(fixture))
	if len(got) == 0 || strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the playbook's markers differ from the committed capture (regenerate it, see the comment on this test)\nplaybook now prints:\n%s\n\ncommitted fixture:\n%s",
			strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if strings.HasSuffix(string(fixture), "\n\n") {
		t.Error("the committed capture ends in a blank line; git diff --check rejects that")
	}
}
