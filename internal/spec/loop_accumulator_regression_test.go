package spec

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRegression_LoopAccumulatorsAreInitializedOrGuarded is a repo-wide lint
// over playbooks/**. A fact built up in a loop with
// `x: "{{ (x | default([])) + [item] }}"` stays undefined when the loop has
// no items, so any later bare read of x fails with "'x' is undefined".
// internal-endpoint-apply.yml's internal_endpoint_normalized did exactly
// that for a manifest with `endpoints: []`: the decommission verify query
// read it without a default (2026-09-25). Each such accumulator must be
// set to an empty value before the loop, or every task that reads it bare
// must be guarded by a `when:` that reads it with a default, or loop over
// the same list as the accumulator (then it runs only when the
// accumulator was set, as in snmp-exporter-apply.yml).
func TestRegression_LoopAccumulatorsAreInitializedOrGuarded(t *testing.T) {
	accumulators := 0
	for _, path := range playbookFiles(t) {
		problems, n := unguardedLoopAccumulatorReads(loadYAML(t, path))
		accumulators += n
		for _, p := range problems {
			t.Errorf("%s: %s", strings.TrimPrefix(path, "../../"), p)
		}
	}
	// playbooks/** has a handful of loop accumulators; none found means
	// the detection broke.
	if accumulators == 0 {
		t.Fatal("no loop accumulators found; the detection is broken")
	}
}

func TestUnguardedLoopAccumulatorReads(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"bare read of an uninitialized accumulator (the internal-endpoint bug)", `
- hosts: all
  pre_tasks:
    - set_fact: {acc: "{{ (acc | default([])) + [item] }}"}
      loop: "{{ things | default([]) }}"
  tasks:
    - set_fact: {first: "{{ acc | first }}"}
`, 1},
		{"initialized before the loop", `
- hosts: all
  pre_tasks:
    - ansible.builtin.set_fact: {acc: []}
    - ansible.builtin.set_fact: {acc: "{{ (acc | default([])) + [item] }}"}
      loop: "{{ things }}"
  tasks:
    - ansible.builtin.debug: {msg: "{{ acc | first }}"}
`, 0},
		{"bare read guarded by a when with a default (freeipa-nfs-client's nfs_client_matches)", `
- hosts: all
  tasks:
    - set_fact: {acc: "{{ (acc | default([])) + [item] }}"}
      loop: "{{ things }}"
    - set_fact: {first: "{{ acc[0] }}"}
      when: (acc | default([])) | length > 0
`, 0},
		{"reader loops over the same list (snmp-exporter's snmp_module_contents)", `
- hosts: all
  tasks:
    - set_fact: {acc: "{{ (acc | default({})) | combine({item.key: 1}) }}"}
      loop: "{{ mods | dict2items }}"
    - assert: {that: ["acc[item.key] == 1"]}
      loop: "{{ mods | dict2items }}"
`, 0},
		{"every read has a default", `
- hosts: all
  tasks:
    - set_fact: {acc: "{{ (acc | default({})) | combine({item: 1}) }}"}
      loop: "{{ things }}"
    - debug: {msg: "{{ acc | default({}) }}"}
`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			got, n := unguardedLoopAccumulatorReads(doc)
			if n == 0 {
				t.Fatal("accumulator not detected")
			}
			if len(got) != tc.want {
				t.Fatalf("got %d problems %v, want %d", len(got), got, tc.want)
			}
		})
	}
}

var accumulatorValue = regexp.MustCompile(`^\s*\{\{\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\|\s*default\(`)

// unguardedLoopAccumulatorReads returns one message per task in doc that
// reads a loop accumulator without a default while the accumulator is never
// initialized and the task's `when:` does not check it with a default, and
// the number of accumulators found.
func unguardedLoopAccumulatorReads(doc any) ([]string, int) {
	plays, _ := doc.([]any)
	var tasks []map[string]any
	collect := func(list any) {
		walkTaskTree(list, nil, func(task map[string]any, _ []string) { tasks = append(tasks, task) })
	}
	if len(plays) > 0 {
		if _, isPlay := plays[0].(map[string]any)["hosts"]; !isPlay {
			collect(plays) // a task file
		}
	}
	for _, p := range plays {
		play, _ := p.(map[string]any)
		if _, ok := play["hosts"]; !ok {
			continue
		}
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
			collect(play[section])
		}
	}

	setFactArgs := func(task map[string]any) map[string]any {
		for _, key := range []string{"ansible.builtin.set_fact", "set_fact"} {
			if args, ok := task[key].(map[string]any); ok {
				return args
			}
		}
		return nil
	}
	accumulators := map[string]map[string]any{} // var -> accumulating task
	initialized := map[string]bool{}
	for _, task := range tasks {
		args := setFactArgs(task)
		for name, value := range args {
			switch v := value.(type) {
			case string:
				if m := accumulatorValue.FindStringSubmatch(v); m != nil && m[1] == name && hasLoop(task) {
					accumulators[name] = task
				}
				if s := strings.ReplaceAll(v, " ", ""); s == "{{[]}}" || s == "{{{}}}" {
					initialized[name] = true
				}
			case []any:
				if len(v) == 0 {
					initialized[name] = true
				}
			case map[string]any:
				if len(v) == 0 {
					initialized[name] = true
				}
			}
		}
	}

	var out []string
	for name, accTask := range accumulators {
		if initialized[name] {
			continue
		}
		bare := regexp.MustCompile(`\b` + name + `\b(\s*\|\s*default)?`)
		guard := regexp.MustCompile(`\b` + name + `\s*\|\s*default`)
		for _, task := range tasks {
			if fmt.Sprint(task) == fmt.Sprint(accTask) {
				continue
			}
			body := map[string]any{}
			for k, v := range task {
				if k != "when" && k != "name" {
					body[k] = v
				}
			}
			text, err := yaml.Marshal(body)
			if err != nil {
				continue
			}
			readsBare := false
			for _, m := range bare.FindAllStringSubmatchIndex(string(text), -1) {
				rest := string(text)[m[1]:]
				if m[2] < 0 && !strings.HasPrefix(strings.TrimLeft(rest, " "), ":") {
					readsBare = true
					break
				}
			}
			if !readsBare || guard.MatchString(fmt.Sprint(task["when"])) {
				continue
			}
			if loop, ok := task["loop"]; ok && fmt.Sprint(loop) == fmt.Sprint(accTask["loop"]) {
				continue
			}
			taskName, _ := task["name"].(string)
			out = append(out, fmt.Sprintf("task %q reads loop accumulator %s without a default, but %s is never initialized before its loop (an empty loop leaves it undefined)", taskName, name, name))
		}
	}
	return out, len(accumulators)
}

func hasLoop(task map[string]any) bool {
	for k := range task {
		if k == "loop" || strings.HasPrefix(k, "with_") {
			return true
		}
	}
	return false
}
