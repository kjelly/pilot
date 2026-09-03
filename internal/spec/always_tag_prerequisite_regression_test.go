package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_AlwaysTaggedTasksHaveAllPrerequisitesAlways is a repo-wide
// lint over every playbooks/apply/*.yml. It generalizes the hazard fixed in
// 2abb6fd (prometheus-apply.yml's ext-target compiler pipeline): a
// site-wide deploy can pass Ansible a synthetic --tags list even when the
// operator left --tags empty, whenever a required dependency expands
// --limit (effectiveDeploymentTagScopes / effectiveDeploymentTags in
// cmd/pilot/cmd/deploy.go). Ansible always runs an `always`-tagged task
// regardless of --tags, but silently SKIPS any other task the selected
// tags don't cover. So if task T is tagged `always` and reads a
// set_fact/register variable that an earlier task U in the same play sets,
// U must be tagged `always` too — otherwise a --tags selection that
// excludes U's tags still runs T, with U's output missing or stale.
//
// This is a static, per-file, per-play data-flow check: for every variable
// name it tracks the most recent task (in source order, across
// pre_tasks/tasks/post_tasks and recursing through block/rescue/always,
// which inherit their parent's tags) that set it via set_fact/register, and
// flags any `always`-tagged task that reads a variable whose most recent
// setter was NOT `always`-tagged. It cannot see across playbook/role
// boundaries or through include_tasks — only hazards visible within one
// file's own task list, which is exactly the shape 2abb6fd's bug had.
// (2abb6fd's own fix lived entirely in pre_tasks — an earlier version of
// this lint that only walked `tasks:` silently missed it; two more real
// instances of the same class, in dcgm-exporter-apply.yml and
// host-monitoring-apply.yml, turned up and were fixed once pre_tasks was
// covered too.)
func TestRegression_AlwaysTaggedTasksHaveAllPrerequisitesAlways(t *testing.T) {
	files, err := filepath.Glob("../../playbooks/apply/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no playbooks/apply/*.yml files found")
	}
	sort.Strings(files)
	for _, path := range files {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			tasks, err := parsePlaybookTasks(raw)
			if err != nil {
				t.Fatalf("parse tasks: %v", err)
			}
			for _, violation := range findAlwaysTagPrerequisiteViolations(tasks) {
				t.Error(violation)
			}
		})
	}
}

type playbookTask struct {
	Name     string
	Tags     map[string]bool
	SetsVars []string
	Node     *yaml.Node // this task's own mapping node (block/rescue/always children excluded when read-scanning)
	Line     int
}

// parsePlaybookTasks flattens every task across path's plays into source
// order, recursing into block/rescue/always. A block/rescue/always
// wrapper's own tags are inherited (unioned) by every task nested inside
// it, matching real Ansible tag-inheritance semantics.
func parsePlaybookTasks(raw []byte) ([]playbookTask, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var tasks []playbookTask
	var walkPlays func(n *yaml.Node)
	walkPlays = func(n *yaml.Node) {
		if n == nil {
			return
		}
		switch n.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, c := range n.Content {
				walkPlays(c)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				switch k.Value {
				case "tasks", "pre_tasks", "post_tasks":
					if v.Kind == yaml.SequenceNode {
						walkTaskList(v, nil, &tasks)
						continue
					}
				}
				// Recurse in case this mapping wraps a play in another
				// layer — harmless no-op when there's no nested task list.
				walkPlays(v)
			}
		}
	}
	walkPlays(&doc)
	return tasks, nil
}

func walkTaskList(seq *yaml.Node, inherited map[string]bool, out *[]playbookTask) {
	for _, item := range seq.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		own := map[string]bool{}
		var name string
		var blockSeq, rescueSeq, alwaysSeq *yaml.Node
		setsVars := map[string]bool{}
		for i := 0; i+1 < len(item.Content); i += 2 {
			k, v := item.Content[i], item.Content[i+1]
			switch k.Value {
			case "name":
				name = v.Value
			case "tags":
				collectTagValues(v, own)
			case "block":
				blockSeq = v
			case "rescue":
				rescueSeq = v
			case "always":
				alwaysSeq = v
			case "set_fact", "ansible.builtin.set_fact":
				collectMappingKeys(v, setsVars)
			case "register":
				if v.Value != "" {
					setsVars[v.Value] = true
				}
			}
		}
		effective := make(map[string]bool, len(inherited)+len(own))
		for tag := range inherited {
			effective[tag] = true
		}
		for tag := range own {
			effective[tag] = true
		}
		vars := make([]string, 0, len(setsVars))
		for v := range setsVars {
			vars = append(vars, v)
		}
		sort.Strings(vars)
		*out = append(*out, playbookTask{
			Name:     name,
			Tags:     effective,
			SetsVars: vars,
			Node:     item,
			Line:     item.Line,
		})
		if blockSeq != nil {
			walkTaskList(blockSeq, effective, out)
		}
		if rescueSeq != nil {
			walkTaskList(rescueSeq, effective, out)
		}
		if alwaysSeq != nil {
			walkTaskList(alwaysSeq, effective, out)
		}
	}
}

func collectTagValues(n *yaml.Node, out map[string]bool) {
	switch n.Kind {
	case yaml.ScalarNode:
		out[n.Value] = true
	case yaml.SequenceNode:
		for _, c := range n.Content {
			collectTagValues(c, out)
		}
	}
}

func collectMappingKeys(n *yaml.Node, out map[string]bool) {
	if n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		out[n.Content[i].Value] = true
	}
}

// taskOwnBodyReferencesVar reports whether task's own body (module
// arguments, when/loop/vars — anything except nested block/rescue/always
// children, which are separate tasks scanned independently) mentions
// varName as a whole word. Comments are never part of a yaml.Node scalar
// Value, so they can't cause a false positive.
func taskOwnBodyReferencesVar(item *yaml.Node, varName string) bool {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(varName) + `\b`)
	var found bool
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if found || n == nil {
			return
		}
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				key := n.Content[i]
				if key.Value == "block" || key.Value == "rescue" || key.Value == "always" {
					continue
				}
				walk(n.Content[i+1])
				if found {
					return
				}
			}
			return
		}
		if n.Kind == yaml.ScalarNode {
			if re.MatchString(n.Value) {
				found = true
			}
			return
		}
		for _, c := range n.Content {
			walk(c)
			if found {
				return
			}
		}
	}
	walk(item)
	return found
}

type varSetter struct {
	TaskName string
	Always   bool
}

// findAlwaysTagPrerequisiteViolations walks tasks in source order,
// tracking each variable's most recent setter, and flags an
// `always`-tagged task that reads a variable whose most recent setter is
// not itself `always`. A task that reads a variable it is about to
// overwrite in its own set_fact (a self-accumulating pattern, e.g.
// `x: "{{ x | default([]) + [...] }}"`) is checked against whatever set it
// the previous time — exactly the hazard in question, not a false
// positive.
func findAlwaysTagPrerequisiteViolations(tasks []playbookTask) []string {
	lastSetter := map[string]varSetter{}
	var violations []string
	for _, task := range tasks {
		if task.Tags["always"] {
			knownVars := make([]string, 0, len(lastSetter))
			for v := range lastSetter {
				knownVars = append(knownVars, v)
			}
			sort.Strings(knownVars)
			for _, varName := range knownVars {
				setter := lastSetter[varName]
				if setter.Always {
					continue
				}
				if taskOwnBodyReferencesVar(task.Node, varName) {
					violations = append(violations, fmt.Sprintf(
						"line %d: task %q is tagged always and references %q, but %q (its most recent setter) is not tagged always — a --tags selection that excludes %q's tags still runs this task with %q missing or stale",
						task.Line, task.Name, varName, setter.TaskName, setter.TaskName, varName))
				}
			}
		}
		for _, v := range task.SetsVars {
			lastSetter[v] = varSetter{TaskName: task.Name, Always: task.Tags["always"]}
		}
	}
	return violations
}
