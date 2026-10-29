package spec

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRegression_LoopAccumulatorsAreResetBeforeTheirLoop is a repo-wide lint
// over playbooks/**. set_fact outlives the include and the play that set it,
// so a fact a loop builds up from its own previous value
// (`x: "{{ x | default([]) + [item] }}"`, `x | combine({...})`) starts the
// next include of the same task file, or the next play on the same host,
// from the old value. Issue #157: site.yml includes
// tasks/freeipa-server-pool.yml from dns-apply.yml and again from
// freeipa-client-apply.yml, so a host in both groups listed every replica
// twice and the duplicate-FQDN gate failed the run (AGENTS.md §4.5 point 2).
// Each such accumulator needs, earlier in the same task list (the task file,
// or the play's pre_tasks, tasks and post_tasks), a set_fact without a loop
// that sets the fact to a value that does not read it. That reset must run
// whenever the loop does: its when: conditions, its own and those of the
// blocks around it, are all conditions of the loop too, and it is tagged
// `always` or with every tag of the loop.
func TestRegression_LoopAccumulatorsAreResetBeforeTheirLoop(t *testing.T) {
	found := map[string][]string{}
	accumulators := 0
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		unreset, n := loopAccumulatorsWithoutReset(loadYAML(t, path))
		accumulators += n
		for _, u := range unreset {
			found[rel+"::"+u.fact] = append(found[rel+"::"+u.fact], u.task)
		}
	}
	for _, p := range unresetAccumulatorProblems(found, unresetLoopAccumulatorAllowlist) {
		t.Error(p)
	}
	// playbooks/** has a few dozen loop accumulators; far fewer means the
	// detection broke.
	if accumulators < 20 {
		t.Fatalf("only %d loop accumulators found; the detection is broken", accumulators)
	}
}

// unresetLoopAccumulatorAllowlist lists, as "<path>::<fact>", the loop
// accumulators without a reset that were on main when the lint was added.
// Each sits in the only play of its playbook, not in an included task file,
// and no other playbook sets the fact, so it starts from nothing today. The
// lint fails for a new one and for an entry that no longer needs to be here,
// so the list only shrinks.
var unresetLoopAccumulatorAllowlist = map[string]string{
	"playbooks/apply/freeipa-dns-apply.yml::freeipa_dns_authoritative_blocks":            "single play, run on its own (not in site.yml); latent, migrate in follow-up",
	"playbooks/apply/freeipa-dns-apply.yml::freeipa_dns_authoritative_current":           "single play, run on its own (not in site.yml); latent, migrate in follow-up",
	"playbooks/apply/freeipa-dns-apply.yml::freeipa_dns_authoritative_stale":             "single play, run on its own (not in site.yml); latent, migrate in follow-up",
	"playbooks/apply/freeipa-dns-apply.yml::freeipa_dns_record_plan":                     "single play, run on its own (not in site.yml); latent, migrate in follow-up",
	"playbooks/apply/freeipa-identity-apply.yml::canonical_group_removals":               "single play, run on its own (not in site.yml); latent, migrate in follow-up",
	"playbooks/apply/freeipa-identity-apply.yml::ipa_group_membership_removals":          "single play, run on its own (not in site.yml); latent, migrate in follow-up",
	"playbooks/apply/freeipa-identity-apply.yml::ipa_hbac_removals":                      "single play, run on its own (not in site.yml); latent, migrate in follow-up",
	"playbooks/apply/freeipa-identity-apply.yml::ipa_hostgroup_membership_removals":      "single play, run on its own (not in site.yml); latent, migrate in follow-up",
	"playbooks/apply/freeipa-identity-apply.yml::ipa_netgroup_membership_removals":       "single play, run on its own (not in site.yml); latent, migrate in follow-up",
	"playbooks/apply/freeipa-identity-apply.yml::ipa_sudo_removals":                      "single play, run on its own (not in site.yml); latent, migrate in follow-up",
	"playbooks/apply/freeipa-nfs-client-apply.yml::nfs_client_matches":                   "single play, imported once by site.yml; latent, migrate in follow-up",
	"playbooks/apply/prometheus-apply.yml::monitoring_scrape_jobs":                       "single play, imported once by site.yml; latent, migrate in follow-up",
	"playbooks/apply/prometheus-apply.yml::monitoring_snmp_scrape_jobs":                  "single play, imported once by site.yml; latent, migrate in follow-up",
	"playbooks/apply/prometheus-apply.yml::monitoring_targets_normalized":                "single play, imported once by site.yml; latent, migrate in follow-up",
	"playbooks/apply/prometheus-apply.yml::prometheus_dcgm_exporter_auto_static_configs": "single play, imported once by site.yml; latent, migrate in follow-up",
	"playbooks/apply/prometheus-apply.yml::prometheus_node_exporter_auto_static_configs": "single play, imported once by site.yml; latent, migrate in follow-up",
	"playbooks/apply/snmp-exporter-apply.yml::snmp_env_lines":                            "single play, imported once by site.yml; latent, migrate in follow-up",
	"playbooks/apply/snmp-exporter-apply.yml::snmp_module_contents":                      "single play, imported once by site.yml; latent, migrate in follow-up",
	"playbooks/apply/snmp-exporter-apply.yml::snmp_rendered_auths":                       "single play, imported once by site.yml; latent, migrate in follow-up",
	"playbooks/apply/snmp-exporter-apply.yml::snmp_rendered_modules":                     "single play, imported once by site.yml; latent, migrate in follow-up",
}

// unresetAccumulatorProblems compares the loop accumulators found without a
// reset, keyed "<path>::<fact>", with the allowlist.
func unresetAccumulatorProblems(found map[string][]string, allow map[string]string) []string {
	var problems []string
	for key, tasks := range found {
		if _, ok := allow[key]; ok {
			continue
		}
		problems = append(problems, fmt.Sprintf("%s: loop %q builds the fact from its previous value, and no set_fact earlier in the same task list resets it (without a loop, under no narrower when:, tagged `always` or with every tag of the loop); the previous include of this file, or an earlier play on the same host, leaves its value behind (AGENTS.md §4.5 point 2, issue #157)", key, tasks))
	}
	for key := range allow {
		if _, ok := found[key]; !ok {
			problems = append(problems, fmt.Sprintf("allowlist entry %q no longer matches a loop accumulator without a reset; remove it", key))
		}
	}
	sort.Strings(problems)
	return problems
}

// unresetAccumulator is a looped set_fact of fact that reads fact and has no
// reset before it.
type unresetAccumulator struct{ fact, task string }

// loopAccumulatorsWithoutReset returns the loop accumulators in doc that no
// earlier task of their task list resets, and the number of loop
// accumulators found.
func loopAccumulatorsWithoutReset(doc any) ([]unresetAccumulator, int) {
	var out []unresetAccumulator
	n := 0
	for _, list := range runOrderTaskLists(doc) {
		for i, acc := range list {
			if !hasLoop(acc.task) {
				continue
			}
			args := setFactArgs(acc.task)
			names := make([]string, 0, len(args))
			for name := range args {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if name == "cacheable" || !readsFact(args[name], name) {
					continue
				}
				n++
				if !slices.ContainsFunc(list[:i], func(prev condTask) bool { return resetsFor(prev, acc, name) }) {
					taskName, _ := acc.task["name"].(string)
					out = append(out, unresetAccumulator{fact: name, task: taskName})
				}
			}
		}
	}
	return out, n
}

// resetsFor reports whether prev sets name, without a loop, to a value that
// does not read it, whenever acc runs.
func resetsFor(prev, acc condTask, name string) bool {
	if hasLoop(prev.task) {
		return false
	}
	value, ok := setFactArgs(prev.task)[name]
	if !ok || readsFact(value, name) {
		return false
	}
	for _, cond := range prev.whens {
		if !slices.Contains(acc.whens, cond) {
			return false
		}
	}
	if slices.Contains(prev.tags, "never") && !slices.Contains(acc.tags, "never") {
		return false
	}
	if slices.Contains(prev.tags, "always") {
		return true
	}
	for _, tag := range acc.tags {
		if !slices.Contains(prev.tags, tag) {
			return false
		}
	}
	return true
}

// jinjaCodeRe matches a Jinja expression or statement.
var jinjaCodeRe = regexp.MustCompile(`(?s)\{\{(.*?)\}\}|\{%(.*?)%\}`)

// readsFact reports whether a set_fact value reads the variable name in a
// Jinja expression or statement. An attribute or a quoted key with the same
// name (hostvars[item].name, x['name']) is not a read of the variable.
func readsFact(value any, name string) bool {
	text, ok := value.(string)
	if !ok {
		body, err := yaml.Marshal(value)
		if err != nil {
			return false
		}
		text = string(body)
	}
	ref := regexp.MustCompile(`(^|[^\w.'"])` + regexp.QuoteMeta(name) + `\b`)
	for _, m := range jinjaCodeRe.FindAllStringSubmatch(text, -1) {
		if ref.MatchString(m[1] + m[2]) {
			return true
		}
	}
	return false
}

// condTask is a task with its effective tags and when: conditions, its own
// and those of the blocks and the play around it.
type condTask struct {
	task  map[string]any
	tags  []string
	whens []string
}

// rescueCondition marks a task in a rescue section: it runs only when its
// block fails.
const rescueCondition = "<rescue>"

// walkTaskTreeConds is walkTaskTree that also passes each task's effective
// when: conditions, in run order.
func walkTaskTreeConds(list any, tags, whens []string, fn func(condTask)) {
	tasks, _ := list.([]any)
	for _, item := range tasks {
		task, ok := item.(map[string]any)
		if !ok {
			continue
		}
		own := condTask{
			task:  task,
			tags:  append(slices.Clone(tags), yamlTags(task)...),
			whens: append(slices.Clone(whens), yamlWhens(task)...),
		}
		fn(own)
		walkTaskTreeConds(task["block"], own.tags, own.whens, fn)
		walkTaskTreeConds(task["rescue"], own.tags, append(slices.Clone(own.whens), rescueCondition), fn)
		walkTaskTreeConds(task["always"], own.tags, own.whens, fn)
	}
}

// yamlWhens returns a task's `when:` conditions, whitespace normalized,
// accepting the string, list and boolean forms.
func yamlWhens(m map[string]any) []string {
	norm := func(v any) string { return strings.Join(strings.Fields(fmt.Sprint(v)), " ") }
	switch v := m["when"].(type) {
	case nil:
		return nil
	case []any:
		var out []string
		for _, cond := range v {
			out = append(out, norm(cond))
		}
		return out
	default:
		return []string{norm(v)}
	}
}

// runOrderTaskLists returns the task lists of doc that run one after the
// other on a host within one include or play: a task file, or each play's
// pre_tasks, tasks and post_tasks, blocks flattened in order.
func runOrderTaskLists(doc any) [][]condTask {
	items, _ := doc.([]any)
	playbook := false
	for _, item := range items {
		m, _ := item.(map[string]any)
		for _, key := range []string{"hosts", "import_playbook", "ansible.builtin.import_playbook"} {
			if _, ok := m[key]; ok {
				playbook = true
			}
		}
	}
	collect := func(tags []string, sections ...any) []condTask {
		var list []condTask
		for _, section := range sections {
			walkTaskTreeConds(section, tags, nil, func(ct condTask) { list = append(list, ct) })
		}
		return list
	}
	if !playbook {
		return [][]condTask{collect(nil, doc)}
	}
	var lists [][]condTask
	for _, item := range items {
		play, _ := item.(map[string]any)
		if _, ok := play["hosts"]; !ok {
			continue
		}
		lists = append(lists, collect(yamlTags(play), play["pre_tasks"], play["tasks"], play["post_tasks"]))
	}
	return lists
}

func TestLoopAccumulatorsWithoutReset(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string // facts flagged
		n    int      // accumulators found
	}{
		{"paren-less append without a reset (the freeipa-server-pool #157 bug)", `
- ansible.builtin.set_fact:
    acc: >-
      {{
        acc | default([]) +
        [item]
      }}
  loop: "{{ things }}"
  tags: [always]
`, []string{"acc"}, 1},
		{"reset first (the #157 fix)", `
- ansible.builtin.set_fact: {acc: []}
  tags: [always]
- ansible.builtin.set_fact: {acc: "{{ acc | default([]) + [item] }}"}
  loop: "{{ things }}"
  tags: [always]
`, nil, 1},
		{"reset after the loop", `
- set_fact: {acc: "{{ acc | default([]) + [item] }}"}
  loop: "{{ things }}"
- set_fact: {acc: []}
`, []string{"acc"}, 1},
		{"reset under a narrower when", `
- set_fact: {acc: []}
  when: other | bool
- set_fact: {acc: "{{ (acc | default([])) + [item] }}"}
  loop: "{{ things }}"
`, []string{"acc"}, 1},
		{"reset under the loop's own when", `
- set_fact: {acc: []}
  when: other | bool
- set_fact: {acc: "{{ (acc | default([])) + [item] }}"}
  loop: "{{ things }}"
  when:
    - other   |   bool
    - item != ''
`, nil, 1},
		{"reset with narrower tags that are not always", `
- set_fact: {acc: []}
  tags: [C1]
- set_fact: {acc: "{{ acc | default([]) + [item] }}"}
  loop: "{{ things }}"
  tags: [C1, C2]
`, []string{"acc"}, 1},
		{"reset with every tag of the loop", `
- set_fact: {acc: []}
  tags: [C1, C2, C3]
- set_fact: {acc: "{{ acc | default([]) + [item] }}"}
  loop: "{{ things }}"
  tags: [C1, C2]
`, nil, 1},
		{"reset inside the loop's enclosing block", `
- hosts: all
  tasks:
    - when: enabled | bool
      tags: [C4]
      block:
        - set_fact: {acc: {}}
        - set_fact: {acc: "{{ acc | combine({item.key: item.value}) }}"}
          loop: "{{ things | dict2items }}"
`, nil, 1},
		{"reset in a block with a when the loop outside it does not have", `
- hosts: all
  tasks:
    - when: enabled | bool
      block:
        - set_fact: {acc: {}}
    - set_fact: {acc: "{{ acc | combine({item.key: item.value}) }}"}
      loop: "{{ things | dict2items }}"
`, []string{"acc"}, 1},
		{"reset only in a rescue section", `
- block:
    - command: /bin/true
  rescue:
    - set_fact: {acc: []}
- set_fact: {acc: "{{ acc + [item] }}"}
  loop: "{{ things }}"
`, []string{"acc"}, 1},
		{"keyed combine without a reset", `
- set_fact:
    by_key: "{{ by_key | default({}) | combine({item.name: item}) }}"
  with_items: "{{ things }}"
`, []string{"by_key"}, 1},
		{"reset in pre_tasks, loop in tasks of the same play", `
- hosts: all
  pre_tasks:
    - set_fact: {acc: []}
      tags: [always]
  tasks:
    - set_fact: {acc: "{{ acc + [item] }}"}
      loop: "{{ things }}"
      tags: [C1]
`, nil, 1},
		{"reset only in an earlier play", `
- hosts: all
  tasks:
    - set_fact: {acc: []}
- hosts: all
  tasks:
    - set_fact: {acc: "{{ acc + [item] }}"}
      loop: "{{ things }}"
`, []string{"acc"}, 1},
		{"a reset that reads the fact is no reset", `
- set_fact: {acc: "{{ acc | default([]) }}"}
- set_fact: {acc: "{{ acc + [item] }}"}
  loop: "{{ things }}"
`, []string{"acc"}, 1},
		{"a reset to another variable's value", `
- set_fact: {acc: "{{ seed_list }}"}
- set_fact: {acc: "{{ acc + [item] }}"}
  loop: "{{ things }}"
`, nil, 1},
		{"reading another host's or key's same-named value is no accumulator", `
- set_fact:
    fqdn: "{{ hostvars[item].fqdn | default(item) }}"
    other: "{{ lookup_table['other'] }}"
  loop: "{{ hosts_list }}"
`, nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			got, n := loopAccumulatorsWithoutReset(doc)
			var facts []string
			for _, u := range got {
				facts = append(facts, u.fact)
			}
			if n != tc.n || !slices.Equal(facts, tc.want) {
				t.Fatalf("got %v (%d accumulators), want %v (%d)", facts, n, tc.want, tc.n)
			}
		})
	}
}

func TestUnresetAccumulatorProblems(t *testing.T) {
	found := map[string][]string{
		"a.yml::listed": {"loop"},
		"a.yml::new":    {"loop"},
	}
	allow := map[string]string{
		"a.yml::listed": "reason",
		"a.yml::fixed":  "reason",
	}
	problems := unresetAccumulatorProblems(found, allow)
	if len(problems) != 2 ||
		!strings.HasPrefix(problems[0], `a.yml::new: loop ["loop"]`) ||
		!strings.Contains(problems[1], `allowlist entry "a.yml::fixed" no longer matches`) {
		t.Fatalf("problems = %q", problems)
	}
}
