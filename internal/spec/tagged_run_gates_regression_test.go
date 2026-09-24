package spec

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// preTaskGateNotAlwaysAllowlist lists pre_tasks gates that a tag-scoped
// run can still skip in a play whose includes pass tags down with `apply`.
// They were already skippable before the 2026-09-24 include migration: the
// same plays also have plainly tagged tasks, so `--tags <row>` has always
// run those without the gates. They belong to the repo-wide stage-gate
// follow-up (every apply playbook's stage gates `always`, plus the §4.3
// cross-check where it is missing). Keys are "<playbook>|<task name>".
// Entries may only be removed.
var preTaskGateNotAlwaysAllowlist = map[string]bool{
	"playbooks/apply/core-infra-provider-apply.yml|Gate: infra_role must be dns or ntp":                            true,
	"playbooks/apply/core-infra-provider-apply.yml|Gate: staging or prod requires explicit confirm":                true,
	"playbooks/apply/core-infra-provider-apply.yml|Gate: stage must match this host's inventory environment group": true,
	"playbooks/apply/core-infra-provider-apply.yml|Gate: prod requires recent staging attestation":                 true,
	"playbooks/apply/docker-apply.yml|Gate: staging or prod requires explicit confirm":                             true,
	"playbooks/apply/docker-apply.yml|Gate: stage must match this host's inventory environment group":              true,
	"playbooks/apply/docker-apply.yml|Gate: prod requires recent staging attestation":                              true,
	"playbooks/apply/restic-backup-apply.yml|Gate: required secrets present (fail early, before any mutation)":     true,
	"playbooks/apply/restic-backup-apply.yml|Gate: backup destination must be resolvable":                          true,
	"playbooks/apply/reverse-proxy-apply.yml|Gate: staging or prod requires explicit confirm":                      true,
	"playbooks/apply/reverse-proxy-apply.yml|Gate: prod requires recent staging attestation":                       true,
}

// TestRegression_PreTaskGatesRunUnderApplyTags is a repo-wide lint over
// playbooks/**. In a play with an include_tasks that passes tags down with
// `apply`, every assert/fail in pre_tasks must run whenever those included
// tasks can: it must be tagged `always`, or carry every tag the play's
// includes apply. Otherwise `--tags <row>` skips the gate and still runs
// the included mutation. PR #10's review found two such bypasses the
// include migration had opened: freeipa-ca-trust's stage gates
// (`--tags C2 -e stage=prod` installed the CA without confirm_prod) and
// internal-endpoint's C7/C8 DNS gates (see
// TestRegression_InternalEndpointGatesCoverTaggedMutations for the
// tasks-section half, which needs the row mapping).
func TestRegression_PreTaskGatesRunUnderApplyTags(t *testing.T) {
	var files []string
	err := filepath.WalkDir("../../playbooks", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	seen := map[string]bool{}
	checkedPlays := 0
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: parse: %v", rel, err)
		}
		gates, plays := skippablePreTaskGates(doc)
		checkedPlays += plays
		for _, name := range gates {
			key := rel + "|" + name
			if preTaskGateNotAlwaysAllowlist[key] {
				seen[key] = true
				continue
			}
			t.Errorf("%s: pre_tasks gate %q is not `always` (and lacks the tags the play's includes apply), so --tags skips it while the included tasks still run", rel, name)
		}
	}
	// The migrated playbooks alone have more than ten such plays; a much
	// smaller count means the walker stopped finding them.
	if checkedPlays < 10 {
		t.Fatalf("only %d plays with apply-tagged includes found; the walker is broken", checkedPlays)
	}
	for key := range preTaskGateNotAlwaysAllowlist {
		if !seen[key] {
			t.Errorf("preTaskGateNotAlwaysAllowlist entry %q no longer matches — drop it", key)
		}
	}
}

func TestSkippablePreTaskGates(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"untagged gate before apply include (freeipa-ca-trust before the fix)", `
- hosts: all
  pre_tasks:
    - name: g
      ansible.builtin.assert: {that: [true]}
  tasks:
    - name: i
      tags: [C2]
      ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C2]}}
`, []string{"g"}},
		{"always gate", `
- hosts: all
  pre_tasks:
    - name: g
      tags: [always]
      ansible.builtin.assert: {that: [true]}
  tasks:
    - name: i
      tags: [C2]
      ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C2]}}
`, nil},
		{"gate carries every applied tag", `
- hosts: all
  pre_tasks:
    - name: g
      tags: [C1, C2]
      fail: {msg: x}
  tasks:
    - name: i
      tags: [C1]
      include_tasks: {file: tasks/a.yml, apply: {tags: [C1]}}
    - name: j
      tags: [C2]
      include_tasks: {file: tasks/b.yml, apply: {tags: [C2]}}
`, nil},
		{"gate misses one applied tag", `
- hosts: all
  pre_tasks:
    - name: g
      tags: [C1]
      ansible.builtin.fail: {msg: x}
  tasks:
    - name: i
      tags: [C1, C2]
      ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C1, C2]}}
`, []string{"g"}},
		{"always inherited from a block", `
- hosts: all
  pre_tasks:
    - tags: [always]
      block:
        - name: g
          ansible.builtin.assert: {that: [true]}
  tasks:
    - block:
        - name: i
          tags: [C2]
          ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C2]}}
`, nil},
		{"no apply include in the play", `
- hosts: all
  pre_tasks:
    - name: g
      ansible.builtin.assert: {that: [true]}
  tasks:
    - name: i
      tags: [C2]
      ansible.builtin.include_tasks: tasks/a.yml
`, nil},
		{"non-gate pre_task is ignored", `
- hosts: all
  pre_tasks:
    - name: s
      ansible.builtin.set_fact: {x: 1}
  tasks:
    - name: i
      tags: [C2]
      ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C2]}}
`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			got, _ := skippablePreTaskGates(doc)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

var gateModules = []string{"ansible.builtin.assert", "assert", "ansible.builtin.fail", "fail"}

// skippablePreTaskGates returns, for every play in doc that has an
// include_tasks with apply.tags, the names of its assert/fail pre_tasks
// whose effective tags (own plus inherited from the play and enclosing
// blocks) have neither `always` nor every tag those includes apply. The
// second result is the number of such plays checked.
func skippablePreTaskGates(doc any) ([]string, int) {
	plays, _ := doc.([]any)
	var out []string
	checked := 0
	for _, p := range plays {
		play, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := play["hosts"]; !ok {
			continue
		}
		playTags := yamlTags(play)
		applied := map[string]bool{}
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks"} {
			walkTaskTree(play[section], playTags, func(task map[string]any, _ []string) {
				for _, key := range []string{"ansible.builtin.include_tasks", "include_tasks"} {
					inc, _ := task[key].(map[string]any)
					apply, _ := inc["apply"].(map[string]any)
					for _, tag := range yamlTags(apply) {
						applied[tag] = true
					}
				}
			})
		}
		if len(applied) == 0 {
			continue
		}
		checked++
		walkTaskTree(play["pre_tasks"], playTags, func(task map[string]any, tags []string) {
			if !slices.ContainsFunc(gateModules, func(m string) bool { _, ok := task[m]; return ok }) {
				return
			}
			if slices.Contains(tags, "always") {
				return
			}
			for tag := range applied {
				if !slices.Contains(tags, tag) {
					name, _ := task["name"].(string)
					out = append(out, name)
					return
				}
			}
		})
	}
	return out, checked
}

// walkTaskTree calls fn for every task in a task list, recursing into
// block/rescue/always, with each task's effective tags.
func walkTaskTree(list any, inherited []string, fn func(task map[string]any, tags []string)) {
	tasks, _ := list.([]any)
	for _, item := range tasks {
		task, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tags := append(slices.Clone(inherited), yamlTags(task)...)
		fn(task, tags)
		for _, key := range []string{"block", "rescue", "always"} {
			walkTaskTree(task[key], tags, fn)
		}
	}
}

// yamlTags returns a task's or play's `tags:` as a list, accepting both the
// list and the single-string form.
func yamlTags(m map[string]any) []string {
	switch v := m["tags"].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, tag := range v {
			if s, ok := tag.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// TestRegression_InternalEndpointGatesCoverTaggedMutations locks which
// tasks-section gates of internal-endpoint-apply.yml must run under the
// row tags of the mutations they protect. The route DNS reconcile runs
// under C4-C6 and has no zone or collision check of its own, so the C7 and
// C8 gates carry C4-C6; the service-principal (C13) and certificate (C15)
// tasks rely on the C12 enrollment preflight. Before this, `--tags C4`
// could `ipa dnsrecord-mod` a record freeipa-dns.yaml owns. It also locks
// the stage gates on the fleet-wide baseline play (C9 resolver, C10 CA
// trust), which had none.
func TestRegression_InternalEndpointGatesCoverTaggedMutations(t *testing.T) {
	raw, err := os.ReadFile("../../playbooks/apply/internal-endpoint-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc []any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) < 2 {
		t.Fatalf("expected the baseline play and the reconcile play, got %d plays", len(doc))
	}
	find := func(play any, section, prefix string) (map[string]any, []string) {
		var task map[string]any
		var tags []string
		p, _ := play.(map[string]any)
		walkTaskTree(p[section], nil, func(tk map[string]any, tg []string) {
			if name, _ := tk["name"].(string); strings.HasPrefix(name, prefix) {
				task, tags = tk, tg
			}
		})
		if task == nil {
			t.Fatalf("no %s task named %q", section, prefix)
		}
		return task, tags
	}

	for _, gate := range []string{
		"Gate: staging or prod requires explicit confirm",
		"Gate: prod requires recent staging attestation",
	} {
		if _, tags := find(doc[0], "pre_tasks", gate); !slices.Contains(tags, "always") {
			t.Errorf("baseline play: %q must be tagged always, got %v", gate, tags)
		}
	}

	for _, tc := range []struct{ prefix, section string }{
		{"Gate: endpoint's DNS zone exists in freeipa-dns manifest", "tasks"},
		{"Gate: no DNS ownership collision with an explicit freeipa-dns.yaml record", "tasks"},
	} {
		_, tags := find(doc[1], tc.section, tc.prefix)
		for _, row := range []string{"C4", "C5", "C6"} {
			if !slices.Contains(tags, row) {
				t.Errorf("%q must carry %s (the route DNS reconcile runs under it), got %v", tc.prefix, row, tags)
			}
		}
	}

	preflight, tags := find(doc[1], "tasks", "Preflight: TLS certificate owner host has live FreeIPA enrollment")
	inc, _ := preflight["ansible.builtin.include_tasks"].(map[string]any)
	apply, _ := inc["apply"].(map[string]any)
	for _, row := range []string{"C12", "C13", "C15"} {
		if !slices.Contains(tags, row) || !slices.Contains(yamlTags(apply), row) {
			t.Errorf("C12 preflight must carry %s on the include and in apply.tags, got tags=%v apply=%v", row, tags, yamlTags(apply))
		}
	}
}

// TestRegression_InternalEndpointDeleteDelegateToNeverEmpty locks the
// empty-delegate_to fix in the delete sequence. A literal-address route has
// route_owner "" and a tls.mode: disabled endpoint has certificate_owner "".
// delegate_to is templated before `when`, so either one bare is a hard
// error ("Empty hostname produced from delegate_to"), not a skip. Every
// delegate_to in the file needs a fallback that its `when:` never acts on.
func TestRegression_InternalEndpointDeleteDelegateToNeverEmpty(t *testing.T) {
	raw, err := os.ReadFile("../../playbooks/apply/tasks/internal-endpoint-delete.yml")
	if err != nil {
		t.Fatal(err)
	}
	var tasks []any
	if err := yaml.Unmarshal(raw, &tasks); err != nil {
		t.Fatal(err)
	}
	delegated := 0
	walkTaskTree(tasks, nil, func(task map[string]any, _ []string) {
		target, ok := task["delegate_to"].(string)
		if !ok {
			return
		}
		delegated++
		if !strings.Contains(target, "or inventory_hostname") {
			t.Errorf("task %q: delegate_to %q has no fallback for an empty owner", task["name"], target)
		}
	})
	if delegated < 7 {
		t.Fatalf("found only %d delegated tasks; expected the nginx and certificate steps", delegated)
	}
}
