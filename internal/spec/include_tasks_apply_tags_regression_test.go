package spec

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// taggedIncludeWithoutApplyAllowlist lists dynamic include_tasks calls that
// may carry `tags:` without `apply: {tags: ...}`. Such tags select only the
// include statement: the tasks it pulls in do not inherit them, so
// `--tags <tag>` runs the include and then skips every included task that
// has no tag of its own, with no error (AGENTS.md §4.5 point 8; confirmed
// with ansible-core 2.19.2 on 2026-09-24). Site deploys pass --tags too
// when a --limit pulls in provider hosts (effectiveDeploymentTagScopes).
// The 2026-09-24 sweep migrated every such call, so it is empty; an entry
// needs a reason. Keys are "<playbook>|<included file>".
var taggedIncludeWithoutApplyAllowlist = map[string]bool{}

// TestRegression_TaggedIncludeTasksUseApply is a repo-wide lint over
// playbooks/**: every include_tasks with tags must also pass tags down with
// `apply`, unless it is in taggedIncludeWithoutApplyAllowlist. Stale
// allowlist entries fail too, so the list only shrinks.
func TestRegression_TaggedIncludeTasksUseApply(t *testing.T) {
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
		for _, included := range taggedIncludesWithoutApply(doc) {
			key := rel + "|" + included
			if taggedIncludeWithoutApplyAllowlist[key] {
				seen[key] = true
				continue
			}
			t.Errorf("%s: include_tasks %s has tags but no `apply: {tags: [...]}` — its tasks will not inherit the tags, so --tags skips them silently (AGENTS.md §4.5 point 8)", rel, included)
		}
	}
	for key := range taggedIncludeWithoutApplyAllowlist {
		if !seen[key] {
			t.Errorf("taggedIncludeWithoutApplyAllowlist entry %q no longer matches — drop it", key)
		}
	}
}

func TestTaggedIncludesWithoutApply(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"free-form with tags", `
- hosts: all
  tasks:
    - name: t
      tags: [C1]
      ansible.builtin.include_tasks: tasks/a.yml
`, []string{"tasks/a.yml"}},
		{"file form with apply tags", `
- name: t
  tags: [C1]
  ansible.builtin.include_tasks:
    file: tasks/a.yml
    apply: {tags: [C1]}
`, nil},
		{"file form with apply but no apply tags", `
- name: t
  tags: [C1]
  include_tasks:
    file: tasks/a.yml
    apply: {become: true}
`, []string{"tasks/a.yml"}},
		{"untagged include", `
- name: t
  ansible.builtin.include_tasks: tasks/a.yml
`, nil},
		{"nested in a block", `
- block:
    - name: t
      tags: [always]
      ansible.builtin.include_tasks: tasks/b.yml
`, []string{"tasks/b.yml"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			got := taggedIncludesWithoutApply(doc)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// taggedIncludesWithoutApply returns the included file of every
// include_tasks task in doc that has tags but no apply.tags.
func taggedIncludesWithoutApply(doc any) []string {
	var out []string
	var walk func(n any)
	walk = func(n any) {
		switch v := n.(type) {
		case []any:
			for _, c := range v {
				walk(c)
			}
		case map[string]any:
			for _, key := range []string{"ansible.builtin.include_tasks", "include_tasks"} {
				inc, ok := v[key]
				if !ok {
					continue
				}
				if tags, _ := v["tags"].([]any); len(tags) == 0 {
					if _, isString := v["tags"].(string); !isString {
						continue
					}
				}
				file, applyTags := "", false
				switch i := inc.(type) {
				case string:
					file = i
				case map[string]any:
					file, _ = i["file"].(string)
					if apply, ok := i["apply"].(map[string]any); ok {
						_, applyTags = apply["tags"]
					}
				}
				if !applyTags {
					out = append(out, file)
				}
			}
			for _, c := range v {
				walk(c)
			}
		}
	}
	walk(doc)
	return out
}
