package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// taggedPrerequisiteAllowlist lists apply playbooks where a row-tagged task
// still reads a register or set_fact that its own tags do not select. Each
// needs its reads fixed and a tag-scoped run on a target; an entry fails
// the test once the playbook has no such read left.
var taggedPrerequisiteAllowlist = map[string]string{
	"audit-log-forwarding-apply.yml":   "follow-up",
	"dcgm-exporter-apply.yml":          "follow-up",
	"freeipa-client-apply.yml":         "follow-up",
	"freeipa-identity-apply.yml":       "follow-up",
	"freeipa-nfs-server-apply.yml":     "follow-up",
	"gateway-scope-apply.yml":          "follow-up",
	"host-monitoring-apply.yml":        "follow-up",
	"log-server-apply.yml":             "follow-up",
	"log-shipping-apply.yml":           "follow-up",
	"pilot-access-directory-apply.yml": "follow-up",
	"pilot-access-gateway-apply.yml":   "follow-up",
	"pilot-session-store-apply.yml":    "follow-up",
	"seaweedfs-s3-apply.yml":           "follow-up",
	"snmp-exporter-apply.yml":          "follow-up",
	"wazuh-fim-apply.yml":              "follow-up",
}

// TestRegression_TaggedTasksReadOnlyWhatTheirTagsSet is a repo-wide lint
// over playbooks/apply/*.yml. It extends
// TestRegression_AlwaysTaggedTasksHaveAllPrerequisitesAlways from `always`
// tasks to row-tagged ones: a task tagged T that reads a variable set by an
// earlier task U (set_fact or register) must find it set under every
// --tags that selects T. That holds when U is `always`, when U carries
// every tag of T, or when the read has a default or an `is defined`
// check. Otherwise `--tags <row>` fails at the task, or reads a stale
// value. Until 2026-10-01, alertmanager's, dashboard's, prometheus's and
// thanos-query's container tasks read the register of a render task with
// other tags in their `restart:` expression, so every container row run
// failed; pam-oidc-sshd's C2 copy read an untagged detection; and
// agent-controller's C2/C4 config render read an untagged listen-address
// resolve and rendered an empty address. Each failure is inside a block
// whose rescue now rolls back under --tags too
// (TestRegression_RescueRunsWheneverItsBlockDoes).
func TestRegression_TaggedTasksReadOnlyWhatTheirTagsSet(t *testing.T) {
	files, err := filepath.Glob("../../playbooks/apply/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 30 {
		t.Fatalf("found only %d apply playbooks", len(files))
	}
	for _, path := range files {
		base := filepath.Base(path)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		tasks, err := parsePlaybookTasks(raw)
		if err != nil {
			t.Fatalf("%s: %v", base, err)
		}
		problems := findTaggedPrerequisiteViolations(tasks)
		if _, allowed := taggedPrerequisiteAllowlist[base]; allowed {
			if len(problems) == 0 {
				t.Errorf("%s: no unselected reads left; remove it from taggedPrerequisiteAllowlist", base)
			}
			continue
		}
		for _, p := range problems {
			t.Errorf("%s: %s", base, p)
		}
	}
	for base := range taggedPrerequisiteAllowlist {
		if _, err := os.Stat("../../playbooks/apply/" + base); err != nil {
			t.Errorf("taggedPrerequisiteAllowlist: %s: %v", base, err)
		}
	}
}

func TestFindTaggedPrerequisiteViolations(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"restart reads another row's render register (the alertmanager bug)", `
- hosts: all
  tasks:
    - {name: render, tags: [C4], template: {src: a, dest: b}, register: render_result}
    - name: container
      tags: [C1]
      docker_container: {name: x, restart: "{{ render_result is changed }}"}
`, 1},
		{"read with a default", `
- hosts: all
  tasks:
    - {name: render, tags: [C4], template: {src: a, dest: b}, register: render_result}
    - name: container
      tags: [C1]
      docker_container: {name: x, restart: "{{ (render_result | default({})) is changed }}"}
`, 0},
		{"guarded by is defined", `
- hosts: all
  tasks:
    - {name: render, tags: [C4], template: {src: a, dest: b}, register: r}
    - {name: c, tags: [C1], debug: {msg: x}, when: [r is defined, r is changed]}
`, 0},
		{"setter carries the reader's tags", `
- hosts: all
  tasks:
    - {name: detect, tags: [C2, C3], shell: x, register: lib}
    - {name: copy, tags: [C2], copy: {src: a, dest: "{{ lib.stdout }}"}}
`, 0},
		{"untagged setter (pam-oidc-sshd Step 4)", `
- hosts: all
  tasks:
    - {name: detect, shell: x, register: lib}
    - {name: copy, tags: [C2], copy: {src: a, dest: "{{ lib.stdout }}"}}
`, 1},
		{"always setter", `
- hosts: all
  pre_tasks:
    - {name: resolve, tags: [always], set_fact: {addr: 1}}
  tasks:
    - {name: render, tags: [C2], copy: {content: "{{ addr }}", dest: b}}
`, 0},
		{"untagged reader is not checked", `
- hosts: all
  tasks:
    - {name: render, tags: [C4], template: {src: a, dest: b}, register: r}
    - {name: c, debug: {msg: "{{ r }}"}}
`, 0},
		{"inherited block tags count", `
- hosts: all
  tasks:
    - tags: [C1]
      block:
        - {name: detect, shell: x, register: lib}
        - {name: copy, copy: {src: a, dest: "{{ lib.stdout }}"}}
`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tasks, err := parsePlaybookTasks([]byte(tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if got := findTaggedPrerequisiteViolations(tasks); len(got) != tc.want {
				t.Fatalf("got %d problems %v, want %d", len(got), got, tc.want)
			}
		})
	}
}

// findTaggedPrerequisiteViolations flags each task tagged with something
// other than `always` that reads, without a default or an `is defined`
// check, a variable whose most recent setter is neither `always` nor
// tagged with every tag of the reader.
func findTaggedPrerequisiteViolations(tasks []playbookTask) []string {
	type setter struct {
		name string
		tags map[string]bool
	}
	last := map[string]setter{}
	var out []string
	for _, task := range tasks {
		if len(task.Tags) > 0 && !task.Tags["always"] {
			vars := make([]string, 0, len(last))
			for v := range last {
				vars = append(vars, v)
			}
			sort.Strings(vars)
			for _, v := range vars {
				s := last[v]
				if s.tags["always"] || tagsCover(s.tags, task.Tags) {
					continue
				}
				if taskReadsVarUnguarded(task.Node, v) {
					out = append(out, fmt.Sprintf("line %d: task %q (tags %s) reads %q, set by %q (tags %s), which those tags do not select; tag the setter, or read it with a default",
						task.Line, task.Name, tagList(task.Tags), v, s.name, tagList(s.tags)))
				}
			}
		}
		for _, v := range task.SetsVars {
			last[v] = setter{task.Name, task.Tags}
		}
	}
	return out
}

func tagsCover(setter, reader map[string]bool) bool {
	for tag := range reader {
		if !setter[tag] {
			return false
		}
	}
	return true
}

func tagList(tags map[string]bool) string {
	list := make([]string, 0, len(tags))
	for tag := range tags {
		list = append(list, tag)
	}
	sort.Strings(list)
	return "[" + strings.Join(list, ", ") + "]"
}

// taskReadsVarUnguarded reports whether the task's own body reads varName
// at least once without `| default(...)` or `is (not) defined` right after
// it (attribute access in between allowed), unless the task checks
// `varName is defined` somewhere.
func taskReadsVarUnguarded(item *yaml.Node, varName string) bool {
	word := regexp.MustCompile(`\b` + regexp.QuoteMeta(varName) + `\b`)
	guard := regexp.MustCompile(`^(\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]*\])*\s*(\|\s*default\b|is\s+(not\s+)?defined\b)`)
	checked := regexp.MustCompile(`\b` + regexp.QuoteMeta(varName) + `\s+is\s+defined\b`)
	var scalars []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		switch n.Kind {
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				switch n.Content[i].Value {
				case "block", "rescue", "always", "name", "register":
					continue
				}
				walk(n.Content[i+1])
			}
		case yaml.ScalarNode:
			scalars = append(scalars, n.Value)
		default:
			for _, c := range n.Content {
				walk(c)
			}
		}
	}
	walk(item)
	unguarded := false
	for _, s := range scalars {
		if checked.MatchString(s) {
			return false
		}
		for _, loc := range word.FindAllStringIndex(s, -1) {
			if !guard.MatchString(s[loc[1]:]) {
				unguarded = true
			}
		}
	}
	return unguarded
}
