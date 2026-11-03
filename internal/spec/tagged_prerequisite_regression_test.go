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
// still reads a register or set_fact that its own tags do not select. It
// is empty since 2026-10-01. An entry needs a reason, and fails the test
// once the playbook has no such read left.
var taggedPrerequisiteAllowlist = map[string]string{}

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
// (TestRegression_RescueRunsWheneverItsBlockDoes). Facts set inside an
// include_tasks/import_tasks file count too (expandIncludedSetters):
// wazuh-manager's C10 and wazuh-fim's C7 /etc/hosts pins read
// hosts_alias_resolved_ip from an untagged include of
// tasks/resolve-hosts-alias-target.yml, so those rows always failed and,
// once the rescues ran under --tags, removed the deployed configuration.
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
		tasks, err = expandIncludedSetters(tasks, filepath.Dir(path), filepath.Dir(path))
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

// expandIncludedSetters returns tasks with a synthetic setter entry after
// each include_tasks/import_tasks of a static file, one per task in that
// file that sets a variable, tagged the way Ansible selects it:
//   - import_tasks: the include's tags plus the task's own;
//   - include_tasks: the task runs when --tags selects both the include
//     line and the included task, whose tags are `apply` tags plus its own.
//
// Synthetic entries have no Node, so they are never checked as readers.
// Paths resolve against the including file's directory, then baseDir.
func expandIncludedSetters(tasks []playbookTask, fileDir, baseDir string) ([]playbookTask, error) {
	return expandIncludedSettersDepth(tasks, fileDir, baseDir, 0)
}

func expandIncludedSettersDepth(tasks []playbookTask, fileDir, baseDir string, depth int) ([]playbookTask, error) {
	var out []playbookTask
	for _, task := range tasks {
		out = append(out, task)
		file, apply, static, err := includedFile(task.Node)
		if err != nil {
			return nil, fmt.Errorf("task %q: %w", task.Name, err)
		}
		if file == "" || depth > 4 {
			continue
		}
		var raw []byte
		var dir string
		for _, d := range []string{fileDir, baseDir} {
			if b, err := os.ReadFile(filepath.Join(d, file)); err == nil {
				raw, dir = b, filepath.Dir(filepath.Join(d, file))
				break
			}
		}
		if raw == nil {
			continue
		}
		var doc yaml.Node
		if yaml.Unmarshal(raw, &doc) != nil || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.SequenceNode {
			continue
		}
		var inner []playbookTask
		walkTaskList(doc.Content[0], nil, &inner)
		inner, err = expandIncludedSettersDepth(inner, dir, baseDir, depth+1)
		if err != nil {
			return nil, err
		}
		for _, in := range inner {
			if len(in.SetsVars) == 0 {
				continue
			}
			out = append(out, playbookTask{
				Name:     task.Name + " -> " + in.Name,
				Tags:     includedTaskTags(task.Tags, apply, in.Tags, static),
				SetsVars: in.SetsVars,
				Line:     task.Line,
			})
		}
	}
	return out, nil
}

// includedFile returns the static file an include_tasks/import_tasks task
// loads, the tags its `apply` gives the included tasks, and whether it is
// an import. Task args are merged first, then module arguments replace whole
// keys (including apply), as ModuleArgsParser does; aliases work at each level.
// It returns "" for any other task or a templated path, and an error for
// argument forms that cannot be resolved statically instead of ignoring them.
func includedFile(item *yaml.Node) (string, map[string]bool, bool, error) {
	item = yamlDeref(item)
	if item == nil || item.Kind != yaml.MappingNode {
		return "", nil, false, nil
	}
	for i := 0; i+1 < len(item.Content); i += 2 {
		k, v := item.Content[i].Value, item.Content[i+1]
		static := k == "import_tasks" || k == "ansible.builtin.import_tasks"
		if !static && k != "include_tasks" && k != "ansible.builtin.include_tasks" {
			continue
		}
		args := map[string]*yaml.Node{}
		merge := func(n *yaml.Node) error {
			n = yamlDeref(n)
			if n == nil || n.Tag == "!!null" {
				return nil
			}
			if n.Kind != yaml.MappingNode {
				return fmt.Errorf("%s arguments must be a static mapping", k)
			}
			for j := 0; j+1 < len(n.Content); j += 2 {
				if n.Content[j].Value == "<<" {
					return fmt.Errorf("%s arguments use unsupported merge key (<<:)", k)
				}
				args[n.Content[j].Value] = yamlDeref(n.Content[j+1])
			}
			return nil
		}
		if err := merge(yamlField(item, "args")); err != nil {
			return "", nil, static, err
		}
		v = yamlDeref(v)
		if v != nil && v.Kind == yaml.ScalarNode && v.Tag != "!!null" {
			// Legacy k=v strings require Ansible's split_args parser. Refuse
			// them rather than guessing at their effective file/apply values.
			if strings.Contains(v.Value, "=") {
				return "", nil, static, fmt.Errorf("%s uses unsupported key=value arguments", k)
			}
			args["_raw_params"] = v
		} else if err := merge(v); err != nil {
			return "", nil, static, err
		}
		fileNode := args["_raw_params"]
		if fileNode == nil || fileNode.Value == "" {
			fileNode = args["file"]
		}
		file := ""
		if fileNode != nil {
			if fileNode.Kind != yaml.ScalarNode {
				return "", nil, static, fmt.Errorf("%s file must be a static scalar", k)
			}
			file = fileNode.Value
		}
		apply := map[string]bool{}
		if a := args["apply"]; a != nil {
			if a.Kind != yaml.MappingNode {
				return "", nil, static, fmt.Errorf("%s apply must be a static mapping", k)
			}
			for j := 0; j+1 < len(a.Content); j += 2 {
				if a.Content[j].Value == "<<" {
					return "", nil, static, fmt.Errorf("%s apply uses unsupported merge key (<<:)", k)
				}
			}
			var tags func(*yaml.Node, int) error
			tags = func(n *yaml.Node, depth int) error {
				if depth > 16 {
					return fmt.Errorf("%s apply tags exceed nesting limit (possible alias cycle)", k)
				}
				n = yamlDeref(n)
				if n == nil {
					return nil
				}
				switch n.Kind {
				case yaml.ScalarNode:
					if strings.Contains(n.Value, "{{") {
						return fmt.Errorf("%s apply tags must be static", k)
					}
				case yaml.SequenceNode:
					for _, c := range n.Content {
						if err := tags(c, depth+1); err != nil {
							return err
						}
					}
				default:
					return fmt.Errorf("%s apply tags must be static scalars or a list", k)
				}
				return nil
			}
			tagNode := yamlField(a, "tags")
			if err := tags(tagNode, 0); err != nil {
				return "", nil, static, err
			}
			apply = convergenceTagSet(tagNode)
		}
		if strings.Contains(file, "{{") {
			return "", nil, static, nil
		}
		return file, apply, static, nil
	}
	return "", nil, false, nil
}

func TestIncludedFileUnsupportedArguments(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"templated args", "include_tasks: child.yml\n      args: '{{ opts }}'", "arguments must be a static mapping"},
		{"templated apply", "include_tasks: {file: child.yml, apply: '{{ opts }}'}", "apply must be a static mapping"},
		{"templated tags", "include_tasks: {file: child.yml, apply: {tags: '{{ taglist }}'}}", "apply tags must be static"},
		{"merged args", "include_tasks: child.yml\n      args: {<<: {apply: {tags: [always]}}}", "unsupported merge key"},
		{"merged apply", "include_tasks: {file: child.yml, apply: {<<: {tags: [always]}}}", "unsupported merge key"},
		{"invalid tag mapping", "include_tasks: {file: child.yml, apply: {tags: {always: true}}}", "apply tags must be static scalars or a list"},
		{"cyclic tags", "include_tasks: {file: child.yml, apply: {tags: &cycle [*cycle]}}", "apply tags exceed nesting limit"},
		{"legacy key=value", "include_tasks: file=child.yml", "unsupported key=value arguments"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte("- hosts: all\n  tasks:\n    - name: include\n      tags: [always]\n      " + tc.body + "\n")
			tasks, err := parsePlaybookTasks(raw)
			if err != nil {
				t.Fatal(err)
			}
			_, err = expandIncludedSetters(tasks, t.TempDir(), t.TempDir())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("setter expansion: got %v, want %q", err, tc.want)
			}
			_, err = scanAlwaysTaggedConvergence("p.yml", raw, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("convergence scan: got %v, want %q", err, tc.want)
			}
		})
	}
}

// includedTaskTags is the tag set under which a task inside an included
// file runs, in the form findTaggedPrerequisiteViolations compares: a set
// with `always`, or the row tags that select it (empty: full runs only).
func includedTaskTags(line, apply, own map[string]bool, static bool) map[string]bool {
	union := func(a, b map[string]bool) map[string]bool {
		out := map[string]bool{}
		for t := range a {
			out[t] = true
		}
		for t := range b {
			out[t] = true
		}
		return out
	}
	if static {
		return union(line, own)
	}
	inner := union(apply, own)
	switch {
	case line["always"] && inner["always"]:
		return map[string]bool{"always": true}
	case line["always"]:
		return inner
	case inner["always"]:
		return union(line, nil)
	}
	out := map[string]bool{}
	for t := range line {
		if inner[t] {
			out[t] = true
		}
	}
	return out
}

func TestExpandIncludedSetters(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tasks"), 0o755); err != nil {
		t.Fatal(err)
	}
	resolver := "- name: resolve\n  set_fact: {resolved_ip: 192.0.2.1}\n"
	if err := os.WriteFile(filepath.Join(dir, "tasks", "resolve.yml"), []byte(resolver), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		include string
		want    int
	}{
		{"untagged include, tagged reader (the wazuh-manager C10 pin)", `
    - name: resolve
      include_tasks: tasks/resolve.yml`, 1},
		{"include tagged always with apply always", `
    - name: resolve
      tags: [always]
      include_tasks: {file: tasks/resolve.yml, apply: {tags: [always]}}`, 0},
		{"include tagged with the reader's row but no apply", `
    - name: resolve
      tags: [C10]
      include_tasks: tasks/resolve.yml`, 1},
		{"include with the reader's row and apply", `
    - name: resolve
      tags: [C10]
      include_tasks: {file: tasks/resolve.yml, apply: {tags: [C10]}}`, 0},
		{"task args apply always", `
    - name: resolve
      tags: [always]
      include_tasks: tasks/resolve.yml
      args: {apply: {tags: [always]}}`, 0},
		{"aliased apply mapping", `
    - name: resolve
      vars: {opts: &opts {tags: [always]}}
      tags: [always]
      include_tasks: {file: tasks/resolve.yml, apply: *opts}`, 0},
		{"aliased apply tag list", `
    - name: resolve
      vars: {taglist: &taglist [always]}
      tags: [always]
      include_tasks: {file: tasks/resolve.yml, apply: {tags: *taglist}}`, 0},
		{"module apply replaces args apply", `
    - name: resolve
      tags: [always]
      include_tasks: {file: tasks/resolve.yml, apply: {tags: [C10]}}
      args: {apply: {tags: [other]}}`, 0},
		{"args apply cannot override module apply", `
    - name: resolve
      tags: [always]
      include_tasks: {file: tasks/resolve.yml, apply: {tags: [other]}}
      args: {apply: {tags: [C10]}}`, 1},
		{"module apply replacement does not merge tags", `
    - name: resolve
      tags: [always]
      include_tasks: {file: tasks/resolve.yml, apply: {become: false}}
      args: {apply: {tags: [C10]}}`, 1},
		{"import tagged with the reader's row", `
    - name: resolve
      tags: [C10]
      import_tasks: tasks/resolve.yml`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			play := "- hosts: all\n  tasks:" + tc.include + `
    - name: pin
      tags: [C10]
      lineinfile: {path: /etc/hosts, line: "{{ resolved_ip }} alias"}
`
			tasks, err := parsePlaybookTasks([]byte(play))
			if err != nil {
				t.Fatal(err)
			}
			tasks, err = expandIncludedSetters(tasks, dir, dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := findTaggedPrerequisiteViolations(tasks); len(got) != tc.want {
				t.Fatalf("got %d problems %v, want %d", len(got), got, tc.want)
			}
		})
	}
}
