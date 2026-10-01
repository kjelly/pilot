package spec

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRegression_IpaCommandsHaveAKinitForTheirTags is a repo-wide lint over
// playbooks/apply/*.yml. A task that runs `ipa <command>` needs a Kerberos
// ticket from an earlier kinit in the same play, and under --tags that kinit
// is skipped unless it is `always` or carries the task's row tags. The
// playbooks also kdestroy at the end of a full run, so no cached ticket
// covers for it. Until 2026-10-01, freeipa-identity's admin kinit carried
// only its group tags (every C<n> row run failed with "did not receive
// Kerberos credentials"), and pilot-access-directory's AD_service and
// pilot-session-store's SS_service rows ran `ipa group-add` without one.
// Plays with no kinit at all (they authenticate another way) are not
// checked.
func TestRegression_IpaCommandsHaveAKinitForTheirTags(t *testing.T) {
	checked := 0
	for _, path := range playbookFiles(t) {
		if !strings.Contains(path, "/playbooks/apply/") || strings.Contains(path, "/playbooks/apply/tasks/") {
			continue
		}
		problems, n := ipaTasksWithoutKinit(loadYAML(t, path))
		checked += n
		for _, p := range problems {
			t.Errorf("%s: %s", strings.TrimPrefix(path, "../../"), p)
		}
	}
	// Several apply playbooks kinit before ipa commands; none found means
	// the detection broke.
	if checked < 5 {
		t.Fatalf("found only %d plays with a kinit; the detection is broken", checked)
	}
}

func TestIpaTasksWithoutKinit(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"kinit with group tags, ipa task with a row tag (freeipa-identity)", `
- hosts: all
  tasks:
    - {name: kinit, tags: [identity], shell: "printf %s pw | kinit admin"}
    - {name: hbac, tags: [identity, C14], command: {argv: [ipa, hbacrule-enable, r]}}
`, 1},
		{"kinit always", `
- hosts: all
  tasks:
    - {name: kinit, tags: [always], shell: "printf %s pw | kinit admin"}
    - {name: hbac, tags: [C14], command: {argv: [ipa, hbacrule-enable, r]}}
`, 0},
		{"kinit carries the row tag", `
- hosts: all
  tasks:
    - {name: kinit, tags: [AD_keytab, AD_service], shell: "echo pw | kinit admin"}
    - {name: group, tags: [AD_service], command: "ipa group-add g"}
`, 0},
		{"ipa task tagged always needs an always kinit", `
- hosts: all
  tasks:
    - {name: kinit, tags: [C1], shell: "echo pw | kinit admin"}
    - {name: show, tags: [always], command: {argv: [ipa, host-show, h]}}
`, 1},
		{"untagged ipa task is covered by any kinit", `
- hosts: all
  tasks:
    - {name: kinit, tags: [C1], shell: "echo pw | kinit admin"}
    - {name: show, command: {argv: [ipa, host-show, h]}}
`, 0},
		{"kinit after the ipa task does not count", `
- hosts: all
  tasks:
    - {name: show, tags: [C2], command: {argv: [ipa, host-show, h]}}
    - {name: kinit, tags: [always], shell: "echo pw | kinit admin"}
`, 1},
		{"ipa-getcert and ipa_ variables are not ipa commands", `
- hosts: all
  tasks:
    - {name: kinit, tags: [C1], shell: "echo pw | kinit admin@{{ ipa_realm }}"}
    - {name: cert, tags: [C2], command: "ipa-getcert list"}
    - {name: var, tags: [C2], shell: "echo {{ ipa_realm }}"}
`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			got, n := ipaTasksWithoutKinit(doc)
			if n == 0 {
				t.Fatal("play with a kinit not detected")
			}
			if len(got) != tc.want {
				t.Fatalf("got %d problems %v, want %d", len(got), got, tc.want)
			}
		})
	}
}

var (
	ipaCommand   = regexp.MustCompile(`(^|[\s;&|(])ipa\s+[a-z]`)
	kinitCommand = regexp.MustCompile(`\bkinit\b`)
)

// ipaTasksWithoutKinit returns one message per task in doc's plays that runs
// an ipa command under a --tags selection that skips every earlier kinit in
// its play, and the number of plays with a kinit.
func ipaTasksWithoutKinit(doc any) ([]string, int) {
	plays, _ := doc.([]any)
	var out []string
	checked := 0
	for _, p := range plays {
		play, _ := p.(map[string]any)
		if _, ok := play["hosts"]; !ok {
			continue
		}
		type entry struct {
			task map[string]any
			tags []string
		}
		var tasks []entry
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks"} {
			walkTaskTree(play[section], yamlTags(play), func(task map[string]any, tags []string) {
				if task["block"] == nil {
					tasks = append(tasks, entry{task, tags})
				}
			})
		}
		var kinits [][]string
		for _, e := range tasks {
			if kinitCommand.MatchString(commandText(e.task)) {
				kinits = append(kinits, e.tags)
			}
		}
		if len(kinits) == 0 {
			continue
		}
		checked++
		kinits = nil
		for _, e := range tasks {
			text := commandText(e.task)
			if kinitCommand.MatchString(text) {
				kinits = append(kinits, e.tags)
				continue
			}
			if !ipaCommand.MatchString(text) || len(e.tags) == 0 {
				continue
			}
			var missing []string
			if slices.Contains(e.tags, "always") {
				if !slices.ContainsFunc(kinits, func(k []string) bool { return slices.Contains(k, "always") }) {
					missing = append(missing, "always")
				}
			} else {
				for _, tag := range e.tags {
					if !slices.ContainsFunc(kinits, func(k []string) bool { return slices.Contains(k, "always") || slices.Contains(k, tag) }) {
						missing = append(missing, tag)
					}
				}
			}
			if len(missing) > 0 {
				name, _ := e.task["name"].(string)
				out = append(out, fmt.Sprintf("task %q runs ipa, but no earlier kinit in its play runs under --tags %s; tag a kinit always or with those tags", name, strings.Join(missing, ",")))
			}
		}
	}
	return out, checked
}

// commandText returns a command/shell task's command line, or "".
func commandText(task map[string]any) string {
	for _, module := range []string{"command", "ansible.builtin.command", "shell", "ansible.builtin.shell"} {
		switch v := task[module].(type) {
		case string:
			return v
		case map[string]any:
			if argv, ok := v["argv"].([]any); ok {
				parts := make([]string, 0, len(argv))
				for _, a := range argv {
					parts = append(parts, fmt.Sprint(a))
				}
				return strings.Join(parts, " ")
			}
			if cmd, ok := v["cmd"].(string); ok {
				return cmd
			}
		}
	}
	return ""
}
