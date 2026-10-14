package spec

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRegression_IpaCommandsHaveAKinitForTheirTags is a repo-wide lint over
// the plays under playbooks/ (not the deprecated playbooks/verify/). A task
// that runs `ipa <command>` needs a Kerberos ticket from an earlier kinit in
// the same play that wrote the same credential cache, and under --tags that
// kinit is skipped unless it is `always` or carries the task's row tags.
// The playbooks destroy their caches (issue #69), so no ticket left over
// from earlier covers for it. Until 2026-10-01, freeipa-identity's admin
// kinit carried only its group tags (every C<n> row run failed with "did
// not receive Kerberos credentials"), and pilot-access-directory's
// AD_service and pilot-session-store's SS_service rows ran `ipa group-add`
// without one. Since PR #72 the cache must match too: an ipa task after a
// private-cache block, or with another block's cache, runs without the
// ticket. Plays with no kinit at all (they authenticate another way) are
// not checked.
func TestRegression_IpaCommandsHaveAKinitForTheirTags(t *testing.T) {
	checked := 0
	for _, path := range playbookFiles(t) {
		if strings.Contains(path, "/playbooks/verify/") {
			continue
		}
		problems, n := ipaTasksWithoutKinit(loadYAML(t, path))
		checked += n
		for _, p := range problems {
			t.Errorf("%s: %s", strings.TrimPrefix(path, "../../"), p)
		}
	}
	// Many playbooks kinit before ipa commands; few found means the
	// detection broke.
	if checked < 15 {
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
		{"ipa after the private-cache block runs without the ticket", `
- hosts: all
  tasks:
    - name: b
      environment: {KRB5CCNAME: "{{ pilot_krb5ccname | default('FILE:/nonexistent/x') }}"}
      block:
        - {name: open, tags: [always], include_tasks: {file: tasks/freeipa-private-ccache-open.yml, apply: {tags: [always]}}}
        - {name: kinit, tags: [always], shell: "echo pw | kinit admin"}
        - {name: inside, tags: [C1], command: {argv: [ipa, host-show, h]}}
      always:
        - {name: close, tags: [always], include_tasks: {file: tasks/freeipa-private-ccache-close.yml, apply: {tags: [always]}}}
    - {name: after, tags: [C1], command: {argv: [ipa, host-show, h]}}
`, 1},
		{"ipa in another private block than the kinit", `
- hosts: all
  tasks:
    - name: b1
      environment: {KRB5CCNAME: "{{ pilot_krb5ccname }}"}
      block:
        - {name: open, include_tasks: {file: tasks/freeipa-private-ccache-open.yml, apply: {tags: [always]}}, tags: [always]}
        - {name: kinit, shell: "echo pw | kinit admin"}
      always:
        - {name: close, include_tasks: {file: tasks/freeipa-private-ccache-close.yml, apply: {tags: [always]}}, tags: [always]}
    - name: b2
      environment: {KRB5CCNAME: "{{ pilot_krb5ccname }}"}
      block:
        - {name: open, include_tasks: {file: tasks/freeipa-private-ccache-open.yml, apply: {tags: [always]}}, tags: [always]}
        - {name: show, command: {argv: [ipa, host-show, h]}}
      always:
        - {name: close, include_tasks: {file: tasks/freeipa-private-ccache-close.yml, apply: {tags: [always]}}, tags: [always]}
`, 1},
		{"dedicated tempfile cache: kinit inline, ipa with the same env", `
- hosts: all
  tasks:
    - {name: tf, tempfile: {state: file}, register: cc}
    - {name: kinit, shell: 'echo pw | KRB5CCNAME="{{ cc.path }}" kinit admin'}
    - {name: same, command: {argv: [ipa, host-show, h]}, environment: {KRB5CCNAME: "FILE:{{ cc.path }}"}}
    - {name: other, command: {argv: [ipa, host-show, h]}, environment: {KRB5CCNAME: "{{ cc2.path }}"}}
    - {name: default, command: {argv: [ipa, host-show, h]}}
`, 2},
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

var ipaSubcommand = regexp.MustCompile(`^[a-z]`)

// runsIpa reports whether segs run the ipa CLI with a subcommand (not
// ipa-getcert and the other ipa-* programs).
func runsIpa(segs [][]string) bool {
	for _, seg := range segs {
		for i, tok := range seg {
			if path.Base(tok) == "ipa" && i+1 < len(seg) && ipaSubcommand.MatchString(seg[i+1]) {
				return true
			}
		}
	}
	return false
}

// ipaTasksWithoutKinit returns one message per task in doc's plays that runs
// an ipa command without an earlier kinit in its play that writes the same
// credential cache and runs under every --tags selection the task does, and
// the number of plays with a kinit.
func ipaTasksWithoutKinit(doc any) ([]string, int) {
	plays, _ := doc.([]any)
	var out []string
	checked := 0
	for _, p := range plays {
		play, _ := p.(map[string]any)
		if _, ok := play["hosts"]; !ok {
			continue
		}
		w := &krbWalker{}
		scope := ""
		if v, ok := envCache(play); ok {
			scope = ccacheScope(v)
		}
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks"} {
			w.walk(taskList(play[section]), yamlTags(play), scope, nil)
		}
		type kinit struct {
			scope string
			tags  []string
		}
		var kinits []kinit
		for _, e := range w.tasks {
			if found, _ := kinitCache(commandSegments(e.task)); found {
				kinits = append(kinits, kinit{})
			}
		}
		if len(kinits) == 0 {
			continue
		}
		checked++
		kinits = nil
		for _, e := range w.tasks {
			segs := commandSegments(e.task)
			if found, c := kinitCache(segs); found {
				s := e.scope
				if c != "" {
					s = ccacheScope(c)
				}
				kinits = append(kinits, kinit{s, e.tags})
				continue
			}
			if !runsIpa(segs) {
				continue
			}
			var same [][]string
			for _, k := range kinits {
				if k.scope == e.scope {
					same = append(same, k.tags)
				}
			}
			if len(same) == 0 {
				out = append(out, fmt.Sprintf("task %q runs ipa with credential cache %s, but no earlier kinit in its play writes that cache; run it inside the block that holds the kinit", e.name, cacheLabel(e.scope)))
				continue
			}
			if len(e.tags) == 0 {
				continue
			}
			var missing []string
			if slices.Contains(e.tags, "always") {
				if !slices.ContainsFunc(same, func(k []string) bool { return slices.Contains(k, "always") }) {
					missing = append(missing, "always")
				}
			} else {
				for _, tag := range e.tags {
					if !slices.ContainsFunc(same, func(k []string) bool { return slices.Contains(k, "always") || slices.Contains(k, tag) }) {
						missing = append(missing, tag)
					}
				}
			}
			if len(missing) > 0 {
				out = append(out, fmt.Sprintf("task %q runs ipa, but no earlier kinit in its play runs under --tags %s; tag a kinit always or with those tags", e.name, strings.Join(missing, ",")))
			}
		}
	}
	return out, checked
}

func cacheLabel(scope string) string {
	if scope == "" {
		return "(the default cache)"
	}
	return scope
}
