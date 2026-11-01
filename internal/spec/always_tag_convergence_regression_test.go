package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// alwaysTagConvergenceAllowlist lists the always-tagged command/shell/raw/
// script/tempfile tasks that still report changed on every run, keyed
// `<playbook under playbooks/apply>::<task name>` (a task reached through an
// include is `<playbook>::<include name> -> <task name>`). It holds two
// entries. An entry needs a reason, and fails the test once its task no
// longer violates the invariant, so a fix cannot leave a stale exemption
// behind.
var alwaysTagConvergenceAllowlist = map[string]string{
	"agent-controller-apply.yml::Step 4: back up state.db before an upgrade (SQLite consistent snapshot via VACUUM INTO)": "" +
		"same shape detection-engine had before kjelly/pilot#190: Steps 3-5 are `always` and Step 4 is changed_when: true. " +
		"agent-controller is not imported by site.yml (contract site.include: false), so a pilot deploy --limit dependency " +
		"expansion cannot reach it; the reachable trigger is a tag-scoped single-component deploy that does not select Step 6, " +
		"which still takes the backup on a stale binary and changes it on every apply; " +
		"tracked by https://github.com/kjelly/pilot/issues/195, remove this entry when #195 lands",
	"freeipa-realm-replacement-apply.yml::Realm replacement — snapshot old client trust before mutation": "" +
		"one-off migration: it refuses to run again once its prior-state file exists (the `Gate: prior migration state " +
		"must be absent` assert), so there is no second apply to keep at changed=0, and it is not imported by site.yml",
}

// convergenceViolation is one always-run task that cannot converge.
type convergenceViolation struct {
	// Key is `<playbook>::<task name>`, the allowlist key.
	Key string
	// Why names the module and the invariant, for the failure message.
	Why string
}

// convergenceScan is what scanAlwaysTaggedConvergence found in one playbook.
type convergenceScan struct {
	Violations []convergenceViolation
	// Checked counts the always-run command/shell/raw/script/tempfile tasks
	// examined, and ViaInclude those of them reached through an include; the
	// real-repo test requires both to be well above zero so a broken walker
	// cannot pass by finding nothing.
	Checked, ViaInclude int
}

// TestRegression_AlwaysTaggedTasksConverge is a repo-wide lint over
// playbooks/apply/*.yml and the task files they include. It locks the class
// behind kjelly/pilot#189, "always-tagged non-convergent mutation".
//
// A task tagged `always` runs under every --tags selection, including a
// `pilot deploy --limit` run where the host is only pulled in by dependency
// expansion and the component was not selected: site.yml still imports the
// component's play for that host, and Ansible runs its `always` tasks even
// though no other task of the play is selected (cmd/pilot/cmd/deploy.go
// synthesizes --tags from the selected components). When such a task reports
// changed on every run, the second apply of pilot's idempotency check can
// never see changed=0, because the fact that would make the task skip
// (detection-engine's `detection_engine_is_upgrade`) can only clear through a
// task the same --tags did not select. detection-engine's Step 4 backed up
// state.db with `changed_when: true` under `always` and failed every
// delivery that touched that host (#189); #190 and #203 re-tagged Steps 3-5e
// with Step 6's tag, so they run exactly when the binary is replaced.
// TestRegression_AlwaysTaggedTasksHaveAllPrerequisitesAlways,
// TestRegression_RescueRunsWheneverItsBlockDoes,
// TestRegression_TaggedTasksReadOnlyWhatTheirTagsSet,
// TestRegression_PreTaskGatesRunUnderApplyTags and
// TestRegression_NoUntaggedChecksInTaggedPlays all still passed with the
// pre-#190 tags put back: none of them looks at what an `always` task
// reports.
//
// The invariant: every task Ansible runs under any --tags selection because
// it is tagged `always` (its own tag, its block's, its play's or an
// include's `apply`), in a main task list or a block's `always:` section but
// not in a `rescue:`, must report changed only when it changed something.
//   - command/shell/raw/script must declare a changed_when that is not
//     literally true (no changed_when counts: the default is changed on
//     every run; an expression or false is fine);
//   - tempfile must declare changed_when: false (it creates a new path on
//     every run).
//
// The lint models only those modules. file, copy, service, systemd,
// docker_container and any other module whose changed result could be true on
// every run are not checked by it; a one-off sweep of the 882 always-run
// tasks in playbooks/apply (2026-11-01, during the #189 review) found no live
// instance.
//
// A `rescue:` only runs after a failure, so it cannot break the second
// apply. agent-controller's Step 4 has the same shape detection-engine had
// and is tracked by #195; it is the first of two allowlist entries.
func TestRegression_AlwaysTaggedTasksConverge(t *testing.T) {
	files, err := filepath.Glob("../../playbooks/apply/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 30 {
		t.Fatalf("found only %d apply playbooks", len(files))
	}
	sort.Strings(files)
	found := map[string]int{}
	checked, viaInclude := 0, 0
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		scan, err := scanAlwaysTaggedConvergence(filepath.Base(path), raw, filepath.Dir(path))
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(path), err)
			continue
		}
		checked += scan.Checked
		viaInclude += scan.ViaInclude
		for _, v := range scan.Violations {
			found[v.Key]++
			reason, allowed := alwaysTagConvergenceAllowlist[v.Key]
			switch {
			case found[v.Key] > 1:
				t.Errorf("%s: task name is used by more than one violating task; an allowlist key must identify one task, rename one", v.Key)
			case allowed:
				if strings.TrimSpace(reason) == "" {
					t.Errorf("alwaysTagConvergenceAllowlist[%q] has no reason", v.Key)
				}
			default:
				t.Errorf("%s: %s", v.Key, v.Why)
			}
		}
	}
	keys := make([]string, 0, len(alwaysTagConvergenceAllowlist))
	for key := range alwaysTagConvergenceAllowlist {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		playbook, _, _ := strings.Cut(key, "::")
		if _, err := os.Stat(filepath.Join("../../playbooks/apply", playbook)); err != nil {
			t.Errorf("alwaysTagConvergenceAllowlist: %s: %v", key, err)
		}
		if found[key] == 0 {
			t.Errorf("%s: no longer an always-tagged task that reports changed on every run; remove it from alwaysTagConvergenceAllowlist", key)
		}
	}
	// 0 would mean the walker stopped reaching tasks. On 2026-11-01 it
	// examined 91, 42 of them through includes (a separate scan of the same
	// YAML counted the same).
	if checked < 60 || viaInclude < 20 {
		t.Fatalf("examined %d always-run command/shell/tempfile tasks (%d through includes); the scan is broken", checked, viaInclude)
	}
}

// writeConvergenceTaskFiles writes the task files the synthetic playbooks of
// the tests below include, under <dir>/tasks, and returns <dir>:
//   - child.yml: an untagged command with changed_when: true;
//   - child-always.yml: the same command tagged `always`;
//   - outer.yml: an untagged include of child-always.yml named `inner`, to
//     see whether a line inherits an enclosing include's `apply` tags;
//   - chain0.yml ... chain7.yml: chainN.yml holds an include line named `cN`
//     (no tags) of chain<N+1>.yml, and chain7.yml an always-tagged command
//     named `leaf` with changed_when: true. With `always` apply tags on each
//     hop the chain reaches 7 includes deep from chain0 and 6 from chain2.
func writeConvergenceTaskFiles(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tasks"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"child.yml":        "- name: child\n  ansible.builtin.command: {argv: [x]}\n  changed_when: true\n",
		"child-always.yml": "- name: child\n  tags: [always]\n  ansible.builtin.command: {argv: [x]}\n  changed_when: true\n",
		"outer.yml":        "- name: inner\n  ansible.builtin.include_tasks: child-always.yml\n",
		"chain7.yml":       "- name: leaf\n  tags: [always]\n  ansible.builtin.command: {argv: [x]}\n  changed_when: true\n",
	}
	for i := 0; i < 7; i++ {
		files[fmt.Sprintf("chain%d.yml", i)] = fmt.Sprintf("- name: c%d\n  tags: [always]\n  ansible.builtin.include_tasks: {file: chain%d.yml, apply: {tags: [always]}}\n", i, i+1)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, "tasks", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestFindAlwaysTaggedNonConvergent checks scanAlwaysTaggedConvergence
// against synthetic playbooks, each case asserting the exact violation keys:
// the pre-#190 shape is flagged, the same tasks under a row tag, in a
// rescue or with a real changed_when are not, and the tag rules of
// block/always:/include_tasks/import_tasks decide what counts as always-run.
func TestFindAlwaysTaggedNonConvergent(t *testing.T) {
	dir := writeConvergenceTaskFiles(t)
	const (
		backupAlways = `
    - name: Step 4 backup
      tags: [always]
      ansible.builtin.command: {argv: [bin, db, backup]}
      changed_when: true
    - name: Step 3e tempdir
      tags: [always]
      ansible.builtin.tempfile: {state: directory, prefix: apply-}
`
		pb = "p.yml::"
	)
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"the pre-#190 shape: an always command with changed_when: true and an always tempfile", "- hosts: all\n  tasks:" + backupAlways,
			[]string{pb + "Step 3e tempdir", pb + "Step 4 backup"}},
		{"the same tasks under a row tag (the #190 fix)", "- hosts: all\n  tasks:" + strings.ReplaceAll(backupAlways, "[always]", "[detection-engine-C1]"), nil},
		{"the same tasks, untagged", "- hosts: all\n  tasks:" + strings.ReplaceAll(backupAlways, "      tags: [always]\n", ""), nil},
		{"always command with no changed_when at all", `
- hosts: all
  tasks:
    - {name: probe, tags: [always], ansible.builtin.command: {argv: [x]}}
`, []string{pb + "probe"}},
		{"always command with a conditional changed_when", `
- hosts: all
  tasks:
    - name: probe
      tags: [always]
      ansible.builtin.command: {argv: [x]}
      register: r
      changed_when: "'changed' in r.stdout"
`, nil},
		{"always command and shell with changed_when: false", `
- hosts: all
  tasks:
    - {name: probe, tags: [always], ansible.builtin.command: {argv: [x]}, changed_when: false}
    - {name: probe2, tags: [always], shell: x, changed_when: false}
`, nil},
		{"always tempfile with changed_when: false", `
- hosts: all
  tasks:
    - {name: tmp, tags: [always], ansible.builtin.tempfile: {state: directory}, changed_when: false}
`, nil},
		{"always tempfile with a conditional changed_when still needs false", `
- hosts: all
  tasks:
    - {name: tmp, tags: [always], tempfile: {state: directory}, changed_when: "x | bool"}
`, []string{pb + "tmp"}},
		{"changed_when: yes and a string true are literal true", `
- hosts: all
  tasks:
    - {name: a, tags: [always], command: x, changed_when: yes}
    - {name: b, tags: [always], ansible.builtin.shell: x, changed_when: "true"}
    - {name: c, tags: [always], raw: x, changed_when: "{{ true }}"}
    - {name: d, tags: [always], ansible.builtin.script: x.sh, changed_when: [true, True]}
    - {name: e, tags: [always], command: x, changed_when: [true, "r.rc == 0"]}
`, []string{pb + "a", pb + "b", pb + "c", pb + "d"}},
		{"rescue with changed_when: true is not flagged", `
- hosts: all
  tasks:
    - block:
        - {name: mutate, tags: [C1], copy: {src: a, dest: b}}
      rescue:
        - {name: restore, tags: [always], ansible.builtin.command: {argv: [x]}, changed_when: true}
        - {name: tmp, tags: [always], ansible.builtin.tempfile: {state: directory}}
`, nil},
		{"a block's always: section is flagged", `
- hosts: all
  tasks:
    - block:
        - {name: mutate, tags: [C1], copy: {src: a, dest: b}}
      always:
        - {name: cleanup, tags: [always], ansible.builtin.command: {argv: [x]}, changed_when: true}
`, []string{pb + "cleanup"}},
		{"an always: section inside a rescue is still a rescue", `
- hosts: all
  tasks:
    - block:
        - {name: mutate, tags: [C1], copy: {src: a, dest: b}}
      rescue:
        - block:
            - {name: inner, tags: [always], command: x}
          always:
            - {name: inner cleanup, tags: [always], command: x}
`, nil},
		{"always inherited from the enclosing block, the play and an alias", `
- hosts: all
  tasks:
    - tags: [always]
      block:
        - {name: from block, command: x}
- hosts: all
  tags: [always]
  tasks:
    - {name: from play, command: x}
- hosts: all
  vars: {t: &alwaystags [always]}
  tasks:
    - {name: from alias, tags: *alwaystags, command: x}
`, []string{pb + "from alias", pb + "from block", pb + "from play"}},
		{"always and the row tag together still run under every selection", `
- hosts: all
  tasks:
    - {name: gate, tags: [always, C2], command: x, changed_when: true}
`, []string{pb + "gate"}},
		{"pre_tasks and post_tasks are scanned too", `
- hosts: all
  pre_tasks:
    - {name: early, tags: [always], command: x}
  post_tasks:
    - {name: late, tags: [always], command: x}
`, []string{pb + "early", pb + "late"}},
		{"include_tasks tagged C1 with apply always: the line is not selected by every --tags", `
- hosts: all
  tasks:
    - name: inc
      tags: [C1]
      ansible.builtin.include_tasks: {file: tasks/child.yml, apply: {tags: [always]}}
`, nil},
		{"include_tasks tagged always with apply always reaches its children", `
- hosts: all
  tasks:
    - name: inc
      tags: [always]
      ansible.builtin.include_tasks: {file: tasks/child.yml, apply: {tags: [always]}}
`, []string{pb + "inc -> child"}},
		{"include_tasks tagged always without apply: the children do not inherit the line's tags", `
- hosts: all
  tasks:
    - name: inc
      tags: [always]
      ansible.builtin.include_tasks: tasks/child.yml
`, nil},
		{"include_tasks tagged always, child tagged always itself", `
- hosts: all
  tasks:
    - name: inc
      tags: [always]
      ansible.builtin.include_tasks: tasks/child-always.yml
`, []string{pb + "inc -> child"}},
		{"include_tasks tagged C1, child tagged always itself: the line is not selected", `
- hosts: all
  tasks:
    - name: inc
      tags: [C1]
      ansible.builtin.include_tasks: tasks/child-always.yml
`, nil},
		{"include_tasks reached through an always block inherits only apply tags", `
- hosts: all
  tasks:
    - tags: [always]
      block:
        - name: inc
          ansible.builtin.include_tasks: tasks/child.yml
`, nil},
		{"include_tasks inside an always block, with apply always", `
- hosts: all
  tasks:
    - tags: [always]
      block:
        - name: inc
          ansible.builtin.include_tasks: {file: tasks/child.yml, apply: {tags: [always]}}
`, []string{pb + "inc -> child"}},
		{"include_tasks inside a rescue", `
- hosts: all
  tasks:
    - block:
        - {name: mutate, tags: [C1], copy: {src: a, dest: b}}
      rescue:
        - name: inc
          tags: [always]
          ansible.builtin.include_tasks: {file: tasks/child.yml, apply: {tags: [always]}}
`, nil},
		{"import_tasks under an always block", `
- hosts: all
  tasks:
    - tags: [always]
      block:
        - name: imp
          ansible.builtin.import_tasks: tasks/child.yml
`, []string{pb + "imp -> child"}},
		{"import_tasks tagged always", `
- hosts: all
  tasks:
    - {name: imp, tags: [always], import_tasks: tasks/child.yml}
`, []string{pb + "imp -> child"}},
		{"import_tasks tagged C1: children inherit C1, not always", `
- hosts: all
  tasks:
    - {name: imp, tags: [C1], import_tasks: tasks/child.yml}
`, nil},
		{"import_tasks tagged C1, child tagged always itself", `
- hosts: all
  tasks:
    - {name: imp, tags: [C1], import_tasks: tasks/child-always.yml}
`, []string{pb + "imp -> child"}},
		{"a nested include line inherits the enclosing include's apply tags", `
- hosts: all
  tasks:
    - name: outer
      tags: [always]
      ansible.builtin.include_tasks: {file: tasks/outer.yml, apply: {tags: [always]}}
`, []string{pb + "outer -> inner -> child"}},
		{"a nested include line of a file included without apply is not selected by every --tags", `
- hosts: all
  tasks:
    - name: outer
      tags: [always]
      ansible.builtin.include_tasks: tasks/outer.yml
`, nil},
		{"a comma separated tags string", `
- hosts: all
  tasks:
    - {name: csv, tags: "always, x", command: x, changed_when: true}
    - {name: csv without always, tags: "x, y", command: x, changed_when: true}
`, []string{pb + "csv"}},
		{"an alias as an element of the tags list", `
- hosts: all
  vars: {t: &a always}
  tasks:
    - {name: aliased element, tags: [*a], command: x}
    - {name: plain element, tags: [x], command: x}
`, []string{pb + "aliased element"}},
		{"six includes deep is still followed", `
- hosts: all
  tasks:
    - name: start
      tags: [always]
      ansible.builtin.include_tasks: {file: tasks/chain2.yml, apply: {tags: [always]}}
`, []string{pb + "start -> c2 -> c3 -> c4 -> c5 -> c6 -> leaf"}},
		{"unnamed task is keyed by its line", `
- hosts: all
  tasks:
    - tags: [always]
      command: x
`, []string{pb + "line 4"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scan, err := scanAlwaysTaggedConvergence("p.yml", []byte(tc.yaml), dir)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, v := range scan.Violations {
				got = append(got, v.Key)
				if v.Why == "" {
					t.Errorf("%s: no reason given", v.Key)
				}
			}
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("violations = %q, want %q", got, want)
			}
		})
	}
}

// TestAlwaysTaggedConvergenceFailsClosed checks that the scan reports what
// it cannot follow instead of passing over it: a task file it cannot read, a
// templated include of an always-run line, includes nested deeper than the
// depth limit, and the constructs it does not model (roles, import_playbook,
// action:, merge keys, the legacy spellings of include_tasks/import_tasks and
// `include:`).
func TestAlwaysTaggedConvergenceFailsClosed(t *testing.T) {
	dir := writeConvergenceTaskFiles(t)
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"missing task file", `
- hosts: all
  tasks:
    - {name: inc, tags: [always], include_tasks: {file: tasks/nope.yml, apply: {tags: [always]}}}
`, "tasks/nope.yml"},
		{"templated include of an always-run line", `
- hosts: all
  tasks:
    - {name: inc, tags: [always], include_tasks: "{{ which }}.yml"}
`, "templated"},
		{"role", "- hosts: all\n  roles: [common]\n", "roles"},
		{"import_playbook", "- import_playbook: other.yml\n", "import_playbook"},
		{"include_role", `
- hosts: all
  tasks:
    - {name: r, tags: [always], ansible.builtin.include_role: {name: common}}
`, "include_role"},
		{"action", `
- hosts: all
  tasks:
    - {name: a, tags: [always], action: command x}
`, "action"},
		{"ansible.legacy.include_tasks", `
- hosts: all
  tasks:
    - {name: i, tags: [always], ansible.legacy.include_tasks: {file: tasks/child.yml, apply: {tags: [always]}}}
`, "ansible.legacy.include_tasks"},
		{"ansible.legacy.import_tasks", `
- hosts: all
  tasks:
    - {name: i, tags: [always], ansible.legacy.import_tasks: tasks/child.yml}
`, "ansible.legacy.import_tasks"},
		{"legacy include:", `
- hosts: all
  tasks:
    - {name: i, tags: [always], include: tasks/child.yml}
`, "uses include,"},
		{"includes nested deeper than 6", `
- hosts: all
  tasks:
    - name: start
      tags: [always]
      ansible.builtin.include_tasks: {file: tasks/chain1.yml, apply: {tags: [always]}}
`, "deeper than 6"},
		{"merge key", `
- hosts: all
  tasks:
    - name: a
      <<: {tags: [always]}
      command: x
`, "merge key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := scanAlwaysTaggedConvergence("p.yml", []byte(tc.yaml), dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %q", err, tc.want)
			}
		})
	}
}

// TestAlwaysTaggedConvergenceFlagsThePre190Playbook puts the pre-#190 tags
// back on the real detection-engine playbook, in memory: every Step 3-5e
// task goes from Step 6's tag to `always`. The scan must name the two tasks
// #189 was about, Step 4 (changed_when: true) and Step 3e (a tempfile). The
// playbook as committed has neither.
func TestAlwaysTaggedConvergenceFlagsThePre190Playbook(t *testing.T) {
	const playbook = "detection-engine-apply.yml"
	dir := "../../playbooks/apply"
	raw, err := os.ReadFile(filepath.Join(dir, playbook))
	if err != nil {
		t.Fatal(err)
	}
	const rowTag = "tags: [detection-engine-C1]"
	if strings.Count(string(raw), rowTag) < 15 {
		t.Fatalf("%s no longer tags Steps 3-6 with %q; update this test", playbook, rowTag)
	}
	keysOf := func(src string) map[string]bool {
		scan, err := scanAlwaysTaggedConvergence(playbook, []byte(src), dir)
		if err != nil {
			t.Fatal(err)
		}
		keys := map[string]bool{}
		for _, v := range scan.Violations {
			keys[v.Key] = true
		}
		return keys
	}
	const (
		step4 = playbook + "::Step 4: back up state.db before an upgrade (SQLite consistent snapshot via VACUUM INTO, spec §26/§40)"
		step3 = playbook + "::Step 3e: allocate a private directory for this upgrade only"
	)
	if committed := keysOf(string(raw)); committed[step4] || committed[step3] {
		t.Fatalf("the committed %s already has an always-tagged non-convergent backup: %v", playbook, committed)
	}
	reverted := keysOf(strings.ReplaceAll(string(raw), rowTag, "tags: [always]"))
	for _, want := range []string{step4, step3} {
		if !reverted[want] {
			t.Errorf("with the pre-#190 `always` tags back, the scan does not flag %q; flagged: %v", want, reverted)
		}
	}
}

// convergenceKind is what a module needs from its changed_when.
type convergenceKind int

const (
	kindOther    convergenceKind = iota
	kindCommand                  // command, shell, raw, script
	kindTempfile                 // tempfile
)

// convergenceModules maps a task's module key to its kind, with and without
// the collection prefix: the modules whose changed result the #189 invariant
// constrains (command-like modules report changed on every run unless
// changed_when says otherwise; tempfile creates a new path every run).
var convergenceModules = func() map[string]convergenceKind {
	m := map[string]convergenceKind{}
	for _, name := range []string{"command", "shell", "raw", "script"} {
		m[name] = kindCommand
		m["ansible.builtin."+name] = kindCommand
		m["ansible.legacy."+name] = kindCommand
	}
	m["tempfile"] = kindTempfile
	m["ansible.builtin.tempfile"] = kindTempfile
	m["ansible.legacy.tempfile"] = kindTempfile
	return m
}()

// convergenceUnsupported are the keys the scan does not model. Meeting one
// is an error, not a pass: a role, an imported playbook, an action: string,
// a merge key or a legacy spelling of an include could hide an always-run
// task from it.
var convergenceUnsupported = func() map[string]string {
	m := map[string]string{
		"roles": "roles", "action": "action:", "local_action": "local_action:", "<<": "merge key (<<:)",
		// The removed legacy `include:` loaded a task file like include_tasks.
		"include": "include", "ansible.builtin.include": "ansible.builtin.include", "ansible.legacy.include": "ansible.legacy.include",
		// includedFile follows include_tasks/import_tasks and ansible.builtin.*
		// only; the legacy collection spelling would be skipped silently, so it
		// is refused like the other spellings (the module table above accepts
		// ansible.legacy.command and tempfile).
		"ansible.legacy.include_tasks": "ansible.legacy.include_tasks", "ansible.legacy.import_tasks": "ansible.legacy.import_tasks",
	}
	for _, name := range []string{"import_playbook", "include_role", "import_role"} {
		for _, prefix := range []string{"", "ansible.builtin.", "ansible.legacy."} {
			m[prefix+name] = prefix + name
		}
	}
	return m
}()

// convergenceCtx is the state of one task list during the walk.
type convergenceCtx struct {
	tags    map[string]bool // inherited from the play, enclosing blocks and an include's apply
	rescue  bool            // inside a rescue: only runs after a failure
	reach   bool            // every include on the way is selected by every --tags
	via     string          // `<include name> -> ` per include on the way, for the key
	fileDir string          // directory the file being walked lives in
	depth   int             // include nesting
}

// convergenceWalker carries the state of one scanAlwaysTaggedConvergence run
// (kjelly/pilot#189).
type convergenceWalker struct {
	playbook string
	baseDir  string
	scan     convergenceScan
}

// scanAlwaysTaggedConvergence walks one playbook's plays, following
// include_tasks/import_tasks into the task files, and returns the tasks that
// Ansible runs under every --tags selection and that cannot converge (see
// TestRegression_AlwaysTaggedTasksConverge). playbook is the key prefix and
// dir the directory the playbook's relative include paths resolve against
// (an included file's own includes resolve against its directory first).
//
// A task is always-run when its effective tags contain `always` and every
// include on the way to it is selected by every --tags. The tag rules, as
// includedTaskTags in tagged_prerequisite_regression_test.go models them for
// setters (the two agree on the `always` question; this walk carries the
// context down instead of folding tag sets back up, so an include nested in
// an `apply: {tags: [always]}` file inherits the apply tag like any other
// task of that file):
//   - block, rescue and always: sections inherit the block's tags;
//   - import_tasks is static: its children inherit the line's tags, and a
//     child tagged `always` runs whatever the line's tags are;
//   - include_tasks is dynamic: its children inherit only `apply` tags, and
//     run only if the include line itself is selected, so they are
//     always-run only when the line is `always` AND their apply/own tags
//     contain `always`;
//   - a rescue stays a rescue for everything below it, includes included.
//
// includedFile reads `apply: {tags: ...}` without following YAML aliases;
// the repo's only aliases are in dns-apply.yml's task tags, which this walk
// does follow.
func scanAlwaysTaggedConvergence(playbook string, raw []byte, dir string) (convergenceScan, error) {
	w := &convergenceWalker{playbook: playbook, baseDir: dir}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return w.scan, err
	}
	if len(doc.Content) == 0 {
		return w.scan, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.SequenceNode {
		return w.scan, fmt.Errorf("%s: not a list of plays", playbook)
	}
	for _, item := range root.Content {
		play := yamlDeref(item)
		if play == nil || play.Kind != yaml.MappingNode {
			continue
		}
		if err := w.unsupported(play); err != nil {
			return w.scan, err
		}
		ctx := convergenceCtx{tags: convergenceTagSet(yamlField(play, "tags")), reach: true, fileDir: dir}
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks"} {
			if err := w.taskList(yamlField(play, section), ctx); err != nil {
				return w.scan, err
			}
		}
	}
	sort.Slice(w.scan.Violations, func(i, j int) bool { return w.scan.Violations[i].Key < w.scan.Violations[j].Key })
	return w.scan, nil
}

// taskList walks one task list, recursing into block/rescue/always and into
// included task files.
func (w *convergenceWalker) taskList(seq *yaml.Node, ctx convergenceCtx) error {
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil
	}
	for _, entry := range seq.Content {
		item := yamlDeref(entry)
		if item == nil || item.Kind != yaml.MappingNode {
			continue
		}
		if err := w.unsupported(item); err != nil {
			return err
		}
		eff := unionTags(ctx.tags, convergenceTagSet(yamlField(item, "tags")))
		if block := yamlField(item, "block"); block != nil {
			inner := ctx
			inner.tags = eff
			if err := w.taskList(block, inner); err != nil {
				return err
			}
			inRescue := inner
			inRescue.rescue = true
			if err := w.taskList(yamlField(item, "rescue"), inRescue); err != nil {
				return err
			}
			if err := w.taskList(yamlField(item, "always"), inner); err != nil {
				return err
			}
			continue
		}
		if err := w.include(item, eff, ctx); err != nil {
			return err
		}
		if !ctx.rescue && ctx.reach && eff["always"] {
			w.check(item, ctx)
		}
	}
	return nil
}

// include follows an include_tasks/import_tasks task into its file. Nothing
// is followed below a rescue (not checked) or below an include_tasks line
// that is not selected by every --tags (its children cannot be always-run).
func (w *convergenceWalker) include(item *yaml.Node, eff map[string]bool, ctx convergenceCtx) error {
	if ctx.rescue || !ctx.reach {
		return nil
	}
	name := taskDisplayName(item)
	file, apply, static := includedFile(item)
	if file == "" {
		for _, key := range []string{"import_tasks", "ansible.builtin.import_tasks", "include_tasks", "ansible.builtin.include_tasks"} {
			// An include line that is not always-selected cannot lead to an
			// always-run child; an import's children can, so its path matters.
			if yamlField(item, key) != nil && (strings.HasSuffix(key, "import_tasks") || eff["always"]) {
				return fmt.Errorf("%s: %s of %q has a templated or missing file name; the scan cannot follow it", w.playbook, key, name)
			}
		}
		return nil
	}
	child := convergenceCtx{reach: true, via: ctx.via + name + " -> ", depth: ctx.depth + 1}
	if static {
		child.tags = eff
	} else {
		child.tags = apply
		child.reach = eff["always"]
	}
	if !child.reach {
		return nil
	}
	if child.depth > 6 {
		return fmt.Errorf("%s: includes nested deeper than 6 at %q", w.playbook, name)
	}
	var body []byte
	for _, d := range []string{ctx.fileDir, w.baseDir} {
		path := filepath.Join(d, file)
		if b, err := os.ReadFile(path); err == nil {
			body, child.fileDir = b, filepath.Dir(path)
			break
		}
	}
	if body == nil {
		return fmt.Errorf("%s: %q includes %s, which cannot be read from %s or %s", w.playbook, name, file, ctx.fileDir, w.baseDir)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("%s: %s: %w", w.playbook, file, err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.SequenceNode {
		return nil
	}
	return w.taskList(doc.Content[0], child)
}

// check records item if it is an always-run task that cannot converge.
func (w *convergenceWalker) check(item *yaml.Node, ctx convergenceCtx) {
	module, kind := "", kindOther
	for i := 0; i+1 < len(item.Content); i += 2 {
		if k, ok := convergenceModules[item.Content[i].Value]; ok {
			module, kind = item.Content[i].Value, k
			break
		}
	}
	if kind == kindOther {
		return
	}
	w.scan.Checked++
	if ctx.depth > 0 {
		w.scan.ViaInclude++
	}
	state := changedWhenState(yamlField(item, "changed_when"))
	var problem string
	switch {
	case kind == kindCommand && state == changedWhenAbsent:
		problem = "has no changed_when, so it reports changed on every run"
	case kind == kindCommand && state == changedWhenTrue:
		problem = "has changed_when: true, so it reports changed on every run"
	case kind == kindTempfile && state != changedWhenFalse:
		problem = "creates a new path on every run and does not declare changed_when: false"
	default:
		return
	}
	name := taskDisplayName(item)
	w.scan.Violations = append(w.scan.Violations, convergenceViolation{
		Key: w.playbook + "::" + ctx.via + name,
		Why: fmt.Sprintf("line %d: %s task is always-tagged (it runs under every --tags, including a pilot deploy --limit run that only pulls this host in through a dependency) and %s, so the second apply can never be changed=0 (kjelly/pilot#189). Tag it with the tag of the task it prepares for, as detection-engine's Steps 3-5 carry Step 6's, or give it a changed_when that is a real condition, or false",
			item.Line, module, problem),
	})
}

// unsupported returns an error if m uses a construct the scan does not model.
func (w *convergenceWalker) unsupported(m *yaml.Node) error {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if what, ok := convergenceUnsupported[m.Content[i].Value]; ok {
			return fmt.Errorf("%s: line %d uses %s, which the always-tag convergence scan does not follow; extend scanAlwaysTaggedConvergence before using it", w.playbook, m.Content[i].Line, what)
		}
	}
	return nil
}

// changedWhen is what a task's changed_when says about whether it reports
// changed.
type changedWhen int

const (
	changedWhenAbsent changedWhen = iota // the module's own changed result: always for command
	changedWhenTrue                      // literally true: changed every run
	changedWhenFalse                     // literally false: never changed
	changedWhenExpr                      // a condition
)

// changedWhenState classifies a changed_when value. A list is an AND: one
// false makes it never changed, all true makes it always changed.
func changedWhenState(n *yaml.Node) changedWhen {
	if n == nil || n.Tag == "!!null" {
		return changedWhenAbsent
	}
	switch n.Kind {
	case yaml.SequenceNode:
		if len(n.Content) == 0 {
			return changedWhenAbsent
		}
		allTrue := true
		for _, c := range n.Content {
			switch changedWhenState(yamlDeref(c)) {
			case changedWhenFalse:
				return changedWhenFalse
			case changedWhenTrue:
			default:
				allTrue = false
			}
		}
		if allTrue {
			return changedWhenTrue
		}
		return changedWhenExpr
	case yaml.ScalarNode:
		v := strings.ToLower(strings.TrimSpace(n.Value))
		if strings.HasPrefix(v, "{{") && strings.HasSuffix(v, "}}") {
			v = strings.TrimSpace(v[2 : len(v)-2])
		}
		switch v {
		case "true", "yes", "on", "1":
			return changedWhenTrue
		case "false", "no", "off", "0":
			return changedWhenFalse
		}
	}
	return changedWhenExpr
}

// yamlDeref follows YAML aliases (a bounded number of hops).
func yamlDeref(n *yaml.Node) *yaml.Node {
	for hops := 0; n != nil && n.Kind == yaml.AliasNode && hops < 8; hops++ {
		n = n.Alias
	}
	return n
}

// yamlField returns the value under key in mapping m, following aliases, or
// nil.
func yamlField(m *yaml.Node, key string) *yaml.Node {
	m = yamlDeref(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return yamlDeref(m.Content[i+1])
		}
	}
	return nil
}

// convergenceTagSet reads a `tags:` value: a list, a string or a comma
// separated string, each possibly behind an alias.
func convergenceTagSet(n *yaml.Node) map[string]bool {
	out := map[string]bool{}
	var add func(n *yaml.Node)
	add = func(n *yaml.Node) {
		n = yamlDeref(n)
		if n == nil {
			return
		}
		switch n.Kind {
		case yaml.ScalarNode:
			for _, tag := range strings.Split(n.Value, ",") {
				if tag = strings.TrimSpace(tag); tag != "" {
					out[tag] = true
				}
			}
		case yaml.SequenceNode:
			for _, c := range n.Content {
				add(c)
			}
		}
	}
	add(n)
	return out
}

// unionTags returns a new set with the tags of both a and b.
func unionTags(a, b map[string]bool) map[string]bool {
	out := make(map[string]bool, len(a)+len(b))
	for t := range a {
		out[t] = true
	}
	for t := range b {
		out[t] = true
	}
	return out
}

// taskDisplayName is a task's name, or `line <n>` for an unnamed one.
func taskDisplayName(item *yaml.Node) string {
	if n := yamlField(item, "name"); n != nil && n.Value != "" {
		return n.Value
	}
	return fmt.Sprintf("line %d", item.Line)
}
