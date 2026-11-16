package spec

import (
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// checkModeExecAllowlist lists the check_mode: false command/shell/raw tasks that
// run an installed path under --check on purpose, keyed
// `<file under playbooks/>::<task name>`. An entry needs a reason, and fails the
// test once its task no longer violates the invariant, so a fix cannot leave a
// stale exemption behind.
var checkModeExecAllowlist = map[string]string{
	"apply/log-server-apply.yml::Step 6a: Check whether rsyslog started before the receiver config was last written": "" +
		"the installed helper is only reached behind `test -f /etc/rsyslog.d/pilot-relp-receiver/profile.json`, which " +
		"tasks/rsyslog-relp-tls.yml writes after it copies the helper; under --check on a fresh host the profile does not " +
		"exist yet (the copy only simulates), so the branch is not taken and the shell goes on to the timestamp comparison",
}

// checkModeCtx is what a task inherits from its enclosing blocks, plays and includes.
type checkModeCtx struct {
	// guarded: an enclosing `when` is false under --check (`not ansible_check_mode` is one of its
	// conjuncts), so nothing below it runs in a preview.
	guarded bool
	// noCheck: `check_mode: false` is in effect, so command/shell/raw run for real under --check
	// (without it Ansible only simulates them: "skipped, running in check mode").
	noCheck bool
}

type checkModeExecFinding struct {
	// Key is `<file under playbooks/>::<task name>`, the allowlist key.
	Key string
	// Why states the invariant for the failure message.
	Why string
}

type checkModeExecScan struct {
	Findings []checkModeExecFinding
	// Examined counts the command/shell/raw tasks that run under --check, and
	// ExaminedIn how many of them each file contributed (a task file reached through
	// several include sites counts once per site); the real-repo test requires both
	// to be well above zero so a broken walker cannot pass by finding nothing.
	Examined   int
	ExaminedIn map[string]int
}

var (
	checkModeExecModules   = []string{"ansible.builtin.command", "command", "ansible.builtin.shell", "shell", "ansible.builtin.raw", "raw"}
	checkModeIncludeKeys   = []string{"ansible.builtin.include_tasks", "include_tasks", "ansible.builtin.import_tasks", "import_tasks"}
	checkModeInstallers    = []string{"ansible.builtin.copy", "copy", "ansible.builtin.template", "template", "ansible.builtin.get_url", "get_url"}
	checkModeInstalledDirs = []string{"/usr/local/sbin/", "/usr/local/libexec/", "/usr/local/bin/"}
	// An absolute path in command position of a shell script: first on its line, or after a
	// control operator or keyword.
	shellCommandPosition = regexp.MustCompile(`(?m)(?:^|[;&|({]|\b(?:then|do|else|elif|exec)\b)[ \t]*(/[^\s;&|(){}'"]+)`)
	quotedAbsolutePath   = regexp.MustCompile(`['"](/[^'"\s]+)['"]`)
)

// TestRegression_CheckModeTasksNeverExecAnInstalledPath is a repo-wide lint over
// playbooks/** (plays and the task files they include). It locks the class behind
// kjelly/pilot#244's wazuh-fim-apply.yml "Admit native package policy ownership"
// task.
//
// `--check` (the L3 step of `pilot vm-target test`/`topology test`, run before any
// mutation) only simulates `copy`, `template` and the other mutating modules: on a
// fresh host nothing they would install exists. A command/shell/raw task with
// `check_mode: false` runs for real in that preview. If it names a file this
// playbook installs itself (the coordinator copied to /usr/local/sbin, a helper under
// /usr/local/libexec), the exec fails with ENOENT on every fresh node, while the same
// task passes on any host a real run already touched, which is where it was developed.
// wazuh-fim-apply.yml ran `/usr/local/sbin/pilot-wazuh-transaction agent-policy-check`
// that way; main ran the controller-shipped script for the same read.
//
// The invariant: a command/shell/raw task that executes under --check (`check_mode:
// false` on the task or an enclosing block, and no `not ansible_check_mode` conjunct
// in the `when` of the task, an enclosing block or an including task) must not exec a
// path under /usr/local/{sbin,libexec,bin}/ or one that any task in playbooks/**
// installs with copy/template/get_url. It reads through `ansible.builtin.script`
// (shipped from the controller) or a system binary instead. The exec position is the
// first word of a command, of each statement of a shell script and of a `sh -c`
// string; a computed command (`argv: "{{ [...] }}"`) is searched for quoted absolute
// paths.
//
// What it does not model: a guard that is not a `when` (an earlier `meta: end_host`
// in check mode, an assert), a `when` that mixes `ansible_check_mode` into an `or`
// (treated as no guard, so flagged), and the existence of the file itself being
// tested before the exec (the one allowlist entry, whose reason says why that holds).
func TestRegression_CheckModeTasksNeverExecAnInstalledPath(t *testing.T) {
	docs := map[string]any{}
	for _, file := range playbookFiles(t) {
		rel, err := filepath.Rel("../../playbooks", file)
		if err != nil {
			t.Fatal(err)
		}
		docs[filepath.ToSlash(rel)] = loadYAML(t, file)
	}
	scan, err := scanCheckModeInstalledExec(docs)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]int{}
	for _, f := range scan.Findings {
		found[f.Key]++
		reason, allowed := checkModeExecAllowlist[f.Key]
		switch {
		case found[f.Key] > 1:
			t.Errorf("%s: task name is used by more than one violating task; an allowlist key must identify one task, rename one", f.Key)
		case allowed:
			if strings.TrimSpace(reason) == "" {
				t.Errorf("checkModeExecAllowlist[%q] has no reason", f.Key)
			}
		default:
			t.Errorf("%s: %s", f.Key, f.Why)
		}
	}
	keys := make([]string, 0, len(checkModeExecAllowlist))
	for key := range checkModeExecAllowlist {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if found[key] == 0 {
			t.Errorf("%s: no longer a check_mode: false task that execs an installed path; remove it from checkModeExecAllowlist", key)
		}
	}
	t.Logf("examined %d check_mode: false command/shell/raw tasks that run under --check, %d findings (%d allowlisted)", scan.Examined, len(scan.Findings), len(checkModeExecAllowlist))
	if scan.Examined < 100 {
		t.Fatalf("examined only %d check_mode: false command/shell/raw tasks; the scan is broken", scan.Examined)
	}
	for _, reached := range []string{
		"apply/wazuh-fim-apply.yml",           // a play body, including pre_tasks
		"apply/wazuh-manager-apply.yml",       // the other Wazuh play
		"apply/log-server-apply.yml",          // the allowlisted task
		"apply/tasks/apt-package-install.yml", // a task file, reached through include_tasks
	} {
		if scan.ExaminedIn[reached] == 0 {
			t.Errorf("the scan examined no check_mode: false task in %s; the walker is not reaching it", reached)
		}
	}
}

// scanCheckModeInstalledExec walks every play of docs (a map of `<file under playbooks/>`
// to its parsed YAML), follows include_tasks/import_tasks into task files with what the
// include site contributes, and walks task files no include reaches as roots of their own.
// It fails closed: an include it cannot resolve, or a task list that is not a list of
// mappings, is an error, not a pass.
func scanCheckModeInstalledExec(docs map[string]any) (checkModeExecScan, error) {
	w := &checkModeWalker{docs: docs, dests: map[string]bool{}, seen: map[string]bool{}, scan: checkModeExecScan{ExaminedIn: map[string]int{}}}
	files := make([]string, 0, len(docs))
	for file := range docs {
		files = append(files, file)
	}
	sort.Strings(files)
	included := map[string]bool{}
	taskFile := map[string]bool{}
	for _, file := range files {
		list, ok := docs[file].([]any)
		if !ok {
			continue
		}
		var walkErr error
		taskFile[file] = !isPlaybookList(list)
		eachCheckModeTask(list, func(task map[string]any) {
			if dest := installedDest(task); dest != "" {
				w.dests[dest] = true
			}
			for _, key := range checkModeIncludeKeys {
				if v, ok := task[key]; ok {
					name, _ := includeFileAndApply(v)
					target, err := resolveCheckModeInclude(docs, file, name)
					if err != nil {
						walkErr = err
						return
					}
					included[target] = true
				}
			}
		})
		if walkErr != nil {
			return w.scan, walkErr
		}
	}
	for _, file := range files {
		list, ok := docs[file].([]any)
		if !ok {
			continue
		}
		if taskFile[file] {
			if !included[file] {
				if err := w.walk(file, list, checkModeCtx{}); err != nil {
					return w.scan, err
				}
			}
			continue
		}
		for _, raw := range list {
			play, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if _, isPlay := play["hosts"]; !isPlay {
				continue
			}
			ctx := checkModeCtx{}
			if v, ok := play["check_mode"]; ok {
				ctx.noCheck = v == false
			}
			for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
				if err := w.walk(file, play[section], ctx); err != nil {
					return w.scan, err
				}
			}
		}
	}
	return w.scan, nil
}

// isPlaybookList reports whether a parsed file is a playbook (a play or an import_playbook
// among its items) rather than a task file.
func isPlaybookList(list []any) bool {
	for _, raw := range list {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"hosts", "import_playbook", "ansible.builtin.import_playbook"} {
			if _, ok := item[key]; ok {
				return true
			}
		}
	}
	return false
}

type checkModeWalker struct {
	docs  map[string]any
	dests map[string]bool // literal destinations that a copy/template/get_url task installs
	seen  map[string]bool // file|guarded|noCheck already walked
	stack []string
	scan  checkModeExecScan
}

func (w *checkModeWalker) walk(file string, list any, inherited checkModeCtx) error {
	if list == nil {
		return nil
	}
	items, ok := list.([]any)
	if !ok {
		return fmt.Errorf("%s: a task list is a %T, not a list", file, list)
	}
	for _, raw := range items {
		task, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: a task list item is a %T, not a mapping", file, raw)
		}
		own := inherited
		if when, ok := task["when"]; ok && whenSkipsUnderCheckMode(when) {
			own.guarded = true
		}
		if v, ok := task["check_mode"]; ok {
			own.noCheck = v == false
		}
		for _, section := range []string{"block", "rescue", "always"} {
			if err := w.walk(file, task[section], own); err != nil {
				return err
			}
		}
		if err := w.include(file, task, inherited, own); err != nil {
			return err
		}
		for _, module := range checkModeExecModules {
			if params, ok := task[module]; ok && own.noCheck && !own.guarded {
				w.examine(file, task, module, params)
			}
		}
	}
	return nil
}

// include follows an include_tasks/import_tasks into its task file. `own` carries the
// include task's `when` and keywords, `inherited` only what its enclosing blocks give:
// a static import_tasks passes its own keywords to every imported task, a dynamic
// include_tasks passes only what `apply` names (Ansible docs; the include's own
// check_mode does not reach its tasks), and a skipped include skips its whole file.
func (w *checkModeWalker) include(file string, task map[string]any, inherited, own checkModeCtx) error {
	for _, key := range checkModeIncludeKeys {
		v, ok := task[key]
		if !ok {
			continue
		}
		name, apply := includeFileAndApply(v)
		target, err := resolveCheckModeInclude(w.docs, file, name)
		if err != nil {
			return err
		}
		child := own
		if !strings.HasSuffix(key, "import_tasks") {
			child.noCheck = inherited.noCheck
			if applied, ok := apply["check_mode"]; ok {
				child.noCheck = applied == false
			}
		}
		memo := fmt.Sprintf("%s|%t|%t", target, child.guarded, child.noCheck)
		if w.seen[memo] || slices.Contains(w.stack, target) {
			continue
		}
		w.seen[memo] = true
		w.stack = append(w.stack, target)
		err = w.walk(target, w.docs[target], child)
		w.stack = w.stack[:len(w.stack)-1]
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *checkModeWalker) examine(file string, task map[string]any, module string, params any) {
	w.scan.Examined++
	w.scan.ExaminedIn[file]++
	name, _ := task["name"].(string)
	if name == "" {
		name = "(unnamed " + module + " task)"
	}
	for _, head := range checkModeExecHeads(module, params) {
		if isInstalledPath(head, w.dests) {
			w.scan.Findings = append(w.scan.Findings, checkModeExecFinding{
				Key: file + "::" + name,
				Why: fmt.Sprintf("runs %s with check_mode: false and no `not ansible_check_mode` guard, but --check only simulates the copy that installs it, so on a fresh host the exec fails with ENOENT; read through ansible.builtin.script (files/<name>.py) or a system binary, or add `when: not ansible_check_mode`", head),
			})
			return
		}
	}
}

// eachCheckModeTask calls fn for every task below a task list or play list, descending
// into blocks, rescue and always sections.
func eachCheckModeTask(list any, fn func(task map[string]any)) {
	items, _ := list.([]any)
	for _, raw := range items {
		task, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if _, isPlay := task["hosts"]; isPlay {
			for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
				eachCheckModeTask(task[section], fn)
			}
			continue
		}
		fn(task)
		for _, section := range []string{"block", "rescue", "always"} {
			eachCheckModeTask(task[section], fn)
		}
	}
}

// installedDest returns the literal destination of a copy/template/get_url task.
func installedDest(task map[string]any) string {
	for _, module := range checkModeInstallers {
		if params, ok := task[module].(map[string]any); ok {
			if dest, ok := params["dest"].(string); ok && strings.HasPrefix(dest, "/") && !strings.Contains(dest, "{{") {
				return dest
			}
		}
	}
	return ""
}

// includeFileAndApply reads the file name and `apply:` of an include_tasks/import_tasks value.
func includeFileAndApply(v any) (string, map[string]any) {
	switch x := v.(type) {
	case string:
		return x, nil
	case map[string]any:
		name, _ := x["file"].(string)
		if name == "" {
			name, _ = x["_raw_params"].(string)
		}
		apply, _ := x["apply"].(map[string]any)
		return name, apply
	}
	return "", nil
}

// resolveCheckModeInclude finds the task file an include names: relative to the including
// file, then to its tasks/ directory, then by a unique file name anywhere in playbooks/.
func resolveCheckModeInclude(docs map[string]any, from, name string) (string, error) {
	if name == "" || strings.Contains(name, "{{") {
		return "", fmt.Errorf("%s: an include without a literal file name (%q) cannot be followed", from, name)
	}
	dir := path.Dir(from)
	for _, candidate := range []string{path.Join(dir, name), path.Join(dir, "tasks", name)} {
		if _, ok := docs[candidate]; ok {
			return candidate, nil
		}
	}
	var byBase []string
	for file := range docs {
		if path.Base(file) == path.Base(name) {
			byBase = append(byBase, file)
		}
	}
	if len(byBase) != 1 {
		return "", fmt.Errorf("%s: cannot resolve the include %q (%d files by that name)", from, name, len(byBase))
	}
	return byBase[0], nil
}

// whenSkipsUnderCheckMode reports whether a `when` (a string, or a list whose items are
// ANDed) has `not ansible_check_mode` as one of its conjuncts. An item that mixes an `or`
// in is not a guard: it can be true in a preview.
func whenSkipsUnderCheckMode(when any) bool {
	var conditions []string
	switch w := when.(type) {
	case string:
		conditions = []string{w}
	case []any:
		for _, c := range w {
			if s, ok := c.(string); ok {
				conditions = append(conditions, s)
			}
		}
	}
	for _, condition := range conditions {
		flat := strings.Join(strings.Fields(condition), " ")
		if strings.Contains(" "+flat+" ", " or ") {
			continue
		}
		for _, term := range strings.Split(flat, " and ") {
			switch strings.TrimSpace(strings.Trim(term, "() ")) {
			case "not ansible_check_mode", "ansible_check_mode == false", "ansible_check_mode is false", "ansible_check_mode | bool == false":
				return true
			}
		}
	}
	return false
}

// checkModeExecHeads returns the commands a command/shell/raw task executes: the first
// word of the command, of each statement of a shell script, and of a `sh -c` string. A
// computed head (`{{ ... }}`) is replaced by every quoted absolute path in the task.
func checkModeExecHeads(module string, params any) []string {
	whole, _ := json.Marshal(params)
	isShell := strings.HasSuffix(module, "shell") || strings.HasSuffix(module, "raw")
	var words, texts []string
	text := func(s string) {
		if isShell {
			texts = append(texts, s)
			return
		}
		words = strings.Fields(s)
	}
	switch p := params.(type) {
	case string:
		text(p)
	case map[string]any:
		switch argv := p["argv"].(type) {
		case []any:
			for _, a := range argv {
				if s, ok := a.(string); ok {
					words = append(words, s)
				}
			}
		case string:
			words = []string{argv}
		}
		for _, key := range []string{"cmd", "_raw_params"} {
			if s, ok := p[key].(string); ok {
				text(s)
			}
		}
	}
	var heads []string
	if len(words) > 0 {
		heads = append(heads, words[0])
		if slices.Contains([]string{"sh", "bash", "dash", "zsh"}, path.Base(words[0])) {
			if i := slices.Index(words, "-c"); i >= 0 {
				texts = append(texts, strings.TrimLeft(strings.Join(words[i+1:], " "), `'"`))
			}
		}
	}
	for _, script := range texts {
		for _, m := range shellCommandPosition.FindAllStringSubmatch(script, -1) {
			heads = append(heads, m[1])
		}
	}
	for _, head := range slices.Clone(heads) {
		if strings.Contains(head, "{{") || strings.Contains(head, "{%") {
			for _, m := range quotedAbsolutePath.FindAllStringSubmatch(string(whole), -1) {
				heads = append(heads, m[1])
			}
			break
		}
	}
	return heads
}

// isInstalledPath reports whether an exec head is a file some playbook installs itself.
func isInstalledPath(head string, dests map[string]bool) bool {
	for _, dir := range checkModeInstalledDirs {
		if strings.HasPrefix(head, dir) {
			return true
		}
	}
	return dests[head]
}

func parseYAMLForTest(t *testing.T, name, body string) any {
	t.Helper()
	var doc any
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return doc
}

// checkModeFixture builds the docs of a synthetic repo from `<file>: <yaml>` pairs.
func checkModeFixture(t *testing.T, files map[string]string) map[string]any {
	t.Helper()
	docs := map[string]any{}
	for file, body := range files {
		docs[file] = parseYAMLForTest(t, file, body)
	}
	return docs
}

// TestCheckModeInstalledExecFires runs the checker over the shapes it must reject and the
// shapes it must accept, each asserting the exact violating task names.
func TestCheckModeInstalledExecFires(t *testing.T) {
	play := func(tasks string) string {
		return "- hosts: all\n  tasks:\n" + tasks
	}
	// The pre-fix shape of wazuh-fim-apply.yml's package-policy read, verbatim.
	preFix := `    - name: policy
      ansible.builtin.command:
        argv: [/usr/local/sbin/pilot-wazuh-transaction, agent-policy-check, --family, "{{ ansible_os_family }}", --owner, "{{ wazuh_writer_owner }}"]
      changed_when: false
      check_mode: false
      tags: [C1, C2]
`
	cases := []struct {
		name  string
		files map[string]string
		want  []string // violating keys, sorted
	}{
		{"the pre-fix package-policy read", map[string]string{"apply/p.yml": play(preFix)}, []string{"apply/p.yml::policy"}},
		{"the same read as the controller-shipped script (the fix)", map[string]string{"apply/p.yml": play(`    - name: policy
      ansible.builtin.script:
        cmd: >-
          files/wazuh-transaction.py agent-policy-check --family {{ ansible_os_family | quote }}
          --owner {{ wazuh_writer_owner | quote }}
        executable: python3
      changed_when: false
      check_mode: false
`)}, nil},
		{"guarded by its own `when` (list form)", map[string]string{"apply/p.yml": play(preFix + "      when:\n        - x\n        - not ansible_check_mode\n")}, nil},
		{"guarded by its own `when` (and-expression)", map[string]string{"apply/p.yml": play(preFix + "      when: (not ansible_check_mode) and y\n")}, nil},
		{"guarded by an enclosing block", map[string]string{"apply/p.yml": play("    - when: not ansible_check_mode\n      block:\n" + indent(preFix, 4))}, nil},
		{"a `when` that can be true in a preview is no guard (or)", map[string]string{"apply/p.yml": play(preFix + "      when: not ansible_check_mode or force\n")}, []string{"apply/p.yml::policy"}},
		{"a `when` that can be true in a preview is no guard (partial)", map[string]string{"apply/p.yml": play(preFix + "      when: not (ansible_check_mode and fresh)\n")}, []string{"apply/p.yml::policy"}},
		{"no check_mode: false means --check only simulates the command", map[string]string{"apply/p.yml": play(strings.Replace(preFix, "      check_mode: false\n", "", 1))}, nil},
		{"check_mode: false inherited from a block", map[string]string{"apply/p.yml": play("    - check_mode: false\n      block:\n" + indent(strings.Replace(preFix, "      check_mode: false\n", "", 1), 4))}, []string{"apply/p.yml::policy"}},
		{"a task overriding the block's check_mode: false", map[string]string{"apply/p.yml": play("    - check_mode: false\n      block:\n" + indent(strings.Replace(preFix, "check_mode: false", "check_mode: true", 1), 4))}, nil},
		{"inside a rescue section", map[string]string{"apply/p.yml": play("    - block: []\n      rescue:\n" + indent(preFix, 4))}, []string{"apply/p.yml::policy"}},
		{"a system binary", map[string]string{"apply/p.yml": play(strings.Replace(preFix, "/usr/local/sbin/pilot-wazuh-transaction", "/usr/bin/python3", 1))}, nil},
		{"a bare tool name", map[string]string{"apply/p.yml": play("    - name: policy\n      ansible.builtin.command: {argv: [stat, /usr/local/sbin/pilot-wazuh-transaction]}\n      check_mode: false\n")}, nil},
		{"free-form command", map[string]string{"apply/p.yml": play("    - name: policy\n      ansible.builtin.command: /usr/local/libexec/helper check\n      check_mode: false\n")}, []string{"apply/p.yml::policy"}},
		{"sh -c argv wrapper", map[string]string{"apply/p.yml": play("    - name: policy\n      ansible.builtin.command:\n        argv: [sh, -c, \"/usr/local/sbin/x check >/dev/null && echo 0\"]\n      check_mode: false\n")}, []string{"apply/p.yml::policy"}},
		{"shell statement after a keyword", map[string]string{"apply/p.yml": play("    - name: policy\n      ansible.builtin.shell:\n        cmd: |\n          if test -f /etc/x; then\n            /usr/local/libexec/x check\n          fi\n      check_mode: false\n")}, []string{"apply/p.yml::policy"}},
		{"shell that only names the path as an argument", map[string]string{"apply/p.yml": play("    - name: policy\n      ansible.builtin.shell: ls -l /usr/local/sbin/x\n      check_mode: false\n")}, nil},
		{"computed argv naming a literal installed path", map[string]string{"apply/p.yml": play("    - name: policy\n      ansible.builtin.command:\n        argv: \"{{ ['/usr/local/sbin/x', 'a'] + extra }}\"\n      check_mode: false\n")}, []string{"apply/p.yml::policy"}},
		{"computed argv naming no installed path", map[string]string{"apply/p.yml": play("    - name: policy\n      ansible.builtin.command:\n        argv: \"{{ ['dig', 'a'] + extra }}\"\n      check_mode: false\n")}, nil},
		{"a path the repo installs itself, outside /usr/local", map[string]string{"apply/p.yml": play("    - name: install\n      ansible.builtin.copy: {src: files/t, dest: /opt/pilot/bin/tool}\n    - name: run\n      ansible.builtin.command: {argv: [/opt/pilot/bin/tool, x]}\n      check_mode: false\n")}, []string{"apply/p.yml::run"}},
		{"the same path installed by another playbook", map[string]string{
			"apply/a.yml": play("    - name: install\n      ansible.builtin.template: {src: t.j2, dest: /opt/pilot/bin/tool}\n"),
			"apply/b.yml": play("    - name: run\n      ansible.builtin.command: {argv: [/opt/pilot/bin/tool, x]}\n      check_mode: false\n")}, []string{"apply/b.yml::run"}},
		{"a task file reached from an unguarded include", map[string]string{
			"apply/p.yml":       play("    - name: use\n      ansible.builtin.include_tasks: {file: tasks/t.yml, apply: {tags: [C1]}}\n"),
			"apply/tasks/t.yml": "- name: policy\n  ansible.builtin.command: {argv: [/usr/local/sbin/x]}\n  check_mode: false\n"}, []string{"apply/tasks/t.yml::policy"}},
		{"a task file reached only from a guarded include", map[string]string{
			"apply/p.yml":       play("    - name: use\n      ansible.builtin.include_tasks: tasks/t.yml\n      when: not ansible_check_mode\n"),
			"apply/tasks/t.yml": "- name: policy\n  ansible.builtin.command: {argv: [/usr/local/sbin/x]}\n  check_mode: false\n"}, nil},
		{"a task file reached from a guarded and an unguarded include", map[string]string{
			"apply/p.yml": play("    - name: a\n      ansible.builtin.include_tasks: tasks/t.yml\n      when: not ansible_check_mode\n" +
				"    - name: b\n      ansible.builtin.include_tasks: tasks/t.yml\n"),
			"apply/tasks/t.yml": "- name: policy\n  ansible.builtin.command: {argv: [/usr/local/sbin/x]}\n  check_mode: false\n"}, []string{"apply/tasks/t.yml::policy"}},
		{"a dynamic include's own check_mode does not reach its tasks", map[string]string{
			"apply/p.yml":       play("    - name: use\n      ansible.builtin.include_tasks: tasks/t.yml\n      check_mode: false\n"),
			"apply/tasks/t.yml": "- name: policy\n  ansible.builtin.command: {argv: [/usr/local/sbin/x]}\n"}, nil},
		{"a dynamic include's apply check_mode does", map[string]string{
			"apply/p.yml":       play("    - name: use\n      ansible.builtin.include_tasks: {file: tasks/t.yml, apply: {check_mode: false}}\n"),
			"apply/tasks/t.yml": "- name: policy\n  ansible.builtin.command: {argv: [/usr/local/sbin/x]}\n"}, []string{"apply/tasks/t.yml::policy"}},
		{"a static import's own check_mode reaches its tasks", map[string]string{
			"apply/p.yml":       play("    - name: use\n      ansible.builtin.import_tasks: tasks/t.yml\n      check_mode: false\n"),
			"apply/tasks/t.yml": "- name: policy\n  ansible.builtin.command: {argv: [/usr/local/sbin/x]}\n"}, []string{"apply/tasks/t.yml::policy"}},
		{"an include resolved from a sibling directory", map[string]string{
			"check/p.yml":       play("    - name: use\n      ansible.builtin.include_tasks: ../apply/tasks/t.yml\n"),
			"apply/tasks/t.yml": "- name: policy\n  ansible.builtin.command: {argv: [/usr/local/sbin/x]}\n  check_mode: false\n"}, []string{"apply/tasks/t.yml::policy"}},
		{"a task file nothing includes is a root of its own", map[string]string{
			"apply/tasks/t.yml": "- name: policy\n  ansible.builtin.command: {argv: [/usr/local/sbin/x]}\n  check_mode: false\n"}, []string{"apply/tasks/t.yml::policy"}},
		{"handlers run in a preview too", map[string]string{"apply/p.yml": "- hosts: all\n  handlers:\n" + preFix}, []string{"apply/p.yml::policy"}},
		{"an include cycle terminates", map[string]string{
			"apply/tasks/a.yml": "- name: to b\n  ansible.builtin.include_tasks: b.yml\n",
			"apply/tasks/b.yml": "- name: to a\n  ansible.builtin.include_tasks: a.yml\n- name: policy\n  ansible.builtin.command: {argv: [/usr/local/sbin/x]}\n  check_mode: false\n",
			"apply/p.yml":       play("    - name: use\n      ansible.builtin.include_tasks: tasks/a.yml\n")}, []string{"apply/tasks/b.yml::policy"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scan, err := scanCheckModeInstalledExec(checkModeFixture(t, tc.files))
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range scan.Findings {
				if !slices.Contains(got, f.Key) {
					got = append(got, f.Key)
				}
			}
			sort.Strings(got)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("violations = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCheckModeInstalledExecFailsClosed: what the walker cannot follow is an error, never a pass.
func TestCheckModeInstalledExecFailsClosed(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"an include of a file that does not exist": {"apply/p.yml": "- hosts: all\n  tasks:\n    - ansible.builtin.include_tasks: tasks/missing.yml\n"},
		"a computed include file name":             {"apply/p.yml": "- hosts: all\n  tasks:\n    - ansible.builtin.include_tasks: \"tasks/{{ x }}.yml\"\n"},
		"an include with no file":                  {"apply/p.yml": "- hosts: all\n  tasks:\n    - ansible.builtin.include_tasks: {apply: {tags: [C1]}}\n"},
		"a task list that is not a list":           {"apply/p.yml": "- hosts: all\n  tasks: {name: x}\n"},
		"a task that is not a mapping":             {"apply/p.yml": "- hosts: all\n  tasks:\n    - just a string\n"},
		"an ambiguous include name": {
			"apply/p.yml": "- hosts: all\n  tasks:\n    - ansible.builtin.include_tasks: ../elsewhere/t.yml\n",
			"a/t.yml":     "- name: x\n  ansible.builtin.debug: {msg: a}\n",
			"b/t.yml":     "- name: x\n  ansible.builtin.debug: {msg: b}\n"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := scanCheckModeInstalledExec(checkModeFixture(t, files)); err == nil {
				t.Fatal("the scan passed what it cannot follow")
			}
		})
	}
}

func TestWhenSkipsUnderCheckMode(t *testing.T) {
	for when, want := range map[string]bool{
		"not ansible_check_mode":                          true,
		"  not   ansible_check_mode ":                     true,
		"x and not ansible_check_mode":                    true,
		"(not ansible_check_mode) and (x)":                true,
		"ansible_check_mode == false":                     true,
		"ansible_check_mode":                              false,
		"not ansible_check_mode or x":                     false,
		"not (ansible_check_mode and x)":                  false,
		"not ansible_check_mode_extra":                    false,
		"x":                                               false,
		"ansible_os_family == 'Debian'":                   false,
		"wazuh_agent_version_plan.install and not x":      false,
		"not ansible_check_mode and wazuh_x or y":         false,
		"not (wazuh_observed_manager is skipped) and yes": false,
	} {
		if got := whenSkipsUnderCheckMode(when); got != want {
			t.Errorf("whenSkipsUnderCheckMode(%q) = %t, want %t", when, got, want)
		}
	}
	if !whenSkipsUnderCheckMode([]any{"x", "not ansible_check_mode"}) {
		t.Error("a list item that guards must guard the task (items are ANDed)")
	}
	if whenSkipsUnderCheckMode([]any{"x", "y"}) {
		t.Error("a list with no check-mode conjunct must not guard")
	}
}

// indent prefixes every non-empty line of s with n spaces.
func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = pad + line
		}
	}
	return strings.Join(lines, "\n")
}
