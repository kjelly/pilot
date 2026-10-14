package spec

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #69: playbooks ran `kinit admin` into the host's default credential
// cache and did not reliably destroy it, so a FreeIPA admin TGT stayed on the
// host after the run (a freshly deployed FreeIPA server had admin@REALM in
// root's KCM:0), and any later program using the default cache acted as
// admin without knowing it. Every kinit under playbooks/ must write to a
// private cache that is destroyed on success, failure and any --tags:
//
//   - inside a block built on tasks/freeipa-private-ccache-open.yml and
//     -close.yml (both included with tags and apply tags `always`);
//   - with KRB5CCNAME naming {{ pilot_krb5ccname }} (a task file included
//     inside such a block; outside one the name points nowhere);
//   - with a MEMORY: cache (lives only in the kinit process);
//   - or with a cache file registered by ansible.builtin.tempfile that a
//     kdestroy in an enclosing block's always: destroys, tagged so it runs
//     whenever the kinit does.
//
// A literal cache name (KCM:, KEYRING:, "", a fixed /tmp path) is not
// private. There is no allowlist: PR #72 review found that the files once
// allowlisted as "already run kdestroy" left tickets on failure, under
// --tags, or for good (pilot-access-gateway), and migrated all of them.

type kinitSite struct {
	file    string
	task    string
	private bool
	why     string // what makes it not private
}

// krbTask is one non-block task and the credential cache it runs with.
type krbTask struct {
	task      map[string]any
	name      string
	tags      []string
	scope     string // cache identity, see ccacheScope; "" is the default cache
	ancestors []krbBlock
}

// krbBlock is a block enclosing a task, with the tags its tasks inherit.
type krbBlock struct {
	block map[string]any
	tags  []string
}

var (
	tempfileCacheRe = regexp.MustCompile(`^(?:FILE:)?\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\.path\s*\}\}$`)
	ccacheIncludes  = []string{"ansible.builtin.include_tasks", "include_tasks", "ansible.builtin.import_tasks", "import_tasks"}
	commandModules  = []string{"shell", "command", "raw", "expect"}
)

// ccacheScope names the cache a KRB5CCNAME value selects: "pilot_krb5ccname",
// "memory", "var:<tempfile register>", or "literal:<value>".
func ccacheScope(v string) string {
	v = strings.TrimSpace(v)
	switch {
	case strings.Contains(v, "pilot_krb5ccname"):
		return "pilot_krb5ccname"
	case strings.HasPrefix(v, "MEMORY:"):
		return "memory"
	}
	if m := tempfileCacheRe.FindStringSubmatch(v); m != nil {
		return "var:" + m[1]
	}
	return "literal:" + v
}

// moduleArgs returns the args of the first command-running module a task
// uses (short, ansible.builtin. or ansible.legacy. name), or nil.
func moduleArgs(task map[string]any) (string, any) {
	for _, m := range commandModules {
		for _, key := range []string{m, "ansible.builtin." + m, "ansible.legacy." + m} {
			if v, ok := task[key]; ok {
				return m, v
			}
		}
	}
	return "", nil
}

// commandSegments returns the simple commands a task runs, each as tokens
// with quotes removed and {{ }} kept whole. Shell comment lines are dropped.
// A token that is itself a quoted command line (`sh -c '...'`) is scanned as
// well.
func commandSegments(task map[string]any) [][]string {
	module, raw := moduleArgs(task)
	if module == "" {
		return nil
	}
	var text string
	switch v := raw.(type) {
	case string:
		text = v
	case map[string]any:
		if argv, ok := v["argv"].([]any); ok {
			parts := make([]string, 0, len(argv))
			segs := [][]string{nil}
			for _, a := range argv {
				s := fmt.Sprint(a)
				parts = append(parts, s)
				if strings.ContainsAny(s, " \t\n;|&") {
					segs = append(segs, shellSegments(s, 1)...)
				}
			}
			segs[0] = parts
			return segs
		}
		for _, key := range []string{"cmd", "_raw_params", "command"} {
			if s, ok := v[key].(string); ok {
				text = s
				break
			}
		}
	}
	var kept []string
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			kept = append(kept, line)
		}
	}
	return shellSegments(strings.Join(kept, "\n"), 0)
}

// shellSegments splits a shell command line into simple commands on ; & |
// ( ) and newlines outside quotes and {{ }}, and each into tokens.
func shellSegments(text string, depth int) [][]string {
	var segs [][]string
	var tok strings.Builder
	var cur []string
	inTok, quote, jinja := false, rune(0), 0
	flushTok := func() {
		if inTok {
			cur = append(cur, tok.String())
			if depth < 2 && strings.ContainsAny(tok.String(), " \t\n;|&") {
				segs = append(segs, shellSegments(tok.String(), depth+1)...)
			}
		}
		tok.Reset()
		inTok = false
	}
	flushSeg := func() {
		flushTok()
		if len(cur) > 0 {
			segs = append(segs, cur)
		}
		cur = nil
	}
	rs := []rune(text)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case jinja > 0:
			tok.WriteRune(c)
			if c == '}' && i+1 < len(rs) && rs[i+1] == '}' {
				tok.WriteRune('}')
				i++
				jinja--
			}
		case c == '{' && i+1 < len(rs) && rs[i+1] == '{':
			tok.WriteString("{{")
			i++
			jinja++
			inTok = true
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '\\' && quote == '"' && i+1 < len(rs) {
				i++
				tok.WriteRune(rs[i])
			} else {
				tok.WriteRune(c)
			}
		case c == '\'' || c == '"':
			quote = c
			inTok = true
		case c == '\\' && i+1 < len(rs):
			i++
			if rs[i] != '\n' {
				tok.WriteRune(rs[i])
				inTok = true
			}
		case c == ' ' || c == '\t':
			flushTok()
		case c == '\n' || c == ';' || c == '&' || c == '|' || c == '(' || c == ')':
			flushSeg()
		default:
			tok.WriteRune(c)
			inTok = true
		}
	}
	flushSeg()
	return segs
}

// kinitCache returns, for the first kinit among segs, whether there is one
// and the cache it selects on its own command line ("" when -c and a
// KRB5CCNAME= prefix are both absent).
func kinitCache(segs [][]string) (bool, string) {
	for _, seg := range segs {
		for i, t := range seg {
			if path.Base(t) != "kinit" {
				continue
			}
			for j := i + 1; j < len(seg); j++ {
				switch {
				case seg[j] == "-c" && j+1 < len(seg):
					return true, seg[j+1]
				case strings.HasPrefix(seg[j], "-c") && len(seg[j]) > 2:
					return true, seg[j][2:]
				}
			}
			for _, prev := range seg[:i] {
				if v, ok := strings.CutPrefix(prev, "KRB5CCNAME="); ok {
					return true, v
				}
			}
			return true, ""
		}
	}
	return false, ""
}

// runsWord reports whether segs run the program word (any path).
func runsWord(segs [][]string, word string) bool {
	for _, seg := range segs {
		for _, t := range seg {
			if path.Base(t) == word {
				return true
			}
		}
	}
	return false
}

func envCache(m map[string]any) (string, bool) {
	env, ok := m["environment"].(map[string]any)
	if !ok {
		return "", false
	}
	v, ok := env["KRB5CCNAME"]
	if !ok {
		return "", false
	}
	return fmt.Sprint(v), true
}

func includeFile(task map[string]any) (string, map[string]any) {
	for _, key := range ccacheIncludes {
		switch v := task[key].(type) {
		case string:
			return v, nil
		case map[string]any:
			f, _ := v["file"].(string)
			return f, v
		}
	}
	return "", nil
}

// includesHelper reports whether task includes the shared helper file name
// and, with tags and apply tags `always`, runs under any --tags.
func includesHelper(task map[string]any, name string) (bool, bool) {
	f, args := includeFile(task)
	if !strings.HasSuffix(f, name) {
		return false, false
	}
	apply, _ := args["apply"].(map[string]any)
	return true, slices.Contains(yamlTags(task), "always") && apply != nil && slices.Contains(yamlTags(apply), "always")
}

func taskList(raw any) []map[string]any {
	list, _ := raw.([]any)
	var out []map[string]any
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// krbWalker collects every non-block task of one file with the cache it
// runs with, and the problems in private-cache blocks.
type krbWalker struct {
	file     string
	blocks   int
	tasks    []krbTask
	problems []string
}

func (w *krbWalker) walk(tasks []map[string]any, tags []string, scope string, ancestors []krbBlock) {
	for _, task := range tasks {
		name, _ := task["name"].(string)
		ttags := append(slices.Clone(tags), yamlTags(task)...)
		tscope := scope
		if v, ok := envCache(task); ok {
			tscope = ccacheScope(v)
		}
		if _, isBlock := task["block"]; isBlock {
			if tscope == "pilot_krb5ccname" {
				if v, _ := envCache(task); strings.Contains(v, "pilot_krb5ccname") {
					w.checkHelperBlock(task, name)
					w.blocks++
					tscope = fmt.Sprintf("helper@%d", w.blocks)
				}
			}
			inner := append(slices.Clone(ancestors), krbBlock{task, ttags})
			for _, section := range []string{"block", "rescue", "always"} {
				w.walk(taskList(task[section]), ttags, tscope, inner)
			}
			continue
		}
		w.tasks = append(w.tasks, krbTask{task: task, name: name, tags: ttags, scope: tscope, ancestors: ancestors})
	}
}

func (w *krbWalker) checkHelperBlock(task map[string]any, name string) {
	block := taskList(task["block"])
	opened := false
	if len(block) > 0 {
		found, always := includesHelper(block[0], "freeipa-private-ccache-open.yml")
		opened = found
		if found && !always {
			w.problems = append(w.problems, fmt.Sprintf("%s: block %q: the open include must have tags [always] and apply: {tags: [always]}, or a --tags run skips it", w.file, name))
		}
	}
	if !opened {
		w.problems = append(w.problems, fmt.Sprintf("%s: block %q sets KRB5CCNAME from pilot_krb5ccname but does not include tasks/freeipa-private-ccache-open.yml first", w.file, name))
	}
	closed := false
	for _, t := range taskList(task["always"]) {
		if found, always := includesHelper(t, "freeipa-private-ccache-close.yml"); found {
			closed = true
			if !always {
				w.problems = append(w.problems, fmt.Sprintf("%s: block %q: the close include must have tags [always] and apply: {tags: [always]}, or a --tags run leaves the cache behind", w.file, name))
			}
		}
	}
	if !closed {
		w.problems = append(w.problems, fmt.Sprintf("%s: block %q opens a private Kerberos cache but its always: does not include tasks/freeipa-private-ccache-close.yml", w.file, name))
	}
}

// tempfileRegisters returns the names registered by ansible.builtin.tempfile
// tasks among tasks.
func tempfileRegisters(tasks []krbTask) map[string]bool {
	out := map[string]bool{}
	for _, t := range tasks {
		for _, key := range []string{"ansible.builtin.tempfile", "tempfile"} {
			if _, ok := t.task[key]; ok {
				if r, ok := t.task["register"].(string); ok {
					out[r] = true
				}
			}
		}
	}
	return out
}

// cleanupTagsCover reports whether a cleanup task with tags cleanup runs under
// every --tags selection that runs a task with tags.
func cleanupTagsCover(cleanup, tags []string) bool {
	if slices.Contains(cleanup, "always") {
		return true
	}
	if slices.Contains(tags, "always") {
		return false
	}
	if len(tags) == 0 {
		return len(cleanup) == 0
	}
	for _, tag := range tags {
		if !slices.Contains(cleanup, tag) {
			return false
		}
	}
	return true
}

// tempfileCleaned reports whether an always: of a block enclosing k runs a
// kdestroy of {{ v.path }} under every tag k runs with.
func (w *krbWalker) tempfileCleaned(k krbTask, v string) bool {
	ref := regexp.MustCompile(`\b` + regexp.QuoteMeta(v) + `\.path\b`)
	for _, anc := range k.ancestors {
		var inner krbWalker
		inner.walk(taskList(anc.block["always"]), anc.tags, "", nil)
		for _, t := range inner.tasks {
			segs := commandSegments(t.task)
			if runsWord(segs, "kdestroy") && ref.MatchString(fmt.Sprint(segs)) && cleanupTagsCover(t.tags, k.tags) {
				return true
			}
		}
	}
	return false
}

// kinitSites classifies every kinit in one file's tasks.
func (w *krbWalker) kinitSites() []kinitSite {
	temps := tempfileRegisters(w.tasks)
	var out []kinitSite
	for _, k := range w.tasks {
		found, cmdCache := kinitCache(commandSegments(k.task))
		if !found {
			continue
		}
		scope := k.scope
		if cmdCache != "" {
			scope = ccacheScope(cmdCache)
		}
		site := kinitSite{file: w.file, task: k.name}
		switch {
		case strings.HasPrefix(scope, "helper@"), scope == "pilot_krb5ccname", scope == "memory":
			site.private = true
		case strings.HasPrefix(scope, "var:"):
			v := strings.TrimPrefix(scope, "var:")
			switch {
			case !temps[v]:
				site.why = fmt.Sprintf("KRB5CCNAME names {{ %s.path }}, which no ansible.builtin.tempfile task in the file registers", v)
			case !w.tempfileCleaned(k, v):
				site.why = fmt.Sprintf("no always: of an enclosing block runs kdestroy of {{ %s.path }} under every tag the kinit has (%v)", v, k.tags)
			default:
				site.private = true
			}
		case scope == "":
			site.why = "it writes the default credential cache"
		default:
			site.why = fmt.Sprintf("KRB5CCNAME %q is not a private cache", strings.TrimPrefix(scope, "literal:"))
		}
		out = append(out, site)
	}
	return out
}

// walkKrbDoc walks one parsed playbook or task file.
func walkKrbDoc(file string, doc any) *krbWalker {
	w := &krbWalker{file: file}
	for _, item := range taskList(doc) {
		if _, isPlay := item["hosts"]; isPlay {
			scope := ""
			if v, ok := envCache(item); ok {
				scope = ccacheScope(v)
			}
			for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
				w.walk(taskList(item[section]), yamlTags(item), scope, nil)
			}
			continue
		}
		w.walk([]map[string]any{item}, nil, "", nil)
	}
	return w
}

func scanKinitDir(t *testing.T, root string) ([]kinitSite, []string) {
	t.Helper()
	var sites []kinitSite
	var problems []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !(strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var doc any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		rel, err := filepath.Rel(filepath.Dir(root), p)
		if err != nil {
			return err
		}
		w := walkKrbDoc(filepath.ToSlash(rel), doc)
		sites = append(sites, w.kinitSites()...)
		problems = append(problems, w.problems...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sites, problems
}

func TestRegression_KinitUsesAPrivateCredentialCache(t *testing.T) {
	sites, problems := scanKinitDir(t, "../../playbooks")
	if len(sites) < 30 {
		t.Fatalf("found only %d kinit sites under playbooks/; the scan is broken", len(sites))
	}
	for _, p := range problems {
		t.Error(p)
	}
	for _, s := range sites {
		if !s.private {
			t.Errorf("%s: task %q runs kinit but %s; use a block with tasks/freeipa-private-ccache-open.yml and -close.yml (issue #69)", s.file, s.task, s.why)
		}
	}
}

// The scan reads .yaml files too.
func TestKinitScanReadsYamlFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "playbooks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hello.yaml"), []byte("- hosts: all\n  tasks:\n    - {name: k, shell: kinit admin}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sites, _ := scanKinitDir(t, dir)
	if len(sites) != 1 || sites[0].private || sites[0].file != "playbooks/hello.yaml" {
		t.Fatalf("sites = %+v, want one default-cache kinit in playbooks/hello.yaml", sites)
	}
}

// What counts as a kinit and as a private cache. Each task is classified
// on its own; problems are the block-structure findings.
func TestKinitScanClassifiesSites(t *testing.T) {
	src := `
- hosts: all
  tasks:
    - {name: default cache, ansible.builtin.shell: printf %s x | kinit admin}
    - {name: full path, ansible.builtin.shell: printf %s x | /usr/bin/kinit admin}
    - {name: quoted name, ansible.builtin.shell: '"kinit" admin'}
    - name: expect
      ansible.builtin.expect: {command: kinit admin, responses: {Password: x}}
    - {name: raw params, ansible.builtin.shell: {_raw_params: kinit admin}}
    - {name: argv, ansible.builtin.command: {argv: [/usr/bin/kinit, admin]}}
    - {name: sh -c payload, ansible.builtin.command: {argv: [sh, -c, "printf x | kinit admin"]}}
    - name: comment only
      ansible.builtin.shell: |
        # kinit admin
        true
    - {name: echo is not kinit, ansible.builtin.shell: echo kinit-admin}
    - name: env KCM
      ansible.builtin.command: kinit admin
      environment: {KRB5CCNAME: "KCM:"}
    - name: env empty
      ansible.builtin.command: kinit admin
      environment: {KRB5CCNAME: ""}
    - name: env fixed file
      ansible.builtin.command: kinit admin
      environment: {KRB5CCNAME: "FILE:/tmp/pilot-cc"}
    - {name: -c of another command, ansible.builtin.shell: "kinit admin && wc -c f"}
    - {name: echo before kinit, ansible.builtin.shell: "echo KRB5CCNAME=FILE:/x; kinit admin"}
    - {name: memory -c, ansible.builtin.command: {argv: [kinit, -c, "MEMORY:x", u]}}
    - {name: fixed -c, ansible.builtin.command: {argv: [kinit, -c, "FILE:/tmp/x", u]}}
    - name: pilot_krb5ccname task env
      ansible.builtin.shell: printf x | kinit admin
      environment: {KRB5CCNAME: "{{ pilot_krb5ccname }}"}
    - name: tempfile with cleanup
      block:
        - {name: tf, ansible.builtin.tempfile: {state: file}, register: cc}
        - {name: tempfile inline, tags: [C1], ansible.builtin.shell: 'printf x | KRB5CCNAME="{{ cc.path }}" kinit admin'}
        - {name: tempfile env, tags: [C1], ansible.builtin.command: kinit admin, environment: {KRB5CCNAME: "FILE:{{ cc.path }}"}}
      always:
        - {name: kd, tags: [always], ansible.builtin.command: {argv: [kdestroy, -c, "{{ cc.path }}"]}}
    - name: tempfile cleanup skipped under tags
      block:
        - {name: tf2, ansible.builtin.tempfile: {state: file}, register: cc2}
        - {name: tempfile tag gap, tags: [C2], ansible.builtin.shell: 'printf x | KRB5CCNAME="{{ cc2.path }}" kinit admin'}
      always:
        - {name: kd2, tags: [C3], ansible.builtin.command: {argv: [kdestroy, -c, "{{ cc2.path }}"]}}
    - name: tempfile without cleanup
      block:
        - {name: tf3, ansible.builtin.tempfile: {state: file}, register: cc3}
        - {name: tempfile no always, ansible.builtin.shell: 'printf x | KRB5CCNAME="{{ cc3.path }}" kinit admin'}
    - {name: unregistered var, ansible.builtin.shell: 'printf x | KRB5CCNAME="{{ nope.path }}" kinit admin'}
    - name: good block
      environment:
        KRB5CCNAME: "{{ pilot_krb5ccname | default('FILE:/nonexistent/x') }}"
      block:
        - name: open
          ansible.builtin.include_tasks: {file: tasks/freeipa-private-ccache-open.yml, apply: {tags: [always]}}
          tags: [always]
        - {name: inherits, ansible.builtin.command: kinit admin}
        - name: task env overrides the block
          ansible.builtin.command: kinit admin
          environment: {KRB5CCNAME: "KCM:"}
      always:
        - name: close
          ansible.builtin.include_tasks: {file: tasks/freeipa-private-ccache-close.yml, apply: {tags: [always]}}
          tags: [always]
    - name: no close
      environment:
        KRB5CCNAME: "{{ pilot_krb5ccname }}"
      block:
        - name: open
          ansible.builtin.include_tasks: {file: tasks/freeipa-private-ccache-open.yml, apply: {tags: [always]}}
          tags: [always]
    - name: no open first
      environment:
        KRB5CCNAME: "{{ pilot_krb5ccname }}"
      block:
        - {name: kinit first, ansible.builtin.command: kinit admin}
      always:
        - name: close
          ansible.builtin.include_tasks: {file: tasks/freeipa-private-ccache-close.yml, apply: {tags: [always]}}
          tags: [always]
    - name: open not always
      environment:
        KRB5CCNAME: "{{ pilot_krb5ccname }}"
      block:
        - name: open
          ansible.builtin.include_tasks: {file: tasks/freeipa-private-ccache-open.yml}
          tags: [C1]
      always:
        - name: close
          ansible.builtin.include_tasks: {file: tasks/freeipa-private-ccache-close.yml, apply: {tags: [always]}}
          tags: [always]
`
	var doc any
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	w := walkKrbDoc("x.yml", doc)
	got := map[string]bool{}
	for _, s := range w.kinitSites() {
		got[s.task] = s.private
	}
	want := map[string]bool{
		"default cache": false, "full path": false, "quoted name": false, "expect": false,
		"raw params": false, "argv": false, "sh -c payload": false,
		"env KCM": false, "env empty": false, "env fixed file": false,
		"-c of another command": false, "echo before kinit": false,
		"memory -c": true, "fixed -c": false, "pilot_krb5ccname task env": true,
		"tempfile inline": true, "tempfile env": true, "tempfile tag gap": false,
		"tempfile no always": false, "unregistered var": false,
		"inherits": true, "task env overrides the block": false, "kinit first": true,
	}
	for task, private := range want {
		if p, found := got[task]; !found || p != private {
			t.Errorf("%q: found=%v private=%v, want private=%v", task, found, p, private)
		}
	}
	for _, notKinit := range []string{"comment only", "echo is not kinit"} {
		if _, found := got[notKinit]; found {
			t.Errorf("%q was counted as a kinit", notKinit)
		}
	}
	joined := strings.Join(w.problems, "\n")
	if len(w.problems) != 3 || !strings.Contains(joined, `"no close"`) || !strings.Contains(joined, `"no open first"`) || !strings.Contains(joined, `"open not always": the open include must have tags [always]`) {
		t.Errorf("problems = %v, want the block without close, the one without open first, and the open include without always", w.problems)
	}
}
