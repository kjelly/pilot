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

// Every logrotate policy a playbook renders must say which identity it rotates
// as: an explicit `su <user> <group>`, at the top of the file (it applies to
// the stanzas after it) or in every stanza.
//
// logrotate expands a policy's globs as root and then renames, creates,
// compresses and deletes by full path. It refuses a symlinked or hard-linked
// log file but nothing stops a symlinked directory component, so where a
// directory on the path belongs to an unprivileged account (log-server's
// per-host directories belong to the rsyslog user on Ubuntu) that account can
// make root's daily run act inside a directory of its choosing. A policy that
// names no `su` inherits whatever the distribution's /etc/logrotate.conf says,
// which on Ubuntu is `su root adm`, and that global `su` also turns off
// logrotate's own insecure-parent check. The first site found, log-server's
// siem-incoming, rendered no `su` (docs/verification/log-server.md v2.1).
//
// The guard parses the YAML (play vars, blocks, rescue/always, task files) and
// the policy text (script blocks are not directives), and fails closed: a dest
// that names logrotate but cannot be resolved, a source file that cannot be
// found, a policy with no stanza or with Jinja statements the guard cannot
// evaluate, and a writer module other than copy/template are failures, never
// skips.
//
// What it does not see: a policy written by a shell/command task or by a
// module not listed here, and a dest held in a variable that neither names
// logrotate nor is defined in the play's vars. Those need review; none exists
// on the base this guard was added to (git grep for logrotate over playbooks,
// Go, images, scripts, contracts and group_vars).

// logrotateIdentityAllowlist names the policies that are known not to declare
// `su`, with the reason. Each entry is checked both ways: one that now passes
// or whose task no longer exists fails the test and asks for its removal.
var logrotateIdentityAllowlist = map[string]string{
	"playbooks/apply/audit-log-forwarding-apply.yml::Step 4: Render /etc/logrotate.d/auditd": "rotates /var/log/audit/audit.log, a file and a directory " +
		"that root owns (auditd runs as root), so rotating as root is the identity of the files' owner and there is no lower-privileged " +
		"identity to switch to. The exposure that remains on Ubuntu is distro-level (/var/log is root:syslog 0775 without the sticky bit) and " +
		"has no `su` remedy in this policy; it is tracked by https://github.com/kjelly/pilot/issues/364.",
}

// logrotateHostDerivedWriters names the tasks that put a logrotate policy in
// place from a file already on the target (copy with remote_src), so the policy
// text is not in the repository and there is nothing for the guard to read.
// Checked both ways, like the allowlist.
var logrotateHostDerivedWriters = map[string]string{
	"playbooks/apply/audit-log-forwarding-apply.yml::Step 5c: Drop {{ audit_syslog_path }} from the distro rsyslog policy, keeping its other paths (spec C20)": "rewrites " +
		"the distribution's own /etc/logrotate.d/rsyslog without one path; it adds no path to any policy, so the identity it rotates the rest as is the distribution's own.",
}

var (
	logrotatePolicyDest  = regexp.MustCompile(`^/etc/logrotate(\.d/.*|\.conf)$`)
	logrotateJinjaExpr   = regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	logrotateJinjaCmt    = regexp.MustCompile(`(?s)\{#.*?#\}`)
	logrotateSimpleVar   = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
	logrotateFreeFormKV  = regexp.MustCompile(`(?:^|\s)(dest|path|src|remote_src|content)=("[^"]*"|'[^']*'|\S+)`)
	logrotateScriptWords = map[string]bool{"postrotate": true, "prerotate": true, "firstaction": true, "lastaction": true, "preremove": true}

	// copy/template author the file; the others change a file in place or fetch
	// one, which the guard cannot evaluate, so touching a logrotate policy with
	// them is a failure.
	logrotateAuthoringModules  = []string{"copy", "template"}
	logrotateUnanalysedModules = []string{"blockinfile", "lineinfile", "replace", "assemble", "get_url", "unarchive"}
)

// logrotateSite is one task that writes a logrotate policy.
type logrotateSite struct {
	key         string   // "<file>::<task name>"
	dest        string   // resolved dest
	hostDerived bool     // content comes from a file on the target
	problems    []string // why the site does not declare its rotation identity
}

func logrotateModuleArgs(task map[string]any, modules []string) (module string, args map[string]any, ok bool) {
	for _, m := range modules {
		for _, key := range []string{m, "ansible.builtin." + m, "ansible.legacy." + m} {
			raw, present := task[key]
			if !present {
				continue
			}
			args = map[string]any{}
			switch v := raw.(type) {
			case map[string]any:
				args = v
			case string:
				for _, kv := range logrotateFreeFormKV.FindAllStringSubmatch(v, -1) {
					args[kv[1]] = strings.Trim(kv[2], `"'`)
				}
			}
			return m, args, true
		}
	}
	return "", nil, false
}

// logrotateResolveVars replaces {{ name }} with the string value of a variable in
// vars, repeatedly, and reports whether any {{ }} is left.
func logrotateResolveVars(s string, vars map[string]any) (string, bool) {
	for i := 0; i < 8 && logrotateSimpleVar.MatchString(s); i++ {
		changed := false
		s = logrotateSimpleVar.ReplaceAllStringFunc(s, func(m string) string {
			if v, ok := vars[logrotateSimpleVar.FindStringSubmatch(m)[1]].(string); ok {
				changed = true
				return v
			}
			return m
		})
		if !changed {
			break
		}
	}
	return s, strings.Contains(s, "{{")
}

func logrotateMergeVars(outer map[string]any, inner any) map[string]any {
	out := map[string]any{}
	for k, v := range outer {
		out[k] = v
	}
	if m, ok := inner.(map[string]any); ok {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// logrotateWalk calls fn for every task of doc with the vars in scope: the
// play's vars, then each enclosing block's and the task's own. A document that
// is a list of tasks (a task file) is walked with no vars.
func logrotateWalk(doc any, fn func(task map[string]any, vars map[string]any)) {
	items, _ := doc.([]any)
	var loose []any
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if _, isPlay := m["hosts"]; isPlay {
			vars := logrotateMergeVars(nil, m["vars"])
			for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
				logrotateWalkTasks(m[section], vars, fn)
			}
			continue
		}
		if _, ok := m["import_playbook"]; ok {
			continue
		}
		loose = append(loose, item)
	}
	logrotateWalkTasks(loose, nil, fn)
}

func logrotateWalkTasks(list any, vars map[string]any, fn func(map[string]any, map[string]any)) {
	tasks, _ := list.([]any)
	for _, item := range tasks {
		task, ok := item.(map[string]any)
		if !ok {
			continue
		}
		scope := logrotateMergeVars(vars, task["vars"])
		fn(task, scope)
		for _, section := range []string{"block", "rescue", "always"} {
			logrotateWalkTasks(task[section], scope, fn)
		}
	}
}

// logrotateSites returns every task of doc (the YAML of file) that writes, or
// is meant to write, a logrotate policy, with what is wrong with it. file is
// the path on disk, used for the key's file part by relPath and to find `src`
// files next to it.
func logrotateSites(relPath, file string, doc any) []logrotateSite {
	var sites []logrotateSite
	seen := map[string]int{}
	logrotateWalk(doc, func(task map[string]any, vars map[string]any) {
		module, args, authoring := logrotateModuleArgs(task, logrotateAuthoringModules)
		if !authoring {
			var ok bool
			if module, args, ok = logrotateModuleArgs(task, logrotateUnanalysedModules); !ok {
				return
			}
		}
		raw := ""
		for _, k := range []string{"dest", "path"} {
			if s, ok := args[k].(string); ok {
				raw = s
				break
			}
		}
		if raw == "" {
			return
		}
		dest, unresolved := logrotateResolveVars(raw, vars)
		related := strings.Contains(strings.ToLower(raw), "logrotate") ||
			strings.Contains(strings.ToLower(fmt.Sprint(task["loop"], task["with_items"])), "logrotate")
		if unresolved && !related {
			return // not recognisably a logrotate policy
		}
		if !unresolved && !logrotatePolicyDest.MatchString(dest) {
			return
		}

		name, _ := task["name"].(string)
		if name == "" {
			name = fmt.Sprintf("(unnamed %s task writing %s)", module, raw)
		}
		key := relPath + "::" + name
		if seen[key]++; seen[key] > 1 {
			key = fmt.Sprintf("%s (#%d)", key, seen[key])
		}
		site := logrotateSite{key: key, dest: dest}
		fail := func(format string, a ...any) { site.problems = append(site.problems, fmt.Sprintf(format, a...)) }

		switch {
		case unresolved:
			fail("unresolvable logrotate dest %q (not a literal and not a plain variable of the play's vars); write the path, or define it in the play's vars", raw)
		case !authoring:
			fail("%s changes %s in place; the guard cannot evaluate that. Render the whole policy with copy or template", module, dest)
		case logrotateIsTrue(args["remote_src"]):
			site.hostDerived = true
		default:
			text, problem := logrotatePolicyText(file, args, vars)
			if problem != "" {
				fail("%s", problem)
			} else {
				site.problems = append(site.problems, logrotateIdentityProblems(text)...)
			}
		}
		sites = append(sites, site)
	})
	return sites
}

func logrotateIsTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true") || strings.EqualFold(x, "yes")
	}
	return false
}

// logrotatePolicyText returns the policy a copy/template task renders: its
// `content`, or the `src` file found next to the playbook (or its task file's
// parent) in the places Ansible looks.
func logrotatePolicyText(file string, args, vars map[string]any) (text, problem string) {
	if c, ok := args["content"].(string); ok {
		return c, ""
	}
	src, _ := args["src"].(string)
	if src == "" {
		return "", "has neither content nor src to read"
	}
	dir := filepath.Dir(file)
	resolved, unresolved := logrotateResolveVars(strings.ReplaceAll(src, "{{ playbook_dir }}", dir), vars)
	if unresolved {
		return "", fmt.Sprintf("unresolvable logrotate source %q", src)
	}
	candidates := []string{resolved}
	if !filepath.IsAbs(resolved) {
		candidates = []string{
			filepath.Join(dir, resolved), filepath.Join(dir, "files", resolved), filepath.Join(dir, "templates", resolved),
			filepath.Join(filepath.Dir(dir), "files", resolved), filepath.Join(filepath.Dir(dir), "templates", resolved),
		}
	}
	for _, c := range candidates {
		if b, err := os.ReadFile(c); err == nil {
			return string(b), ""
		}
	}
	return "", fmt.Sprintf("unresolvable logrotate source %q: not found among %v", src, candidates)
}

// logrotateIdentityProblems returns what is wrong with a policy's text: a
// stanza that is neither under a top-level `su <user> <group>` nor has its own.
func logrotateIdentityProblems(text string) []string {
	if logrotateJinjaCmt.MatchString(text) {
		text = logrotateJinjaCmt.ReplaceAllStringFunc(text, func(m string) string { return strings.Repeat("\n", strings.Count(m, "\n")) })
	}
	if strings.Contains(text, "{%") {
		return []string{"the policy uses Jinja statements ({% %}), so the guard cannot tell which stanzas are rendered; render a plain policy"}
	}
	original := strings.Split(text, "\n")
	cleaned := strings.Split(logrotateJinjaExpr.ReplaceAllStringFunc(text, func(m string) string {
		return "JINJA" + strings.Repeat("\n", strings.Count(m, "\n"))
	}), "\n")

	var problems []string
	suOperands := func(line string, at int) bool {
		if f := strings.Fields(line); len(f) != 3 {
			problems = append(problems, fmt.Sprintf("line %d %q is not `su <user> <group>`", at+1, strings.TrimSpace(original[at])))
			return false
		}
		return true
	}

	globalSu, stanzas := false, 0
	var (
		inStanza bool
		stanzaSu bool
		stanzaAt int
		script   string
	)
	closeStanza := func() {
		if !globalSu && !stanzaSu {
			problems = append(problems, fmt.Sprintf("the stanza at line %d (%q) has no `su <user> <group>`, and no top-level `su` comes before it, so it rotates as root through whatever the path crosses", stanzaAt+1, strings.TrimSpace(original[stanzaAt])))
		}
		inStanza = false
	}
	for i, raw := range cleaned {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if script != "" {
			if line == "endscript" {
				script = ""
			}
			continue
		}
		f := strings.Fields(line)
		if logrotateScriptWords[f[0]] {
			script = f[0]
			continue
		}
		switch {
		case !inStanza && strings.Contains(line, "{"):
			stanzas++
			inStanza, stanzaSu, stanzaAt = true, false, i
			if open, close := strings.Index(line, "{"), strings.LastIndex(line, "}"); close > open {
				// one-line stanza: `/path { daily su a b }`
				body := strings.Fields(line[open+1 : close])
				for j := 0; j+2 < len(body); j++ {
					if body[j] == "su" {
						stanzaSu = true
					}
				}
				closeStanza()
			}
		case !inStanza && f[0] == "su":
			if suOperands(line, i) {
				globalSu = true
			}
		case inStanza && strings.HasPrefix(line, "}"):
			closeStanza()
		case inStanza && f[0] == "su":
			if suOperands(line, i) {
				stanzaSu = true
			}
		}
	}
	switch {
	case script != "":
		problems = append(problems, fmt.Sprintf("script block %q has no endscript", script))
	case inStanza:
		problems = append(problems, fmt.Sprintf("the stanza at line %d is never closed", stanzaAt+1))
	case stanzas == 0:
		problems = append(problems, "no logrotate stanza found in the policy text, so `su` cannot be verified")
	}
	return problems
}

// logrotateIdentityFindings compares the sites with the two ratchet lists.
func logrotateIdentityFindings(sites []logrotateSite, allow, derived map[string]string) []string {
	var out []string
	exists := map[string]bool{}
	violating := map[string]bool{}
	isDerived := map[string]bool{}
	for _, s := range sites {
		exists[s.key] = true
		switch {
		case s.hostDerived:
			isDerived[s.key] = true
			if _, ok := derived[s.key]; !ok {
				out = append(out, fmt.Sprintf("%s (%s) puts a logrotate policy in place from a file on the target, so the guard cannot read its `su`. If the policy is not authored here, add it to logrotateHostDerivedWriters with the reason; otherwise render it with content or a src file", s.key, s.dest))
			}
		case len(s.problems) > 0:
			violating[s.key] = true
			if _, ok := allow[s.key]; !ok {
				out = append(out, fmt.Sprintf("%s (%s) does not declare the identity it rotates as: %s", s.key, s.dest, strings.Join(s.problems, "; ")))
			}
		}
	}
	for k := range allow {
		switch {
		case !exists[k]:
			out = append(out, fmt.Sprintf("allowlist entry %q no longer matches any task; remove it from logrotateIdentityAllowlist", k))
		case !violating[k]:
			out = append(out, fmt.Sprintf("allowlist entry %q now declares its rotation identity; remove it from logrotateIdentityAllowlist", k))
		}
	}
	for k := range derived {
		if !isDerived[k] {
			out = append(out, fmt.Sprintf("host-derived entry %q no longer matches a task that copies a policy from the target; remove it from logrotateHostDerivedWriters", k))
		}
	}
	sort.Strings(out)
	return out
}

// TestRegression_LogrotatePoliciesDeclareTheirRotationIdentity is the
// repository-wide guard described at the top of this file.
func TestRegression_LogrotatePoliciesDeclareTheirRotationIdentity(t *testing.T) {
	var sites []logrotateSite
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		sites = append(sites, logrotateSites(rel, path, loadYAML(t, path))...)
	}
	// The walker is not vacuous: at the time of writing log-server and
	// audit-log-forwarding render four policies between them.
	if len(sites) < 4 {
		t.Fatalf("found only %d logrotate policy writers in playbooks/**; the walker is broken: %v", len(sites), sites)
	}
	for _, p := range logrotateIdentityFindings(sites, logrotateIdentityAllowlist, logrotateHostDerivedWriters) {
		t.Error(p)
	}
}

func logrotateFixtureSites(t *testing.T, dir, name, src string) []logrotateSite {
	t.Helper()
	var doc any
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatalf("fixture does not parse: %v\n%s", err, src)
	}
	return logrotateSites(name, filepath.Join(dir, name), doc)
}

func TestLogrotateIdentityGuardParsesWhatItClaimsTo(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "templates"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"with-su.j2": "/var/log/a/*.log {\n    su a b\n}\n",
		"no-su.j2":   "/var/log/a/*.log {\n    daily\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, "templates", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// stanza is a policy with `extra` (indented four spaces) among its directives.
	stanza := func(extra string) string {
		return "/var/log/a/*.log {\n    daily\n" + extra + "    sharedscripts\n    postrotate\n        true\n    endscript\n}\n"
	}
	copyTask := func(name, dest, content string) string {
		var b strings.Builder
		b.WriteString("    - name: " + name + "\n      ansible.builtin.copy:\n        dest: " + dest + "\n        content: |\n")
		for _, l := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
			b.WriteString("          " + l + "\n")
		}
		return b.String()
	}
	play := func(vars, tasks string) string { return "- hosts: all\n  vars:\n" + vars + "  tasks:\n" + tasks }
	noSu := "has no `su <user> <group>`"

	cases := []struct {
		name string
		src  string
		want map[string]string // task name -> substring of its first problem; "" passes, "derived" is host-derived
	}{
		{"no su", play("", copyTask("t", "/etc/logrotate.d/x", stanza(""))), map[string]string{"t": noSu}},
		{"su in the stanza", play("", copyTask("t", "/etc/logrotate.d/x", stanza("    su root syslog\n"))), map[string]string{"t": ""}},
		{"jinja operands", play("", copyTask("t", "/etc/logrotate.d/x", stanza("    su {{ owner }} {{ owner }}\n"))), map[string]string{"t": ""}},
		{"top-level su before the stanza", play("", copyTask("t", "/etc/logrotate.d/x", "su root adm\n"+stanza(""))), map[string]string{"t": ""}},
		{"top-level su after the stanza does not cover it", play("", copyTask("t", "/etc/logrotate.d/x", stanza("")+"su root adm\n")), map[string]string{"t": noSu}},
		{
			"su inside postrotate is a script, not a directive",
			play("", copyTask("t", "/etc/logrotate.d/x", "/var/log/a/*.log {\n    daily\n    postrotate\n        su root adm\n    endscript\n}\n")),
			map[string]string{"t": noSu},
		},
		{
			"su in a comment",
			play("", copyTask("t", "/etc/logrotate.d/x", "/var/log/a/*.log {\n    # su root adm\n    daily\n}\n")),
			map[string]string{"t": noSu},
		},
		{
			"second stanza lacks su",
			play("", copyTask("t", "/etc/logrotate.d/x", "/a/*.log {\n    su r r\n}\n/b/*.log {\n    daily\n}\n")),
			map[string]string{"t": `("/b/*.log {")`},
		},
		{"su with one operand", play("", copyTask("t", "/etc/logrotate.d/x", stanza("    su syslog\n"))), map[string]string{"t": "is not `su <user> <group>`"}},
		{"one-line stanza", play("", copyTask("t", "/etc/logrotate.d/x", "/a/*.log { daily su r r }\n")), map[string]string{"t": ""}},
		{"dest through a play var", play("    conf: /etc/logrotate.d/y\n", copyTask("t", `"{{ conf }}"`, stanza(""))), map[string]string{"t": noSu}},
		{
			"dest through a var that names another var",
			play("    base: /etc/logrotate.d\n    conf: '{{ base }}/y'\n", copyTask("t", `"{{ conf }}"`, stanza("    su r r\n"))),
			map[string]string{"t": ""},
		},
		{
			"dest that names logrotate but cannot be resolved",
			play("", copyTask("t", `"{{ siem_logrotate_conf }}"`, stanza("    su r r\n"))),
			map[string]string{"t": "unresolvable logrotate dest"},
		},
		{
			"dest from a loop over logrotate paths",
			play("", "    - name: t\n      ansible.builtin.copy:\n        dest: \"{{ item }}\"\n        content: x\n      loop: ['/etc/logrotate.d/a']\n"),
			map[string]string{"t": "unresolvable logrotate dest"},
		},
		{"an unrelated copy with a variable dest is not a logrotate writer", play("", copyTask("t", `"{{ some_path }}"`, "x\n")), map[string]string{}},
		{"an unrelated literal dest", play("", copyTask("t", "/etc/other.conf", stanza(""))), map[string]string{}},
		{
			"content that is only an expression",
			play("", copyTask("t", "/etc/logrotate.d/x", `"{{ lookup('file', 'x') }}"`)),
			map[string]string{"t": "no logrotate stanza"},
		},
		{
			"jinja statements",
			play("", copyTask("t", "/etc/logrotate.d/x", "{% if a %}\n/a/*.log {\n    su r r\n}\n{% endif %}\n")),
			map[string]string{"t": "Jinja statements"},
		},
		{"unclosed stanza", play("", copyTask("t", "/etc/logrotate.d/x", "/a/*.log {\n    su r r\n")), map[string]string{"t": "never closed"}},
		{
			"remote_src",
			"- hosts: all\n  tasks:\n    - name: t\n      ansible.builtin.copy:\n        src: /tmp/x/policy\n        dest: /etc/logrotate.d/x\n        remote_src: true\n",
			map[string]string{"t": "derived"},
		},
		{
			"src template with su",
			"- hosts: all\n  tasks:\n    - name: t\n      ansible.builtin.template:\n        src: with-su.j2\n        dest: /etc/logrotate.d/x\n",
			map[string]string{"t": ""},
		},
		{
			"src template without su",
			"- hosts: all\n  tasks:\n    - name: t\n      template:\n        src: no-su.j2\n        dest: /etc/logrotate.d/x\n",
			map[string]string{"t": noSu},
		},
		{
			"src that is not there",
			"- hosts: all\n  tasks:\n    - name: t\n      ansible.builtin.template:\n        src: missing.j2\n        dest: /etc/logrotate.d/x\n",
			map[string]string{"t": "unresolvable logrotate source"},
		},
		{
			"free-form copy",
			"- hosts: all\n  tasks:\n    - name: t\n      copy: src=no-su.j2 dest=/etc/logrotate.d/x\n",
			map[string]string{"t": noSu},
		},
		{
			"edited in place",
			"- hosts: all\n  tasks:\n    - name: t\n      ansible.builtin.blockinfile:\n        path: /etc/logrotate.d/x\n        block: |\n          su r r\n",
			map[string]string{"t": "in place"},
		},
		{
			"block and rescue in a task file",
			`- name: t1
  block:
    - name: t
      ansible.builtin.copy:
        dest: /etc/logrotate.d/x
        content: |
          /a/*.log {
              daily
          }
  rescue:
    - name: r
      ansible.builtin.copy:
        dest: /etc/logrotate.d/y
        content: |
          /a/*.log {
              su r r
          }
`,
			map[string]string{"t": noSu, "r": ""},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := map[string]string{}
			for _, s := range logrotateFixtureSites(t, dir, "fixture.yml", tc.src) {
				name := strings.TrimPrefix(s.key, "fixture.yml::")
				switch {
				case s.hostDerived:
					got[name] = "derived"
				case len(s.problems) > 0:
					got[name] = s.problems[0]
				default:
					got[name] = ""
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("sites = %q, want %q", got, tc.want)
			}
			for name, want := range tc.want {
				g, ok := got[name]
				if !ok || (want == "" && g != "") || (want != "" && !strings.Contains(g, want)) {
					t.Errorf("site %q = %q, want %q (all: %q)", name, g, want, got)
				}
			}
		})
	}
}

func TestLogrotateIdentityFindingsRatchet(t *testing.T) {
	site := func(key string, problems ...string) logrotateSite {
		return logrotateSite{key: key, dest: "/etc/logrotate.d/x", problems: problems}
	}
	derived := logrotateSite{key: "d", dest: "/etc/logrotate.d/d", hostDerived: true}
	cases := []struct {
		name          string
		sites         []logrotateSite
		allow, derive map[string]string
		want          string // substring of the single finding, "" for none
	}{
		{name: "all declare su", sites: []logrotateSite{site("a")}},
		{name: "violation not allowlisted", sites: []logrotateSite{site("a", "no su")}, want: "a (/etc/logrotate.d/x) does not declare"},
		{name: "violation allowlisted", sites: []logrotateSite{site("a", "no su")}, allow: map[string]string{"a": "root owns it"}},
		{name: "allowlisted site now passes", sites: []logrotateSite{site("a")}, allow: map[string]string{"a": "r"}, want: "now declares its rotation identity"},
		{name: "allowlisted site is gone", sites: []logrotateSite{site("b")}, allow: map[string]string{"a": "r"}, want: "no longer matches any task"},
		{name: "host-derived not listed", sites: []logrotateSite{derived}, want: "from a file on the target"},
		{name: "host-derived listed", sites: []logrotateSite{derived}, derive: map[string]string{"d": "r"}},
		{name: "host-derived entry is gone", sites: []logrotateSite{site("a")}, derive: map[string]string{"d": "r"}, want: "no longer matches a task that copies"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := logrotateIdentityFindings(tc.sites, tc.allow, tc.derive)
			switch {
			case tc.want == "" && len(got) != 0:
				t.Fatalf("findings = %q, want none", got)
			case tc.want != "" && (len(got) != 1 || !strings.Contains(got[0], tc.want)):
				t.Fatalf("findings = %q, want one containing %q", got, tc.want)
			}
		})
	}
}
