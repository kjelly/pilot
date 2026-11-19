package spec

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// An rsyslog dynaFile builds a file name from message properties, and the
// properties of a network-received message are chosen by the sender. With no
// option, %HOSTNAME% = ".." wrote /var/log/audit.log (and, for auth, the log
// server's own /var/log/auth.log), "a/../../x" walked out of the landing
// root, and "." or an empty name wrote into the root itself (kjelly/pilot#363,
// measured on Ubuntu 24.04.4 / rsyslog 8.2312.0: the only thing that stopped a
// path was AppArmor, not rsyslog, and the blocked write also lost the next
// legitimate message on the same TCP connection).
//
// secpath-replace turns "/" into "_" and "." / ".." into "_" / "_.", so a
// property is always one path component. It has to be the ONLY option: with
// another one in the list rsyslog 8.2312 mishandles it (lowercase,secpath-
// replace turns "a//b" into "a_/b", two components again), and secpath-drop
// merges names ("a//b" becomes "ab"), so two sources share one directory.
//
// The rule below is the class: every template that a dynaFile references, in
// playbooks/**, has every property of its path rendered with exactly
// secpath-replace. It is a lint of text, so it reads what a Jinja render of the
// file would put in front of rsyslog; what the rsyslogd does with the result
// is TestRegression_LogServerReceiverKeepsHostnamePathsUnderTheRoot.
//
// What it does not see: a dynaFile built in an include file under another
// name pattern ($IncludeConfig of a file not under playbooks/**), a template
// assembled by Jinja from variables, `omfile file=` with a static path, and
// properties inside `subtree`/`plugin` templates (those are reported, not
// read).

// rsyslogSource is one piece of text the lint reads: a decoded YAML scalar or
// a whole non-YAML file.
type rsyslogSource struct {
	loc  string
	text string
}

// rsyslogTemplate is one template definition.
type rsyslogTemplate struct {
	loc, name, kind, body string
}

// rsyslogDynaRef is one dynaFile use of a template name.
type rsyslogDynaRef struct{ loc, name string }

var (
	rsyslogJinjaBlock     = regexp.MustCompile(`(?s)\{#.*?#\}|\{%.*?%\}|\{\{.*?\}\}`)
	rsyslogDynaRainer     = regexp.MustCompile(`(?i)\bdynafile\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	rsyslogDynaLegacy     = regexp.MustCompile(`(?m)^[ \t]*[A-Za-z0-9*,;.!=-]+\.[A-Za-z0-9*,;.!=-]+[ \t]+(?::omfile:)?-?\?([A-Za-z0-9_.-]+)`)
	rsyslogLegacyTemplate = regexp.MustCompile(`(?im)^[ \t]*\$template[ \t]+([^\s,]+)[ \t]*,[ \t]*"((?:[^"\\]|\\.)*)"`)
	rsyslogTemplateStart  = regexp.MustCompile(`(?i)\btemplate\s*\(`)
	rsyslogPropertyStart  = regexp.MustCompile(`(?i)\bproperty\s*\(`)
)

// rsyslogPrepare drops what rsyslog would not read or Jinja would replace
// before rsyslog sees the file, keeping line numbers: whole-line comments,
// Jinja blocks ({{ }} becomes a harmless word; {% %} and {# #} vanish).
func rsyslogPrepare(text string) string {
	text = rsyslogJinjaBlock.ReplaceAllStringFunc(text, func(block string) string {
		keep := strings.Repeat("\n", strings.Count(block, "\n"))
		if strings.HasPrefix(block, "{{") {
			return "J" + keep
		}
		return keep
	})
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n")
}

func rsyslogLine(text string, pos int) int { return 1 + strings.Count(text[:pos], "\n") }

// rsyslogParams reads key="value" / key=value pairs from just after an
// opening parenthesis, up to the closing one. Backslash escapes inside a quoted
// value are kept as written. ok is false when the text is not a parameter list.
func rsyslogParams(text string, i int) (params map[string]string, end int, ok bool) {
	params = map[string]string{}
	skip := func() {
		for i < len(text) && (unicode.IsSpace(rune(text[i])) || text[i] == ',') {
			i++
		}
	}
	for {
		skip()
		if i >= len(text) {
			return params, i, false
		}
		if text[i] == ')' {
			return params, i + 1, true
		}
		j := i
		for j < len(text) && (text[j] == '.' || text[j] == '_' || text[j] == '-' || unicode.IsLetter(rune(text[j])) || unicode.IsDigit(rune(text[j]))) {
			j++
		}
		if j == i {
			return params, i, false
		}
		key := strings.ToLower(text[i:j])
		i = j
		for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
			i++
		}
		if i >= len(text) || text[i] != '=' {
			return params, i, false
		}
		i++
		for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
			i++
		}
		if i >= len(text) {
			return params, i, false
		}
		if q := text[i]; q == '"' || q == '\'' {
			i++
			var b strings.Builder
			for i < len(text) && text[i] != q {
				if text[i] == '\\' && i+1 < len(text) {
					b.WriteByte(text[i])
					i++
				}
				b.WriteByte(text[i])
				i++
			}
			if i >= len(text) {
				return params, i, false
			}
			i++
			params[key] = b.String()
			continue
		}
		j = i
		for j < len(text) && !unicode.IsSpace(rune(text[j])) && text[j] != ')' && text[j] != ',' {
			j++
		}
		params[key] = text[i:j]
		i = j
	}
}

// rsyslogBlock returns the {...} block that starts at or after i (after
// white space), quoted strings skipped, and the index after it.
func rsyslogBlock(text string, i int) (string, int, bool) {
	for i < len(text) && unicode.IsSpace(rune(text[i])) {
		i++
	}
	if i >= len(text) || text[i] != '{' {
		return "", i, false
	}
	depth, start := 0, i+1
	for ; i < len(text); i++ {
		switch text[i] {
		case '"', '\'':
			q := text[i]
			for i++; i < len(text) && text[i] != q; i++ {
				if text[i] == '\\' {
					i++
				}
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return text[start:i], i + 1, true
			}
		}
	}
	return "", i, false
}

// scanRsyslog returns the template definitions and dynaFile references in src.
func scanRsyslog(src rsyslogSource) ([]rsyslogTemplate, []rsyslogDynaRef) {
	text := rsyslogPrepare(src.text)
	at := func(pos int) string { return fmt.Sprintf("%s+%d", src.loc, rsyslogLine(text, pos)) }
	var tpls []rsyslogTemplate
	var refs []rsyslogDynaRef
	for _, m := range rsyslogTemplateStart.FindAllStringIndex(text, -1) {
		params, end, ok := rsyslogParams(text, m[1])
		if !ok || params["name"] == "" {
			continue
		}
		kind := strings.ToLower(params["type"])
		if _, hasString := params["string"]; kind == "" && hasString {
			kind = "string"
		}
		if kind == "" {
			continue
		}
		t := rsyslogTemplate{loc: at(m[0]), name: params["name"], kind: kind}
		switch kind {
		case "string":
			t.body = params["string"]
		default:
			if block, _, ok := rsyslogBlock(text, end); ok {
				t.body = block
			}
		}
		tpls = append(tpls, t)
	}
	for _, m := range rsyslogLegacyTemplate.FindAllStringSubmatchIndex(text, -1) {
		tpls = append(tpls, rsyslogTemplate{loc: at(m[0]), name: text[m[2]:m[3]], kind: "string", body: text[m[4]:m[5]]})
	}
	for _, m := range rsyslogDynaRainer.FindAllStringSubmatchIndex(text, -1) {
		name := ""
		for _, g := range []int{2, 4} {
			if m[g] >= 0 {
				name = text[m[g]:m[g+1]]
			}
		}
		refs = append(refs, rsyslogDynaRef{loc: at(m[0]), name: name})
	}
	for _, m := range rsyslogDynaLegacy.FindAllStringSubmatchIndex(text, -1) {
		refs = append(refs, rsyslogDynaRef{loc: at(m[0]), name: text[m[2]:m[3]]})
	}
	return tpls, refs
}

// rsyslogStringProperties returns the %property% expressions of a string
// template, without their percent signs. A backslash escapes the next
// character (a literal percent sign is \%).
func rsyslogStringProperties(s string) (props []string, unterminated bool) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '%':
			j := i + 1
			for j < len(s) && s[j] != '%' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(s) {
				return props, true
			}
			props = append(props, s[i+1:j])
			i = j
		}
	}
	return props, false
}

// rsyslogPathIssues says what is wrong with a template that names a file.
func rsyslogPathIssues(t rsyslogTemplate) []string {
	var issues []string
	switch t.kind {
	case "string":
		props, unterminated := rsyslogStringProperties(t.body)
		if unterminated {
			issues = append(issues, fmt.Sprintf("has a property without its closing %% in %q", t.body))
		}
		for _, p := range props {
			parts := strings.Split(p, ":")
			opts := ""
			if len(parts) >= 4 {
				opts = strings.Join(parts[3:], ":")
			}
			if opts != "secpath-replace" {
				issues = append(issues, fmt.Sprintf("writes %%%s%% into a file path with the options %q; want exactly \"secpath-replace\" (a path is one component, and only this option alone does that on rsyslog 8.2312)", p, opts))
			}
		}
	case "list":
		for _, m := range rsyslogPropertyStart.FindAllStringIndex(t.body, -1) {
			params, _, ok := rsyslogParams(t.body, m[1])
			if !ok {
				issues = append(issues, "has a property(...) statement this lint cannot read")
				continue
			}
			if !strings.EqualFold(params["securepath"], "replace") {
				issues = append(issues, fmt.Sprintf("writes property(name=%q) into a file path with securePath=%q; want \"replace\"", params["name"], params["securepath"]))
			}
		}
	default:
		issues = append(issues, fmt.Sprintf("is type=%q, which this lint cannot read; write the path as type=\"string\" or type=\"list\"", t.kind))
	}
	return issues
}

// rsyslogDynaFileLint returns the problems in srcs and the names of the
// templates a dynaFile references.
func rsyslogDynaFileLint(srcs []rsyslogSource) (problems, referenced []string) {
	defs := map[string][]rsyslogTemplate{}
	var refs []rsyslogDynaRef
	for _, s := range srcs {
		t, r := scanRsyslog(s)
		for _, d := range t {
			defs[d.name] = append(defs[d.name], d)
		}
		refs = append(refs, r...)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].loc < refs[j].loc })
	seen := map[string]bool{}
	names := map[string]bool{}
	for _, r := range refs {
		names[r.name] = true
		ds := defs[r.name]
		if len(ds) == 0 {
			problems = append(problems, fmt.Sprintf("%s: dynaFile uses template %q, which is defined nowhere in the files scanned, so its path properties cannot be checked", r.loc, r.name))
			continue
		}
		for _, d := range ds {
			for _, issue := range rsyslogPathIssues(d) {
				key := d.loc + issue
				if seen[key] {
					continue
				}
				seen[key] = true
				problems = append(problems, fmt.Sprintf("%s: template %q (dynaFile at %s) %s", d.loc, d.name, r.loc, issue))
			}
		}
	}
	for n := range names {
		referenced = append(referenced, n)
	}
	sort.Strings(referenced)
	return problems, referenced
}

// rsyslogSourcesUnder reads every text file below dir: the decoded scalars of
// the YAML files, the whole text of anything else.
func rsyslogSourcesUnder(t *testing.T, dir string) []rsyslogSource {
	t.Helper()
	var srcs []rsyslogSource
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(raw, 0) >= 0 {
			return nil
		}
		if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
			var doc yaml.Node
			if err := yaml.Unmarshal(raw, &doc); err != nil {
				return fmt.Errorf("%s: parse: %w", path, err)
			}
			walkScalars(&doc, func(n *yaml.Node) {
				srcs = append(srcs, rsyslogSource{loc: fmt.Sprintf("%s:%d", path, n.Line), text: n.Value})
			})
			return nil
		}
		srcs = append(srcs, rsyslogSource{loc: path, text: string(raw)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return srcs
}

// TestRegression_RsyslogDynaFilePathsAreSecpathReplaced is the repo-wide rule
// of kjelly/pilot#363: every template a dynaFile in playbooks/** uses has every
// property of its path rendered with exactly secpath-replace.
func TestRegression_RsyslogDynaFilePathsAreSecpathReplaced(t *testing.T) {
	problems, referenced := rsyslogDynaFileLint(rsyslogSourcesUnder(t, "../../playbooks"))
	for _, p := range problems {
		t.Error(p)
	}
	// The scan has to be seeing the receiver's three path templates; a
	// scanner that finds nothing would pass anything.
	for _, want := range []string{"SiemAuditPath", "SiemAuthPath", "SiemWazuhPath"} {
		found := false
		for _, name := range referenced {
			found = found || name == want
		}
		if !found {
			t.Errorf("the lint did not see a dynaFile using %s (saw %v); the scanner is broken or the template moved", want, referenced)
		}
	}
}

// TestRsyslogDynaFileLintCases: what the lint above accepts and what it
// reports, on hand-written text. The pass cases are the shapes a path
// template legitimately takes; each trigger case is a way to put sender-chosen
// text into a path that the real rsyslogd measured to be unsafe or to
// misbehave.
func TestRsyslogDynaFileLintCases(t *testing.T) {
	const root = "{{ siem_log_root }}"
	route := func(name string) string {
		return `ruleset(name="r") { action(type="omfile" dynaFile="` + name + `" createDirs="on") }` + "\n"
	}
	str := func(name, path string) string {
		return `template(name="` + name + `" type="string" string="` + path + `")` + "\n"
	}
	for _, tc := range []struct {
		name string
		srcs []string
		want []string // substrings every problem set must contain; none = no problem
	}{
		// What passes.
		{"secpath-replace alone", []string{str("P", root+"/%HOSTNAME:::secpath-replace%/audit.log") + route("P")}, nil},
		{"every property carries it", []string{str("P", "/v/%HOSTNAME:::secpath-replace%/%programname:::secpath-replace%.log") + route("P")}, nil},
		{"positions before the option", []string{str("P", "/v/%HOSTNAME:2:20:secpath-replace%/a.log") + route("P")}, nil},
		{"static path", []string{str("P", "/var/log/fixed.log") + route("P")}, nil},
		{"literal percent signs", []string{str("P", `/v/50\%/%HOSTNAME:::secpath-replace%/a.log`) + route("P")}, nil},
		{"lowercase dynafile spelling", []string{str("P", "/v/%HOSTNAME:::secpath-replace%/a.log") + `action(type="omfile" dynafile="P")` + "\n"}, nil},
		{"template without a dynaFile is a message format, not a path", []string{str("Fmt", `%msg:::drop-last-lf%\n`) + str("P", "/v/%HOSTNAME:::secpath-replace%/a.log") + route("P")}, nil},
		{"template defined in another file", []string{route("P"), str("P", "/v/%HOSTNAME:::secpath-replace%/a.log")}, nil},
		{"Jinja around the template", []string{"{% if x %}\n" + str("P", root+"/%HOSTNAME:::secpath-replace%/a.log") + "{% endif %}\n" + route("P")}, nil},
		{"unsafe dynaFile in a comment", []string{"# " + str("P", "/v/%HOSTNAME%/a.log") + `# action(type="omfile" dynaFile="P")` + "\n"}, nil},
		{"list template with securePath", []string{`template(name="L" type="list") {
    constant(value="/v/")
    property(name="hostname" securePath="replace")
    constant(value="/a.log")
}
` + route("L")}, nil},
		{"legacy $template with the option", []string{`$template L,"/v/%HOSTNAME:::secpath-replace%/a.log"` + "\n" + `local6.* ?L` + "\n"}, nil},

		// What it reports.
		{"bare %HOSTNAME% (the receiver before #363)", []string{str("SiemAuditPath", root+"/%HOSTNAME%/audit.log") + route("SiemAuditPath")}, []string{`template "SiemAuditPath"`, "%HOSTNAME%", `options ""`}},
		{"another option", []string{str("P", "/v/%HOSTNAME:::lowercase%/a.log") + route("P")}, []string{"lowercase"}},
		{"secpath-replace combined with another option (a//b -> a_/b on 8.2312)", []string{str("P", "/v/%HOSTNAME:::lowercase,secpath-replace%/a.log") + route("P")}, []string{"lowercase,secpath-replace"}},
		{"secpath-replace listed first", []string{str("P", "/v/%HOSTNAME:::secpath-replace,lowercase%/a.log") + route("P")}, []string{"secpath-replace,lowercase"}},
		{"secpath-drop merges names", []string{str("P", "/v/%HOSTNAME:::secpath-drop%/a.log") + route("P")}, []string{"secpath-drop"}},
		{"only one of two properties is safe", []string{str("P", "/v/%HOSTNAME:::secpath-replace%/%programname%.log") + route("P")}, []string{"%programname%"}},
		{"another property in the path", []string{str("P", "/v/%fromhost-ip%/a.log") + route("P")}, []string{"%fromhost-ip%"}},
		{"a date property is a property too", []string{str("P", "/v/%$year%/a.log") + route("P")}, []string{"%$year%"}},
		{"property that never closes", []string{str("P", "/v/%HOSTNAME/a.log") + route("P")}, []string{"closing"}},
		{"single-quoted dynaFile", []string{str("P", "/v/%HOSTNAME%/a.log") + `action(type="omfile" dynaFile='P')` + "\n"}, []string{`template "P"`}},
		{"unsafe template defined in another file", []string{route("P"), str("P", "/v/%HOSTNAME%/a.log")}, []string{`template "P"`}},
		{"a second, unsafe definition of the same name", []string{str("P", "/v/%HOSTNAME:::secpath-replace%/a.log") + route("P"), str("P", "/w/%HOSTNAME%/a.log")}, []string{"case1+"}},
		{"list template without securePath", []string{`template(name="L" type="list") {
    constant(value="/v/")
    property(name="hostname")
}
` + route("L")}, []string{`property(name="hostname")`}},
		{"list template with another securePath", []string{`template(name="L" type="list") {
    property(name="hostname" securePath="drop")
}
` + route("L")}, []string{`securePath="drop"`}},
		{"legacy $template with a bare property", []string{`$template L,"/v/%HOSTNAME%/a.log"` + "\n" + `local6.* ?L` + "\n"}, []string{`template "L"`}},
		{"legacy action with a format after the template", []string{`$template L,"/v/%HOSTNAME%/a.log"` + "\n" + `*.* -?L;RSYSLOG_TraditionalFileFormat` + "\n"}, []string{`template "L"`}},
		{"dynaFile template that is defined nowhere", []string{route("Missing")}, []string{"defined nowhere"}},
		{"subtree template", []string{`template(name="S" type="subtree" subtree="$!path")` + "\n" + route("S")}, []string{`type="subtree"`}},
		{"unsafe template behind Jinja", []string{"{% if x %}\n" + str("P", root+"/%HOSTNAME%/a.log") + "{% endif %}\n" + route("P")}, []string{`template "P"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var srcs []rsyslogSource
			for i, text := range tc.srcs {
				srcs = append(srcs, rsyslogSource{loc: fmt.Sprintf("case%d", i), text: text})
			}
			problems, _ := rsyslogDynaFileLint(srcs)
			joined := strings.Join(problems, "\n")
			if tc.want == nil {
				if len(problems) > 0 {
					t.Errorf("want no problem, got:\n%s", joined)
				}
				return
			}
			if len(problems) == 0 {
				t.Fatalf("want a problem containing %q, got none", tc.want)
			}
			for _, w := range tc.want {
				if !strings.Contains(joined, w) {
					t.Errorf("problems do not mention %q:\n%s", w, joined)
				}
			}
		})
	}
}
