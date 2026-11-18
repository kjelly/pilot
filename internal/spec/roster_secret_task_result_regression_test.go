package spec

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRegression_RosterCredentialsStayOutOfTaskResults is a repo-wide lint over
// playbooks/**: a task that is not no_log never holds a credential of the
// canonical roster (freeipa.admin.password, users[].password.initial) or of the
// legacy ipa_users (password, force_password, preserve_existing) in what
// Ansible prints of its result.
//
// Ansible prints a task's result at -v and at every verbosity for a failed or
// skipped iteration; a JSON/YAML stdout callback and ANSIBLE_LOG_PATH keep it.
// What a result carries is not only its module output: a loop prints its whole
// `item` (loop_control.label only changes the prefix of the line, a failed
// iteration prints the item at the default verbosity too), set_fact prints its
// facts, `debug` and `fail` print their message, and -vvv prints the module
// arguments (`invocation`). So for every task that is not no_log the lint
// reads the loop (`loop`, `with_*`), the set_fact values and the module
// arguments (an assert's `that`, `fail_msg` and `success_msg` are conditions
// and messages about a failed check, not read), with the task's own `vars:`,
// and follows a credential through set_fact and through the register of a
// loop (`x.results[].item`).
//
// The roster's credential paths are freeipa.admin.password and users[]; the
// lint is path-sensitive, so `freeipa_roster.groups`, `freeipa_roster.freeipa.server`
// and `freeipa_roster.users | map(attribute='name')` are clean while
// `freeipa_roster`, `freeipa_roster.freeipa`, `freeipa_roster.freeipa.admin`
// and `freeipa_roster.users` are not. A task that needs no credential iterates
// a credential-free projection, so that its failures stay readable (issue
// #216); only the tasks that need the credential are no_log.
//
// What counts as a projection is closed and small, so that a new spelling is a
// finding rather than a silent pass: an attribute that is not a credential
// (name, state, ssh_keys, stdout, rc, ...), `map(attribute=<such>)`, `length`,
// `count`, a test or comparison, and the one rejectattr idiom
//
//	| map('dict2items') | map('rejectattr', 'key', 'in', <keys>) | map('items2dict')
//
// whose key list equals the keys freeipa-identity-normalize-users-groups.yml
// writes when it produces the credentials (credentialKeysOfNormalizer).
//
// Limits: a credential reached through `hostvars[...]`/`vars[...]`/
// `lookup('vars')`, or through the register of a task that is not a loop, is
// not followed, and a play's own `vars:` never shadow a credential root (the
// play's `ipa_users: []` is the default the run's facts and -e replace). Issue
// #378 tracks RedactSecrets on nested mappings, a separate defect.
func TestRegression_RosterCredentialsStayOutOfTaskResults(t *testing.T) {
	keys := credentialKeysOfNormalizer(t, "../..")
	scan := scanRosterCredentialSites(t, "../..", keys)
	for _, problem := range rosterCredentialProblems(scan.findings, rosterCredentialAllowlist) {
		t.Error(problem)
	}
	// The scan has to see the tasks it exists for: a parser that reads nothing
	// passes everything.
	if scan.tasks < 2500 || scan.loops < 300 || scan.setFacts < 350 || scan.noLogCredentialTasks < 12 {
		t.Fatalf("the scan read %d tasks, %d loops, %d set_fact tasks and found %d no_log tasks over a credential; the detection is broken",
			scan.tasks, scan.loops, scan.setFacts, scan.noLogCredentialTasks)
	}
	t.Logf("read %d tasks (%d loops, %d set_fact), %d no_log tasks over a credential", scan.tasks, scan.loops, scan.setFacts, scan.noLogCredentialTasks)
	if scan.unparsed > 0 {
		t.Errorf("%d expressions could not be parsed and mention a credential: %v", scan.unparsed, scan.unparsedExprs)
	}
}

// rosterCredentialAllowlist lists "<path>::<task name>" findings that stay on
// purpose, each with its reason. The lint fails for a finding that is not
// here and for an entry that no longer matches one, so the list only shrinks.
var rosterCredentialAllowlist = map[string]string{}

// rosterCredentialProblems compares the findings, keyed "<path>::<task>", with
// the allowlist.
func rosterCredentialProblems(findings map[string][]string, allow map[string]string) []string {
	var problems []string
	for key, why := range findings {
		if _, ok := allow[key]; ok {
			continue
		}
		problems = append(problems, fmt.Sprintf("%s prints a roster credential in a task result and is not no_log (%s). Iterate or set a credential-free projection, or make the task no_log when it needs the credential (AGENTS.md §4.5 point 17, issues #142, #216)", key, strings.Join(why, "; ")))
	}
	for key := range allow {
		if _, ok := findings[key]; !ok {
			problems = append(problems, fmt.Sprintf("allowlist entry %q no longer matches a finding; remove it", key))
		}
	}
	sort.Strings(problems)
	return problems
}

// ---- credential model ----

// A taintTree describes which part of a value carries a credential. nil is a
// value that carries none. full means everything reachable from the value may
// be a credential (a user dict with its password, a list of such dicts, a
// loop result); otherwise only the named children are.
type taintTree struct {
	full bool
	kids map[string]*taintTree
}

var taintFull = &taintTree{full: true}

// rosterTaint is the canonical roster: freeipa.admin.password and the users
// are credentials, every other path (groups, hosts, hbac, sudo, nfs,
// freeipa.server, ...) is not.
func rosterTaint() *taintTree {
	return &taintTree{kids: map[string]*taintTree{
		"freeipa": {kids: map[string]*taintTree{"admin": {kids: map[string]*taintTree{"password": taintFull}}}},
		"users":   taintFull,
	}}
}

// credentialRoots are the names that carry a credential wherever they are
// read: the roster, the legacy and the normalized users, and the list of the
// active users that declare a password.
func credentialRoots() map[string]*taintTree {
	return map[string]*taintTree{
		"freeipa_roster":              rosterTaint(),
		"ipa_users":                   taintFull,
		"ipa_active_user_credentials": taintFull,
	}
}

// cleanLeafAttrs are the attributes of a user (normalized or from the roster)
// and of a task result that are never a credential: reading one of them from
// a value that carries a credential reads no credential. Everything else is
// treated as the credential's container (`password`, `item`, `results`, ...).
var cleanLeafAttrs = map[string]bool{
	"name": true, "state": true, "first": true, "last": true, "display_name": true, "email": true,
	"uid": true, "gid": true, "login_shell": true, "home_directory": true, "enabled": true,
	"ssh_keys": true, "groups": true, "desc": true,
	"stdout": true, "stderr": true, "stdout_lines": true, "stderr_lines": true, "rc": true,
	"skipped": true, "failed": true, "changed": true,
}

// cleanResultFilters are the filters whose result carries nothing of their
// input that could be a credential.
var cleanResultFilters = map[string]bool{
	"length": true, "count": true, "bool": true, "int": true, "float": true, "type_debug": true,
}

func unionTaint(ts ...*taintTree) *taintTree {
	var out *taintTree
	for _, t := range ts {
		switch {
		case t == nil:
		case out == nil:
			out = t
		case out.full || t.full:
			out = taintFull
		default:
			merged := &taintTree{kids: map[string]*taintTree{}}
			for k, v := range out.kids {
				merged.kids[k] = v
			}
			for k, v := range t.kids {
				merged.kids[k] = unionTaint(merged.kids[k], v)
			}
			out = merged
		}
	}
	return out
}

func attrTaint(t *taintTree, name string) *taintTree {
	switch {
	case t == nil:
		return nil
	case t.full:
		if cleanLeafAttrs[name] {
			return nil
		}
		return t
	default:
		return t.kids[name]
	}
}

// anyChildTaint is the taint of an element picked by a key that is not known.
func anyChildTaint(t *taintTree) *taintTree {
	if t == nil || t.full {
		return t
	}
	var all []*taintTree
	for _, k := range t.kids {
		all = append(all, k)
	}
	return unionTaint(all...)
}

// ---- Jinja expressions ----

type jtoken struct {
	kind string // name, num, str, op
	text string
}

type jnode struct {
	kind string // name const list tuple dict attr index slice call filter test bin not neg cond
	name string // name; attr; filter/test name; operator
	val  any    // const
	kids []*jnode
	kw   map[string]*jnode
}

func jlex(s string) ([]jtoken, error) {
	var out []jtoken
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '\'' || c == '"':
			j := i + 1
			var b strings.Builder
			for j < len(s) && s[j] != c {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("unterminated string in %q", s)
			}
			out = append(out, jtoken{"str", b.String()})
			i = j + 1
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '.' && j+1 < len(s) && s[j+1] >= '0' && s[j+1] <= '9') {
				j++
			}
			out = append(out, jtoken{"num", s[i:j]})
			i = j
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			j := i
			for j < len(s) && (s[j] == '_' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			out = append(out, jtoken{"name", s[i:j]})
			i = j
		default:
			if i+1 < len(s) {
				if two := s[i : i+2]; two == "==" || two == "!=" || two == "<=" || two == ">=" || two == "//" || two == "**" {
					out = append(out, jtoken{"op", two})
					i += 2
					continue
				}
			}
			if strings.ContainsRune("+-*/%~|.,:()[]{}<>=", rune(c)) {
				out = append(out, jtoken{"op", string(c)})
				i++
				continue
			}
			return nil, fmt.Errorf("unexpected %q in %q", c, s)
		}
	}
	return out, nil
}

type jparser struct {
	toks []jtoken
	pos  int
}

func parseJinja(s string) (*jnode, error) {
	toks, err := jlex(s)
	if err != nil {
		return nil, err
	}
	p := &jparser{toks: toks}
	n, err := p.cond()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("trailing %q in %q", p.toks[p.pos].text, s)
	}
	return n, nil
}

func (p *jparser) peek() jtoken {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return jtoken{}
}

func (p *jparser) is(kind, text string) bool {
	t := p.peek()
	return t.kind == kind && t.text == text
}

func (p *jparser) eat(kind, text string) bool {
	if p.is(kind, text) {
		p.pos++
		return true
	}
	return false
}

func (p *jparser) want(kind, text string) error {
	if !p.eat(kind, text) {
		return fmt.Errorf("expected %q, found %q", text, p.peek().text)
	}
	return nil
}

func (p *jparser) cond() (*jnode, error) {
	a, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.eat("name", "if") {
		test, err := p.or()
		if err != nil {
			return nil, err
		}
		kids := []*jnode{a, test}
		if p.eat("name", "else") {
			b, err := p.cond()
			if err != nil {
				return nil, err
			}
			kids = append(kids, b)
		}
		return &jnode{kind: "cond", kids: kids}, nil
	}
	return a, nil
}

func (p *jparser) or() (*jnode, error) {
	l, err := p.and()
	for err == nil && p.eat("name", "or") {
		var r *jnode
		if r, err = p.and(); err == nil {
			l = &jnode{kind: "bin", name: "or", kids: []*jnode{l, r}}
		}
	}
	return l, err
}

func (p *jparser) and() (*jnode, error) {
	l, err := p.not()
	for err == nil && p.eat("name", "and") {
		var r *jnode
		if r, err = p.not(); err == nil {
			l = &jnode{kind: "bin", name: "and", kids: []*jnode{l, r}}
		}
	}
	return l, err
}

func (p *jparser) not() (*jnode, error) {
	if p.eat("name", "not") {
		x, err := p.not()
		return &jnode{kind: "not", kids: []*jnode{x}}, err
	}
	return p.cmp()
}

func (p *jparser) cmp() (*jnode, error) {
	l, err := p.add()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		switch {
		case t.kind == "op" && (t.text == "==" || t.text == "!=" || t.text == "<" || t.text == ">" || t.text == "<=" || t.text == ">="):
			p.pos++
			r, err := p.add()
			if err != nil {
				return nil, err
			}
			l = &jnode{kind: "bin", name: t.text, kids: []*jnode{l, r}}
		case t.kind == "name" && t.text == "in",
			t.kind == "name" && t.text == "not" && p.pos+1 < len(p.toks) && p.toks[p.pos+1].text == "in":
			if t.text == "not" {
				p.pos++
			}
			p.pos++
			r, err := p.add()
			if err != nil {
				return nil, err
			}
			l = &jnode{kind: "bin", name: "in", kids: []*jnode{l, r}}
		case t.kind == "name" && t.text == "is":
			p.pos++
			p.eat("name", "not")
			name := p.peek()
			if name.kind != "name" {
				return nil, fmt.Errorf("expected a test name, found %q", name.text)
			}
			p.pos++
			test := &jnode{kind: "test", name: name.text, kids: []*jnode{l}}
			switch next := p.peek(); {
			case next.kind == "op" && next.text == "(":
				p.pos++
				if err := p.args(test); err != nil {
					return nil, err
				}
			case next.kind == "str" || next.kind == "num" || next.kind == "name" &&
				!slices.Contains([]string{"and", "or", "if", "else", "in", "is", "not"}, next.text):
				arg, err := p.unary()
				if err != nil {
					return nil, err
				}
				test.kids = append(test.kids, arg)
			}
			l = test
		default:
			return l, nil
		}
	}
}

func (p *jparser) add() (*jnode, error) {
	l, err := p.mul()
	for err == nil {
		t := p.peek()
		if t.kind != "op" || (t.text != "+" && t.text != "-" && t.text != "~") {
			break
		}
		p.pos++
		var r *jnode
		if r, err = p.mul(); err == nil {
			l = &jnode{kind: "bin", name: t.text, kids: []*jnode{l, r}}
		}
	}
	return l, err
}

func (p *jparser) mul() (*jnode, error) {
	l, err := p.unary()
	for err == nil {
		t := p.peek()
		if t.kind != "op" || (t.text != "*" && t.text != "/" && t.text != "//" && t.text != "%" && t.text != "**") {
			break
		}
		p.pos++
		var r *jnode
		if r, err = p.unary(); err == nil {
			l = &jnode{kind: "bin", name: t.text, kids: []*jnode{l, r}}
		}
	}
	return l, err
}

func (p *jparser) unary() (*jnode, error) {
	if t := p.peek(); t.kind == "op" && (t.text == "-" || t.text == "+") {
		p.pos++
		x, err := p.unary()
		return &jnode{kind: "neg", kids: []*jnode{x}}, err
	}
	n, err := p.postfix()
	if err != nil {
		return nil, err
	}
	for p.is("op", "|") {
		p.pos++
		name := p.peek()
		if name.kind != "name" {
			return nil, fmt.Errorf("expected a filter name, found %q", name.text)
		}
		p.pos++
		// A dotted filter name (ansible.builtin.default).
		fname := name.text
		for p.is("op", ".") && p.pos+1 < len(p.toks) && p.toks[p.pos+1].kind == "name" {
			fname += "." + p.toks[p.pos+1].text
			p.pos += 2
		}
		fname = fname[strings.LastIndex(fname, ".")+1:]
		f := &jnode{kind: "filter", name: fname, kids: []*jnode{n}}
		if p.eat("op", "(") {
			if err := p.args(f); err != nil {
				return nil, err
			}
		}
		n = f
	}
	return n, nil
}

// args reads call arguments up to the closing parenthesis into n.kids, and
// keyword arguments into n.kw.
func (p *jparser) args(n *jnode) error {
	for !p.eat("op", ")") {
		if t := p.peek(); t.kind == "name" && p.pos+1 < len(p.toks) && p.toks[p.pos+1].kind == "op" && p.toks[p.pos+1].text == "=" {
			p.pos += 2
			v, err := p.cond()
			if err != nil {
				return err
			}
			if n.kw == nil {
				n.kw = map[string]*jnode{}
			}
			n.kw[t.text] = v
		} else {
			v, err := p.cond()
			if err != nil {
				return err
			}
			n.kids = append(n.kids, v)
		}
		if !p.is("op", ")") {
			if err := p.want("op", ","); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *jparser) postfix() (*jnode, error) {
	n, err := p.primary()
	if err != nil {
		return nil, err
	}
	for {
		switch {
		case p.is("op", "."):
			p.pos++
			t := p.peek()
			if t.kind != "name" && t.kind != "num" {
				return nil, fmt.Errorf("expected an attribute, found %q", t.text)
			}
			p.pos++
			if t.kind == "num" {
				n = &jnode{kind: "index", kids: []*jnode{n, {kind: "const", val: t.text}}}
			} else {
				n = &jnode{kind: "attr", name: t.text, kids: []*jnode{n}}
			}
		case p.is("op", "["):
			p.pos++
			var idx []*jnode
			for !p.is("op", "]") {
				if p.eat("op", ":") {
					continue
				}
				v, err := p.cond()
				if err != nil {
					return nil, err
				}
				idx = append(idx, v)
				if p.is("op", ":") {
					continue
				}
				if !p.is("op", "]") {
					return nil, fmt.Errorf("expected ], found %q", p.peek().text)
				}
			}
			p.pos++
			if len(idx) == 1 && idx[0].kind != "slice" {
				n = &jnode{kind: "index", kids: []*jnode{n, idx[0]}}
			} else {
				n = &jnode{kind: "slice", kids: append([]*jnode{n}, idx...)}
			}
		case p.is("op", "("):
			p.pos++
			call := &jnode{kind: "call", kids: []*jnode{n}}
			if err := p.args(call); err != nil {
				return nil, err
			}
			n = call
		default:
			return n, nil
		}
	}
}

func (p *jparser) primary() (*jnode, error) {
	t := p.peek()
	switch {
	case t.kind == "name":
		p.pos++
		switch t.text {
		case "true", "True", "false", "False", "none", "None":
			return &jnode{kind: "const", val: t.text}, nil
		}
		return &jnode{kind: "name", name: t.text}, nil
	case t.kind == "num":
		p.pos++
		return &jnode{kind: "const", val: t.text}, nil
	case t.kind == "str":
		p.pos++
		// Adjacent string literals concatenate, as in Jinja.
		val := t.text
		for p.peek().kind == "str" {
			val += p.peek().text
			p.pos++
		}
		return &jnode{kind: "const", val: val}, nil
	case t.kind == "op" && t.text == "(":
		p.pos++
		var items []*jnode
		comma := false
		for !p.eat("op", ")") {
			v, err := p.cond()
			if err != nil {
				return nil, err
			}
			items = append(items, v)
			if p.eat("op", ",") {
				comma = true
			} else if !p.is("op", ")") {
				return nil, fmt.Errorf("expected ), found %q", p.peek().text)
			}
		}
		if len(items) == 1 && !comma {
			return items[0], nil
		}
		return &jnode{kind: "tuple", kids: items}, nil
	case t.kind == "op" && t.text == "[":
		p.pos++
		var items []*jnode
		for !p.eat("op", "]") {
			v, err := p.cond()
			if err != nil {
				return nil, err
			}
			items = append(items, v)
			if !p.eat("op", ",") && !p.is("op", "]") {
				return nil, fmt.Errorf("expected ], found %q", p.peek().text)
			}
		}
		return &jnode{kind: "list", kids: items}, nil
	case t.kind == "op" && t.text == "{":
		p.pos++
		var items []*jnode
		for !p.eat("op", "}") {
			k, err := p.cond()
			if err != nil {
				return nil, err
			}
			if err := p.want("op", ":"); err != nil {
				return nil, err
			}
			v, err := p.cond()
			if err != nil {
				return nil, err
			}
			items = append(items, k, v)
			if !p.eat("op", ",") && !p.is("op", "}") {
				return nil, fmt.Errorf("expected }, found %q", p.peek().text)
			}
		}
		return &jnode{kind: "dict", kids: items}, nil
	}
	return nil, fmt.Errorf("unexpected %q", t.text)
}

// ---- templates ----

// templateExprs returns the expression text of each {{ }} and of each
// {% %} tag of a string, and whether the string has a template at all. {# #}
// comments are dropped.
func templateExprs(s string) (exprs []string, stmts []string, found bool) {
	for i := 0; i+1 < len(s); {
		if s[i] != '{' || (s[i+1] != '{' && s[i+1] != '%' && s[i+1] != '#') {
			i++
			continue
		}
		open := s[i+1]
		closer := map[byte]string{'{': "}}", '%': "%}", '#': "#}"}[open]
		end := templateClose(s, i+2, open, closer)
		if end < 0 {
			break
		}
		body := strings.Trim(s[i+2:end], "-+ \t\r\n")
		switch open {
		case '{':
			exprs = append(exprs, body)
		case '%':
			stmts = append(stmts, body)
		}
		found = true
		i = end + len(closer)
	}
	return exprs, stmts, found
}

// templateClose finds the end of the tag that opens before from: the closer
// outside a string and, for {{ }}, outside a dict literal's braces. -1 when
// the tag is not closed.
func templateClose(s string, from int, open byte, closer string) int {
	depth := 0
	var quote byte
	for j := from; j < len(s); j++ {
		c := s[j]
		switch {
		case quote != 0:
			if c == '\\' {
				j++
			} else if c == quote {
				quote = 0
			}
		case open != '#' && (c == '\'' || c == '"'):
			quote = c
		case open == '{' && c == '{':
			depth++
		case open == '{' && c == '}' && depth > 0:
			depth--
		case depth == 0 && strings.HasPrefix(s[j:], closer):
			return j
		}
	}
	return -1
}

// stmtExpr is the expression of a {% %} tag that has one: if/elif conditions
// are booleans and read as such; for/set carry a value into the template.
func stmtExpr(stmt string) (string, bool) {
	fields := strings.Fields(stmt)
	if len(fields) == 0 {
		return "", false
	}
	switch fields[0] {
	case "for":
		if i := strings.Index(stmt, " in "); i >= 0 {
			rest := stmt[i+4:]
			if j := strings.LastIndex(rest, " if "); j >= 0 {
				rest = rest[:j]
			}
			return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), "recursive")), true
		}
	case "set":
		if i := strings.Index(stmt, "="); i >= 0 {
			return strings.TrimSpace(stmt[i+1:]), true
		}
	}
	return "", false
}

// ---- evaluation ----

type taintEval struct {
	global   map[string]*taintTree
	keys     []string // the credential keys the normalizer writes
	scope    []map[string]any
	local    map[string]*taintTree
	visiting map[string]bool

	unparsed      int
	unparsedExprs []string
}

func (e *taintEval) lookup(name string) *taintTree {
	if t, ok := e.local[name]; ok {
		return t
	}
	for i := len(e.scope) - 1; i >= 0; i-- {
		if raw, ok := e.scope[i][name]; ok {
			if e.visiting[name] {
				return nil
			}
			e.visiting[name] = true
			defer delete(e.visiting, name)
			return e.value(raw)
		}
	}
	return e.global[name]
}

// value is the taint of a YAML value: a string is a template, a collection is
// the union of its members.
func (e *taintEval) value(v any) *taintTree {
	switch x := v.(type) {
	case string:
		return e.template(x, false)
	case []any:
		var ts []*taintTree
		for _, each := range x {
			ts = append(ts, e.value(each))
		}
		return unionTaint(ts...)
	case map[string]any:
		var ts []*taintTree
		for _, each := range x {
			ts = append(ts, e.value(each))
		}
		return unionTaint(ts...)
	}
	return nil
}

// template is the taint of a string with {{ }} and {% %}: the union of its
// expressions. A tag's loop and set values count as the template's.
func (e *taintEval) template(s string, bare bool) *taintTree {
	exprs, stmts, found := templateExprs(s)
	if !found {
		if bare && strings.TrimSpace(s) != "" {
			exprs = []string{s}
		} else {
			return nil
		}
	}
	for _, st := range stmts {
		if expr, ok := stmtExpr(st); ok {
			exprs = append(exprs, expr)
		}
	}
	var ts []*taintTree
	for _, expr := range exprs {
		ts = append(ts, e.expr(expr))
	}
	return unionTaint(ts...)
}

// expr is the taint of one Jinja expression. An expression this parser cannot
// read counts as tainted when it names something that carries a credential.
func (e *taintEval) expr(src string) *taintTree {
	n, err := parseJinja(src)
	if err != nil {
		var mentioned []*taintTree
		for _, word := range strings.FieldsFunc(src, func(r rune) bool {
			return !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
		}) {
			if t := e.lookup(word); t != nil {
				mentioned = append(mentioned, t)
			}
		}
		if len(mentioned) > 0 {
			e.unparsed++
			e.unparsedExprs = append(e.unparsedExprs, fmt.Sprintf("%q: %v", src, err))
		}
		return unionTaint(mentioned...)
	}
	return e.node(n)
}

func constString(n *jnode) (string, bool) {
	if n != nil && n.kind == "const" {
		s, ok := n.val.(string)
		return s, ok
	}
	return "", false
}

func (e *taintEval) node(n *jnode) *taintTree {
	if n == nil {
		return nil
	}
	switch n.kind {
	case "const", "test", "not", "neg":
		return nil
	case "name":
		return e.lookup(n.name)
	case "list", "tuple":
		var ts []*taintTree
		for _, k := range n.kids {
			ts = append(ts, e.node(k))
		}
		return unionTaint(ts...)
	case "dict":
		// A dict literal with literal keys keeps the credential under its key,
		// so {'name': x.name} is clean and {'password': x.password} is not.
		kids := map[string]*taintTree{}
		var loose []*taintTree
		for i := 0; i+1 < len(n.kids); i += 2 {
			v := e.node(n.kids[i+1])
			key, ok := constString(n.kids[i])
			switch {
			case !ok:
				loose = append(loose, e.node(n.kids[i]), v)
			case v != nil:
				kids[key] = unionTaint(kids[key], v)
			}
		}
		if len(kids) > 0 {
			loose = append(loose, &taintTree{kids: kids})
		}
		return unionTaint(loose...)
	case "attr":
		return attrTaint(e.node(n.kids[0]), n.name)
	case "index":
		base := e.node(n.kids[0])
		if key, ok := constString(n.kids[1]); ok {
			if _, err := strconv.Atoi(key); err != nil {
				return attrTaint(base, key)
			}
		}
		if base == nil || base.full {
			return base
		}
		return anyChildTaint(base)
	case "slice":
		return e.node(n.kids[0])
	case "bin":
		switch n.name {
		case "==", "!=", "<", ">", "<=", ">=", "in":
			return nil
		}
		return unionTaint(e.node(n.kids[0]), e.node(n.kids[1]))
	case "cond":
		return unionTaint(e.node(n.kids[0]), e.node(n.kids[len(n.kids)-1]))
	case "call":
		return e.call(n)
	case "filter":
		return e.filter(n)
	}
	return nil
}

// call reads a method call (x.get('k'), x.keys(), x.split(...)) or a function.
func (e *taintEval) call(n *jnode) *taintTree {
	fn := n.kids[0]
	args := n.kids[1:]
	var argTaint []*taintTree
	for _, a := range args {
		argTaint = append(argTaint, e.node(a))
	}
	for _, a := range n.kw {
		argTaint = append(argTaint, e.node(a))
	}
	if fn.kind == "attr" {
		recv := e.node(fn.kids[0])
		switch fn.name {
		case "keys":
			return nil
		case "get":
			if len(args) > 0 {
				if key, ok := constString(args[0]); ok {
					return unionTaint(append([]*taintTree{attrTaint(recv, key)}, argTaint[1:]...)...)
				}
			}
			return unionTaint(append([]*taintTree{anyChildTaint(recv)}, argTaint...)...)
		}
		return unionTaint(append([]*taintTree{recv}, argTaint...)...)
	}
	if fn.kind == "name" && fn.name == "range" {
		return nil
	}
	return unionTaint(argTaint...)
}

func (e *taintEval) filter(n *jnode) *taintTree {
	x := e.node(n.kids[0])
	args := n.kids[1:]
	if cleanResultFilters[n.name] {
		return nil
	}
	switch n.name {
	case "map":
		if attr, ok := n.kw["attribute"]; ok {
			path, _ := constString(attr)
			out := x
			for _, seg := range strings.Split(path, ".") {
				out = attrTaint(out, seg)
			}
			if path == "" {
				return x
			}
			return unionTaint(out, e.node(n.kw["default"]))
		}
		// map('rejectattr', 'key', 'in', <keys>): the one projection that
		// removes the credential keys from dict2items pairs.
		if len(args) == 4 {
			f, _ := constString(args[0])
			k, _ := constString(args[1])
			in, _ := constString(args[2])
			if f == "rejectattr" && k == "key" && in == "in" {
				if list, ok := e.stringList(args[3]); ok && sameKeySet(list, e.keys) {
					return nil
				}
			}
		}
	}
	ts := []*taintTree{x}
	for _, a := range args {
		ts = append(ts, e.node(a))
	}
	for _, a := range n.kw {
		ts = append(ts, e.node(a))
	}
	return unionTaint(ts...)
}

// stringList reads a literal list of strings, or a name bound to one in the
// task's own vars.
func (e *taintEval) stringList(n *jnode) ([]string, bool) {
	switch n.kind {
	case "list", "tuple":
		var out []string
		for _, k := range n.kids {
			s, ok := constString(k)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	case "name":
		for i := len(e.scope) - 1; i >= 0; i-- {
			raw, ok := e.scope[i][n.name]
			if !ok {
				continue
			}
			switch v := raw.(type) {
			case []any:
				var out []string
				for _, each := range v {
					s, ok := each.(string)
					if !ok {
						return nil, false
					}
					out = append(out, s)
				}
				return out, true
			case string:
				exprs, _, found := templateExprs(v)
				if found && len(exprs) == 1 {
					if inner, err := parseJinja(exprs[0]); err == nil {
						return e.stringList(inner)
					}
				}
			}
		}
	}
	return nil, false
}

func sameKeySet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// ---- tasks ----

// scanTask is a task with the vars of the blocks and the play around it.
type scanTask struct {
	path  string
	task  map[string]any
	scope []map[string]any
}

type rosterScan struct {
	findings             map[string][]string // "<path>::<task>" -> reasons
	tasks                int
	loops                int
	setFacts             int
	noLogCredentialTasks int
	unparsed             int
	unparsedExprs        []string
}

func scanRosterCredentialSites(t *testing.T, root string, keys []string) rosterScan {
	t.Helper()
	var tasks []scanTask
	err := filepath.WalkDir(filepath.Join(root, "playbooks"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !(strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil // not a playbook or task file (a template with Jinja in YAML)
		}
		rel, _ := filepath.Rel(root, p)
		tasks = append(tasks, collectScanTasks(filepath.ToSlash(rel), doc)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return scanRosterCredentials(tasks, keys)
}

// collectScanTasks flattens a playbook or a task file into its tasks.
func collectScanTasks(path string, doc any) []scanTask {
	items, _ := doc.([]any)
	var out []scanTask
	var walk func(list any, scope []map[string]any)
	walk = func(list any, scope []map[string]any) {
		tasks, _ := list.([]any)
		for _, each := range tasks {
			task, ok := each.(map[string]any)
			if !ok {
				continue
			}
			inner := scope
			if vars, ok := task["vars"].(map[string]any); ok {
				inner = append(slices.Clone(scope), vars)
			}
			out = append(out, scanTask{path: path, task: task, scope: inner})
			for _, section := range []string{"block", "rescue", "always"} {
				walk(task[section], inner)
			}
		}
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		_, play := m["hosts"]
		_, imported := m["import_playbook"]
		_, importedFQ := m["ansible.builtin.import_playbook"]
		switch {
		case play:
			// A play's vars define names for its tasks; they never shadow a
			// credential root (`ipa_users: []` in the play vars is the empty
			// default the run's facts and -e replace).
			for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
				walk(m[section], nil)
			}
		case imported || importedFQ:
		default:
			walk([]any{m}, nil)
		}
	}
	return out
}

// loopOf returns what a task loops over: `loop`, or a with_* keyword, which
// takes its value as an expression, so a bare name is one (bare).
func loopOf(task map[string]any) (value any, bare bool, ok bool) {
	if v, found := task["loop"]; found {
		return v, false, true
	}
	for k, v := range task {
		if strings.HasPrefix(k, "with_") {
			return v, true, true
		}
	}
	return nil, false, false
}

func loopVarOf(task map[string]any) string {
	if control, ok := task["loop_control"].(map[string]any); ok {
		if name, ok := control["loop_var"].(string); ok {
			return name
		}
	}
	return "item"
}

// taskKeywords are the keys of a task that are not its module.
var taskKeywords = map[string]bool{
	"name": true, "tags": true, "when": true, "register": true, "loop": true, "loop_control": true,
	"vars": true, "no_log": true, "become": true, "become_user": true, "become_method": true,
	"become_flags": true, "environment": true, "delegate_to": true, "delegate_facts": true,
	"run_once": true, "check_mode": true, "diff": true, "ignore_errors": true,
	"ignore_unreachable": true, "failed_when": true, "changed_when": true, "until": true,
	"retries": true, "delay": true, "notify": true, "listen": true, "any_errors_fatal": true,
	"throttle": true, "timeout": true, "connection": true, "remote_user": true, "port": true,
	"module_defaults": true, "collections": true, "debugger": true, "async": true, "poll": true,
	"block": true, "rescue": true, "always": true, "args": true, "action": true, "local_action": true,
}

// moduleArgsOf returns the arguments of a task's module by "<module>.<key>"
// (a free-form string is "<module>"), `args:` included. What an assert says in
// `that`, `fail_msg` and `success_msg` is a condition or a message about a
// failed check, not a value the module prints.
func moduleArgsOf(task map[string]any) map[string]any {
	out := map[string]any{}
	add := func(module string, v any) {
		switch args := v.(type) {
		case map[string]any:
			for k, each := range args {
				if strings.HasSuffix(module, "assert") && (k == "that" || k == "fail_msg" || k == "success_msg" || k == "msg") {
					continue
				}
				out[module+"."+k] = each
			}
		case string, []any:
			out[module] = args
		}
	}
	for k, v := range task {
		if taskKeywords[k] || strings.HasPrefix(k, "with_") {
			continue
		}
		if _, isSetFact := setFactOf(map[string]any{k: v}); isSetFact {
			continue // read as facts, below
		}
		add(k, v)
	}
	if v, ok := task["args"]; ok {
		add("args", v)
	}
	return out
}

func isNoLog(task map[string]any) bool {
	switch v := task["no_log"].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "True" || v == "yes"
	}
	return false
}

func setFactOf(task map[string]any) (map[string]any, bool) {
	for _, key := range []string{"ansible.builtin.set_fact", "set_fact"} {
		if v, ok := task[key]; ok {
			m, _ := v.(map[string]any)
			return m, true
		}
	}
	return nil, false
}

func scanTaskName(task map[string]any) string {
	name, _ := task["name"].(string)
	if name == "" {
		for k := range task {
			if strings.Contains(k, ".") || k == "set_fact" {
				return "(unnamed " + k + ")"
			}
		}
	}
	return name
}

func scanRosterCredentials(tasks []scanTask, keys []string) rosterScan {
	res := rosterScan{findings: map[string][]string{}, tasks: len(tasks)}
	global := credentialRoots()
	eval := &taintEval{global: global, keys: keys, visiting: map[string]bool{}}
	// Where an item is bound: a loop over a credential makes `item` one.
	bind := func(st scanTask) (loopTaint *taintTree, hasLoop bool) {
		eval.scope, eval.local = st.scope, map[string]*taintTree{}
		loop, bare, ok := loopOf(st.task)
		if !ok {
			return nil, false
		}
		loopTaint = eval.value(loop)
		if s, isString := loop.(string); isString && bare {
			loopTaint = eval.template(s, true)
		}
		eval.local[loopVarOf(st.task)] = loopTaint
		return loopTaint, true
	}
	// Taint follows set_fact and the register of a loop, in any order: run to
	// a fixpoint over every task of every file.
	for changed, rounds := true, 0; changed && rounds < 10; rounds++ {
		changed = false
		add := func(name string, t *taintTree) {
			if t == nil {
				return
			}
			if merged := unionTaint(global[name], t); !sameTaint(merged, global[name]) {
				global[name] = merged
				changed = true
			}
		}
		for _, st := range tasks {
			loopTaint, hasLoop := bind(st)
			if facts, ok := setFactOf(st.task); ok {
				for name, v := range facts {
					if name != "cacheable" {
						add(name, eval.value(v))
					}
				}
			}
			if reg, ok := st.task["register"].(string); ok && hasLoop && loopTaint != nil {
				add(reg, taintFull)
			}
			// vars of an include or an import pass names to the file it loads.
			for _, mod := range []string{"include_tasks", "ansible.builtin.include_tasks", "import_tasks", "ansible.builtin.import_tasks"} {
				if _, ok := st.task[mod]; ok {
					if vars, ok := st.task["vars"].(map[string]any); ok {
						for name, v := range vars {
							add(name, eval.value(v))
						}
					}
				}
			}
		}
	}
	for _, st := range tasks {
		loopTaint, hasLoop := bind(st)
		var why []string
		if hasLoop {
			res.loops++
		}
		facts, isSetFact := setFactOf(st.task)
		if isSetFact {
			res.setFacts++
		}
		if hasLoop && loopTaint != nil {
			why = append(why, "loop over a credential: "+describeTaint(loopTaint))
		}
		if isSetFact {
			names := make([]string, 0, len(facts))
			for name := range facts {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if name == "cacheable" {
					continue
				}
				if t := eval.value(facts[name]); t != nil {
					why = append(why, "set_fact "+name+" holds a credential: "+describeTaint(t))
				}
			}
		}
		args := moduleArgsOf(st.task)
		argNames := make([]string, 0, len(args))
		for name := range args {
			argNames = append(argNames, name)
		}
		sort.Strings(argNames)
		for _, name := range argNames {
			var t *taintTree
			if strings.HasSuffix(name, "debug.var") {
				if v, ok := args[name].(string); ok {
					t = eval.template(v, true) // `var:` names a variable
				}
			} else {
				t = eval.value(args[name])
			}
			if t != nil {
				why = append(why, "argument "+name+" holds a credential: "+describeTaint(t))
			}
		}
		if len(why) == 0 {
			continue
		}
		if isNoLog(st.task) {
			res.noLogCredentialTasks++
			continue
		}
		key := st.path + "::" + scanTaskName(st.task)
		res.findings[key] = append(res.findings[key], why...)
	}
	res.unparsed = eval.unparsed
	seen := map[string]bool{}
	for _, expr := range eval.unparsedExprs {
		if !seen[expr] {
			seen[expr] = true
			res.unparsedExprs = append(res.unparsedExprs, expr)
		}
	}
	sort.Strings(res.unparsedExprs)
	return res
}

func sameTaint(a, b *taintTree) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	case a.full != b.full || len(a.kids) != len(b.kids):
		return false
	}
	for k, v := range a.kids {
		if w, ok := b.kids[k]; !ok || !sameTaint(v, w) {
			return false
		}
	}
	return true
}

func describeTaint(t *taintTree) string {
	if t == nil {
		return "none"
	}
	if t.full {
		return "the whole value"
	}
	var names []string
	for k, v := range t.kids {
		names = append(names, k+"."+describeTaint(v))
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// ---- the credential keys ----

// credentialKeysOfNormalizer is the list of the keys that
// freeipa-identity-normalize-users-groups.yml writes only when it produces the
// credentials: the dict it combines in under `pilot_identity_with_credentials`.
func credentialKeysOfNormalizer(t *testing.T, root string) []string {
	t.Helper()
	doc := loadYAML(t, filepath.Join(root, "playbooks/apply/tasks/freeipa-identity-normalize-users-groups.yml"))
	task := findNamedTask(t, doc, "Normalize canonical users for the compatibility reconciler")
	facts, ok := setFactOf(task)
	if !ok {
		t.Fatal("the users normalization is not a set_fact")
	}
	var keys []string
	var visit func(n *jnode)
	visit = func(n *jnode) {
		if n == nil {
			return
		}
		if n.kind == "cond" && len(n.kids) == 3 && n.kids[1].kind == "name" && n.kids[1].name == "pilot_identity_with_credentials" && n.kids[0].kind == "dict" {
			for i := 0; i < len(n.kids[0].kids); i += 2 {
				if key, ok := constString(n.kids[0].kids[i]); ok {
					keys = append(keys, key)
				}
			}
		}
		for _, k := range n.kids {
			visit(k)
		}
		for _, k := range n.kw {
			visit(k)
		}
	}
	for _, v := range facts {
		s, _ := v.(string)
		exprs, _, _ := templateExprs(s)
		for _, expr := range exprs {
			n, err := parseJinja(expr)
			if err != nil {
				t.Fatalf("the users normalization does not parse: %v", err)
			}
			visit(n)
		}
	}
	if len(keys) == 0 {
		t.Fatal("no credential keys found in the users normalization; the lint's model of it is stale")
	}
	sort.Strings(keys)
	return keys
}

// ---- self-tests: what the lint must flag and must pass (AGENTS.md §5.12) ----

// rosterSnippetFindings scans a task list written in YAML and returns the
// names of the tasks it flags, sorted.
func rosterSnippetFindings(t *testing.T, snippet string) []string {
	t.Helper()
	var doc any
	if err := yaml.Unmarshal([]byte(snippet), &doc); err != nil {
		t.Fatalf("snippet: %v\n%s", err, snippet)
	}
	scan := scanRosterCredentials(collectScanTasks("snippet.yml", doc), credentialKeysOfNormalizer(t, "../.."))
	var names []string
	for key := range scan.findings {
		names = append(names, strings.TrimPrefix(key, "snippet.yml::"))
	}
	sort.Strings(names)
	return names
}

func TestRegression_RosterCredentialLintFlagsWhatItMustFlag(t *testing.T) {
	keys := credentialKeysOfNormalizer(t, "../..")
	complete := "['" + strings.Join(keys, "', '") + "']"
	incomplete := "['" + strings.Join(keys[1:], "', '") + "']"
	projection := func(list string) string {
		return `{{ ipa_users | map('dict2items') | map('rejectattr', 'key', 'in', ` + list + `) | map('items2dict') | list }}`
	}
	cases := []struct {
		name    string
		snippet string
		flagged []string // task names; nil = the lint must not flag anything
	}{
		// ---- must flag ----
		{"the whole roster as a fact (issue #142)", `
- name: fill
  ansible.builtin.set_fact:
    freeipa_roster: "{{ freeipa_roster | combine({'freeipa': (freeipa_roster.freeipa | default({})) | combine({'server': 'x'})}, recursive=True) }}"
`, []string{"fill"}},
		{"a loop over the normalized users (issue #216)", `
- name: add
  ansible.builtin.command: {argv: [ipa, user-add, "{{ item.name }}"]}
  loop: "{{ ipa_users }}"
  loop_control: {label: "{{ item.name }}"}
`, []string{"add"}},
		{"a loop over the users that declare a password", `
- name: pw
  ansible.builtin.command: {argv: [ipa, user-show, "{{ item.name }}"]}
  loop: "{{ ipa_active_user_credentials }}"
`, []string{"pw"}},
		{"a loop over the roster users", `
- name: roster loop
  ansible.builtin.debug: {msg: "{{ item.name }}"}
  loop: "{{ freeipa_roster.users | default([]) }}"
`, []string{"roster loop"}},
		{"the users copied into another fact, then looped over", `
- name: copy
  ansible.builtin.set_fact:
    copied: "{{ ipa_users | selectattr('state', 'defined') | list }}"
- name: use the copy
  ansible.builtin.command: {argv: [ipa, user-del, "{{ item.name }}"]}
  loop: "{{ copied }}"
`, []string{"copy", "use the copy"}},
		{"the register of a loop over users, looped over again", `
- name: hidden loop
  ansible.builtin.command: {argv: [ipa, user-show, "{{ item.name }}"]}
  loop: "{{ ipa_users }}"
  register: shown
  no_log: true
- name: read the results
  ansible.builtin.set_fact:
    found: "{{ shown.results | map(attribute='stdout') | list }}"
  loop: "{{ shown.results }}"
`, []string{"read the results"}},
		{"with_items and with_subelements name the users bare", `
- name: bare
  ansible.builtin.debug: {msg: "{{ item.name }}"}
  with_items: ipa_users
- name: sub
  ansible.builtin.debug: {msg: "{{ item.1 }}"}
  with_subelements:
    - "{{ ipa_users }}"
    - groups
`, []string{"bare", "sub"}},
		{"a default() in front of the attribute does not hide it", `
- name: paren
  ansible.builtin.set_fact: {a: "{{ (freeipa_roster | default({})).users }}"}
- name: get
  ansible.builtin.set_fact: {b: "{{ freeipa_roster.get('users') }}"}
- name: subscript
  ansible.builtin.set_fact: {c: "{{ freeipa_roster['users'] }}"}
- name: admin password
  ansible.builtin.set_fact: {d: "{{ (freeipa_roster.freeipa | default({})).admin.password }}"}
- name: admin
  ansible.builtin.set_fact: {e: "{{ (freeipa_roster.freeipa | default({})).admin }}"}
- name: freeipa
  ansible.builtin.set_fact: {f: "{{ freeipa_roster.freeipa }}"}
`, []string{"admin", "admin password", "freeipa", "get", "paren", "subscript"}},
		{"a projection that leaves a credential key out", `
- name: partial projection
  ansible.builtin.set_fact:
    users: "` + projection(incomplete) + `"
`, []string{"partial projection"}},
		{"a projection with a key that is not the credential keys", `
- name: other keys
  ansible.builtin.set_fact:
    users: "` + projection(`['password', 'comment']`) + `"
`, []string{"other keys"}},
		{"a rejectattr that does not go through dict2items", `
- name: plain rejectattr
  ansible.builtin.set_fact:
    users: "{{ ipa_users | rejectattr('password', 'defined') | list }}"
`, []string{"plain rejectattr"}},
		{"nested in block, rescue and always", `
- name: outer
  block:
    - name: in block
      ansible.builtin.set_fact: {x: "{{ ipa_users }}"}
  rescue:
    - name: in rescue
      ansible.builtin.set_fact: {y: "{{ ipa_users }}"}
  always:
    - name: in always
      ansible.builtin.set_fact: {z: "{{ ipa_users }}"}
`, []string{"in always", "in block", "in rescue"}},
		{"no_log that is not true", `
- name: off
  ansible.builtin.set_fact: {x: "{{ ipa_users }}"}
  no_log: false
- name: templated
  ansible.builtin.set_fact: {x: "{{ ipa_users }}"}
  no_log: "{{ hide_it | default(false) }}"
`, []string{"off", "templated"}},
		{"a custom loop_var", `
- name: renamed
  ansible.builtin.debug: {msg: "{{ u.name }}"}
  loop: "{{ ipa_users }}"
  loop_control: {loop_var: u}
`, []string{"renamed"}},
		{"debug prints a credential", `
- name: msg
  ansible.builtin.debug: {msg: "admin is {{ freeipa_roster.freeipa.admin.password }}"}
- name: var
  ansible.builtin.debug: {var: freeipa_roster}
- name: fail
  ansible.builtin.fail: {msg: "{{ ipa_users }}"}
`, []string{"fail", "msg", "var"}},
		{"a module argument of a task that is not no_log", `
- name: stdin
  ansible.builtin.command:
    argv: [kinit, admin]
    stdin: "{{ freeipa_roster.freeipa.admin.password }}"
`, []string{"stdin"}},
		{"a task variable that holds the users", `
- name: via vars
  ansible.builtin.debug: {msg: "{{ u.name }}"}
  loop: "{{ everyone }}"
  loop_control: {loop_var: u}
  vars:
    everyone: "{{ freeipa_roster.users }}"
`, []string{"via vars"}},
		{"a for loop in a template", `
- name: template
  ansible.builtin.set_fact:
    text: "{% for u in ipa_users %}{{ u.name }}{% endfor %}"
`, []string{"template"}},
		{"an expression the parser cannot read that names a credential", `
- name: odd
  ansible.builtin.set_fact: {x: "{{ ipa_users @@ 3 }}"}
`, []string{"odd"}},
		{"include_tasks looped over the users", `
- name: include per user
  ansible.builtin.include_tasks: {file: per-user.yml}
  loop: "{{ ipa_users }}"
`, []string{"include per user"}},

		// ---- must pass ----
		{"no_log hides what it holds", `
- name: fill
  ansible.builtin.set_fact: {freeipa_roster: "{{ freeipa_roster | combine({'x': 1}) }}"}
  no_log: true
- name: loop
  ansible.builtin.command: {argv: [ipa, user-show, "{{ item.name }}"], stdin: "{{ item.password }}"}
  loop: "{{ ipa_active_user_credentials }}"
  no_log: yes
`, nil},
		{"the roster paths that carry no credential", `
- name: groups
  ansible.builtin.debug: {msg: "{{ item.name }}"}
  loop: "{{ freeipa_roster.groups | default([]) }}"
- name: hosts
  ansible.builtin.debug: {msg: "{{ item.name }}"}
  loop: "{{ (freeipa_roster.hbac | default({})).rules | default([]) }}"
- name: server
  ansible.builtin.set_fact:
    server: "{{ (freeipa_roster.freeipa | default({})).server }}"
    principal: "{{ freeipa_roster.freeipa.admin.principal | default('admin') }}"
    version: "{{ freeipa_roster.schema_version }}"
    nfs: "{{ (freeipa_roster.nfs | default({})).servers | default([]) }}"
`, nil},
		{"projections of the users", `
- name: names
  ansible.builtin.set_fact:
    names: "{{ freeipa_roster.users | map(attribute='name') | list }}"
    count: "{{ ipa_users | length }}"
    keys: "{{ ipa_users | map(attribute='ssh_keys') | list }}"
    first: "{{ (ipa_users | first).name }}"
    dict: "{{ {'name': (ipa_users | first).name, 'groups': (ipa_users | first).get('groups', []) } }}"
- name: loop over the names
  ansible.builtin.debug: {msg: "{{ item }}"}
  loop: "{{ ipa_users | map(attribute='name') | list }}"
- name: loop over a test
  ansible.builtin.debug: {msg: "{{ item }}"}
  loop: "{{ ['a', 'b'] if ipa_users | length > 0 else [] }}"
`, nil},
		{"the credential-free projection", `
- name: project
  ansible.builtin.set_fact:
    literal: "` + projection(complete) + `"
- name: project from vars
  ansible.builtin.set_fact:
    named: "{{ ipa_users | map('dict2items') | map('rejectattr', 'key', 'in', credential_keys) | map('items2dict') | list }}"
  vars:
    credential_keys: ` + complete + `
- name: loop over the projection
  ansible.builtin.command: {argv: [ipa, user-add, "{{ item.name }}"]}
  loop: "{{ literal }}"
`, nil},
		{"assert, when and failed_when are not what a task prints", `
- name: assert
  ansible.builtin.assert:
    that:
      - freeipa_roster.users | map(attribute='password') | list | length > 0
      - ipa_users[0].password is defined
    fail_msg: "{{ freeipa_roster.freeipa.admin.password }}"
- name: conditions
  ansible.builtin.command: {argv: [true]}
  when: freeipa_roster.freeipa.admin.password | length > 8
  failed_when: ipa_users | selectattr('password', 'defined') | list | length > 100
`, nil},
		{"literal facts", `
- name: reset
  ansible.builtin.set_fact: {ipa_users: [], freeipa_roster: {}}
`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rosterSnippetFindings(t, c.snippet)
			if !slices.Equal(got, c.flagged) {
				t.Fatalf("flagged %q, want %q", got, c.flagged)
			}
		})
	}
}

// The model of a credential in an expression, one spelling per row.
func TestRegression_RosterCredentialTaintOfExpressions(t *testing.T) {
	keys := credentialKeysOfNormalizer(t, "../..")
	for _, c := range []struct {
		expr    string
		tainted bool
	}{
		{"ipa_users", true},
		{"ipa_users | list", true},
		{"ipa_users | length", false},
		{"ipa_users | length > 0 and x", false},
		{"ipa_users | count", false},
		{"ipa_users | map(attribute='name') | list", false},
		{"ipa_users | map(attribute='password') | list", true},
		{"ipa_users | map(attribute='password.initial') | list", true},
		{"ipa_users | map('lower') | list", true},
		{"ipa_users | selectattr('state', 'defined') | rejectattr('state', 'equalto', 'absent') | list", true},
		{"ipa_users | first", true},
		{"(ipa_users | first).name", false},
		{"(ipa_users | first).password", true},
		{"(ipa_users | first)['password']", true},
		{"(ipa_users | first)['name']", false},
		{"(ipa_users | first).get('password')", true},
		{"(ipa_users | first).get('name', '')", false},
		{"(ipa_users | first).keys() | list", false},
		{"ipa_users[0]", true},
		{"ipa_users[0].name", false},
		{"ipa_users[1:]", true},
		{"ipa_users | to_json", true},
		{"ipa_users | default([])", true},
		{"x | default(ipa_users)", true},
		{"ansible.builtin.default(ipa_users)", true},
		{"ipa_users | ansible.builtin.length", false},
		{"ipa_users is defined", false},
		{"ipa_users is not none", false},
		{"ipa_users == []", false},
		{"'a' in ipa_users", false},
		{"'a' not in ipa_users", false},
		{"not ipa_users", false},
		{"ipa_users + []", true},
		{"[] + ipa_users", true},
		{"x ~ (ipa_users | first).password", true},
		{"ipa_users if x else []", true},
		{"[] if x else ipa_users", true},
		{"[ipa_users]", true},
		{"{'a': ipa_users}", true},
		{"{'a': (ipa_users | first).name}", false},
		{"{'password': (ipa_users | first).password}.password", true},
		{"{'password': (ipa_users | first).password}.name", false},
		{"{'password': (ipa_users | first).password} | combine({'name': 'x'})", true},
		{"freeipa_roster", true},
		{"freeipa_roster.freeipa", true},
		{"freeipa_roster.freeipa.admin", true},
		{"freeipa_roster.freeipa.admin.password", true},
		{"freeipa_roster.freeipa.admin.principal", false},
		{"freeipa_roster.freeipa.server", false},
		{"freeipa_roster.freeipa.safety", false},
		{"freeipa_roster.users", true},
		{"freeipa_roster.groups", false},
		{"freeipa_roster.schema_version | int >= 2", false},
		{"(freeipa_roster.freeipa | default({})).server | default('') | string | trim | length == 0", false},
		{"((freeipa_roster.freeipa | default({})).admin | default({})).password | default('')", true},
		{"freeipa_roster | combine({'freeipa': {'server': 'x'}}, recursive=True)", true},
		{"freeipa_roster.get('hosts', [])", false},
		{"freeipa_roster['groups']", false},
		{"freeipa_roster | dict2items | map(attribute='key') | list", false},
		{"(freeipa_roster.users | default([])) if x else (range(freeipa_roster.users | default([]) | length) | list)", true},
		{"range(freeipa_roster.users | length) | list", false},
		{"{{ 'x' }}", false},
		{"'{{' ~ ipa_users", true},
		{"ipa_users | map('dict2items') | map('rejectattr', 'key', 'in', " + "['" + strings.Join(keys, "', '") + "']) | map('items2dict') | list", false},
		{"ipa_users | map('dict2items') | map('rejectattr', 'key', 'in', ['password']) | map('items2dict') | list", true},
		{"ipa_users | map('dict2items') | map('rejectattr', 'key', 'in', ['" + strings.Join(append([]string{"extra"}, keys...), "', '") + "']) | map('items2dict') | list", true},
		{"x is divisibleby 3 and ipa_users", true},
		{"ipa_users is not match('^a') or x", false},
		{"'a' if ipa_users is defined else 'b'", false},
		{"ipa_users | selectattr('password', 'defined') | map(attribute='name') | list", false},
		{"unknown_variable | list", false},
		{"(ipa_users | first).groups | default([]) | map('lower') | list", false},
		{"item.item.name", false},
		{"'it''s' ~ x", false},
	} {
		t.Run(c.expr, func(t *testing.T) {
			expr := strings.TrimSuffix(strings.TrimPrefix(c.expr, "{{ "), " }}")
			eval := &taintEval{global: credentialRoots(), keys: keys, visiting: map[string]bool{}, local: map[string]*taintTree{}}
			got := eval.expr(expr) != nil
			if eval.unparsed > 0 {
				t.Fatalf("does not parse: %v", eval.unparsedExprs)
			}
			if got != c.tainted {
				t.Fatalf("%q: tainted=%v, want %v", c.expr, got, c.tainted)
			}
		})
	}
}

// What a template string is made of.
func TestRegression_RosterCredentialTemplateSegmentation(t *testing.T) {
	for _, c := range []struct {
		in    string
		exprs []string
		stmts []string
	}{
		{"plain", nil, nil},
		{"{{ a }} and {{ b | f }}", []string{"a", "b | f"}, nil},
		{"{{ {'a': {'b': 1}} | to_json }}", []string{"{'a': {'b': 1}} | to_json"}, nil},
		{"{{ {'a': 1}}}", []string{"{'a': 1}"}, nil},
		{"{{ '}}' ~ x }}", []string{"'}}' ~ x"}, nil},
		{"{% for u in us %}{{ u.name }}{%- endfor -%}", []string{"u.name"}, []string{"for u in us", "endfor"}},
		{"{# {{ hidden }} #}{{ shown }}", []string{"shown"}, nil},
		{"{{ unterminated", nil, nil},
	} {
		exprs, stmts, _ := templateExprs(c.in)
		if !slices.Equal(exprs, c.exprs) || !slices.Equal(stmts, c.stmts) {
			t.Errorf("%q: exprs %q stmts %q, want %q %q", c.in, exprs, stmts, c.exprs, c.stmts)
		}
	}
}

// ---- one source for the credential keys ----

// TestRegression_IdentityCredentialKeysHaveOneSource ties the keys the
// users normalization writes as credentials to the key list the playbook
// strips from ipa_active_users and ipa_absent_users (issue #216, AGENTS.md
// §5.7). A key added on one side only is a credential in the list that
// every loop prints, or a stale name in a list that strips nothing.
func TestRegression_IdentityCredentialKeysHaveOneSource(t *testing.T) {
	keys := credentialKeysOfNormalizer(t, "../..")
	doc := loadYAML(t, identityApplyPath)
	selection := findNamedTask(t, doc, "Select active identity objects")
	vars, _ := selection["vars"].(map[string]any)
	list, _ := vars["ipa_identity_credential_keys"].([]any)
	var listed []string
	for _, k := range list {
		listed = append(listed, fmt.Sprint(k))
	}
	if !sameKeySet(keys, listed) {
		t.Fatalf("the normalization writes the credential keys %v, the playbook strips %v from the users every loop prints", keys, listed)
	}

	// The lint reads the same two sources: the real playbook passes with the
	// keys as they are, and a key on either side only is a finding.
	var tasks []scanTask
	tasks = append(tasks, collectScanTasks("identity.yml", doc)...)
	if findings := scanRosterCredentials(tasks, keys).findings; len(findings) != 0 {
		t.Fatalf("the identity playbook prints a credential: %v", findings)
	}
	extra := append(slices.Clone(keys), "a_new_credential_key")
	if findings := scanRosterCredentials(tasks, extra).findings; len(findings) == 0 {
		t.Fatal("a credential key the normalization writes and the playbook does not strip is not flagged")
	}
	short := slices.Clone(keys[1:])
	var stale []scanTask
	raw, err := os.ReadFile(identityApplyPath)
	if err != nil {
		t.Fatal(err)
	}
	var again any
	if err := yaml.Unmarshal(raw, &again); err != nil {
		t.Fatal(err)
	}
	stale = append(stale, collectScanTasks("identity.yml", again)...)
	if findings := scanRosterCredentials(stale, short).findings; len(findings) == 0 {
		t.Fatal("a credential key the playbook strips and the normalization does not write is not flagged")
	}
}
