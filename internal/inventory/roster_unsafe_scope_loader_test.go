package inventory

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// unsafeScopeRow is a vars document with one string, "{{ m }}", at path, and
// what the trust map must say about it.
type unsafeScopeRow struct {
	name string
	doc  string
	path []string // map keys; "#0" is the first item of a list
	want string   // "literal", "template" or "ambiguous"
}

// unsafeScopeRows are the shapes of the unsafe-scope rule, each loaded by the
// real Ansible loader (include_vars, the loader roster files go through) and
// classified by newYAMLTrust.
var unsafeScopeRows = []unsafeScopeRow{
	{"a leaf tagged !unsafe", "a: !unsafe \"{{ m }}\"\n", []string{"a"}, "literal"},
	{"a mapping tagged !unsafe", "a: !unsafe {b: \"{{ m }}\"}\n", []string{"a", "b"}, "literal"},
	{"a list tagged !unsafe", "a: !unsafe [\"{{ m }}\"]\n", []string{"a", "#0"}, "literal"},
	{"nested containers below an !unsafe mapping", "a: !unsafe {b: {c: [\"{{ m }}\"]}}\n", []string{"a", "b", "c", "#0"}, "literal"},
	{"a document tagged !unsafe", "--- !unsafe\na: {b: \"{{ m }}\"}\n", []string{"a", "b"}, "literal"},
	{"an alias to an !unsafe mapping", "s: &u !unsafe {p: \"{{ m }}\"}\nc: *u\n", []string{"c", "p"}, "literal"},
	{"an alias to an !unsafe leaf", "s: &u !unsafe \"{{ m }}\"\nc: *u\n", []string{"c"}, "literal"},
	{"a plain string", "a: \"{{ m }}\"\n", []string{"a"}, "template"},
	{"a plain string beside an !unsafe one", "a: \"{{ m }}\"\nb: !unsafe \"{{ m }}\"\n", []string{"a"}, "template"},
	{"a plain container beside an !unsafe one", "a: {x: \"{{ m }}\"}\nb: !unsafe {y: \"{{ m }}\"}\n", []string{"a", "x"}, "template"},
	{"a plain alias beside an !unsafe mapping", "a: &p {x: \"{{ m }}\"}\nb: !unsafe {y: \"{{ m }}\"}\nc: *p\n", []string{"c", "x"}, "template"},
	// Shared between an !unsafe part and a normal one: the loader builds the
	// string once, so which part wins depends on the document's shape
	// (the two rows after the merge row are the same merge with opposite
	// results in Ansible).
	{"a merge from an !unsafe anchor", "s: &u !unsafe {p: \"{{ m }}\"}\nc: {<<: *u}\n", []string{"c", "p"}, "ambiguous"},
	{"an !unsafe mapping merging a normal source", "s: &u {p: \"{{ m }}\"}\nc: !unsafe {<<: *u}\n", []string{"c", "p"}, "ambiguous"},
	{"a normal scalar aliased into an !unsafe mapping", "a: &p \"{{ m }}\"\nb: !unsafe {q: *p}\n", []string{"a"}, "ambiguous"},
	{"an !unsafe scalar aliased into a normal mapping", "b: !unsafe {q: &p \"{{ m }}\"}\na: {r: *p}\n", []string{"a", "r"}, "ambiguous"},
	{"the anchor built deep, the merge shallow (rendered by Ansible)", "deep:\n  a:\n    b: &u !unsafe {password: \"{{ m }}\"}\nshallow:\n  <<: *u\n", []string{"shallow", "password"}, "ambiguous"},
	{"the anchor shallow, the merge deep (literal in Ansible)", "src: &u !unsafe {password: \"{{ m }}\"}\nconsumer:\n  inner:\n    <<: *u\n", []string{"consumer", "inner", "password"}, "ambiguous"},
}

// trustOfRow classifies the row's string the way the reference check does.
func trustOfRow(t *testing.T, row unsafeScopeRow) string {
	t.Helper()
	doc, err := parseYAMLDocument([]byte(row.doc))
	if err != nil {
		t.Fatalf("%s: %v", row.name, err)
	}
	node := documentRoot(doc)
	for _, step := range row.path {
		if strings.HasPrefix(step, "#") {
			node = resolveAlias(node)
			i, err := strconv.Atoi(strings.TrimPrefix(step, "#"))
			if err != nil {
				t.Fatalf("%s: bad list step %s", row.name, step)
			}
			if node == nil || node.Kind != yaml.SequenceNode || i >= len(node.Content) {
				t.Fatalf("%s: no list item %s", row.name, step)
			}
			node = resolveAlias(node.Content[i])
			continue
		}
		node, _ = mappingValue(node, step)
		if node == nil {
			t.Fatalf("%s: no key %s", row.name, step)
		}
	}
	switch ansibleScalarKind(node, newYAMLTrust(doc)) {
	case scalarLiteral:
		return "literal"
	case scalarTemplate:
		return "template"
	case scalarAmbiguous:
		return "ambiguous"
	}
	t.Fatalf("%s: unexpected kind", row.name)
	return ""
}

// The classification of each row, with no Ansible needed.
func TestYAMLTrustClassifiesTheUnsafeScopeRows(t *testing.T) {
	for _, row := range unsafeScopeRows {
		if got := trustOfRow(t, row); got != row.want {
			t.Errorf("%s: classified %s, want %s", row.name, got, row.want)
		}
	}
}

// The merge key's value is entered whatever its tag, in every spelling: an
// alias, an inline mapping, and a sequence of them.
func TestYAMLTrustEntersEveryMergeSpelling(t *testing.T) {
	for _, row := range []unsafeScopeRow{
		{"a sequence of merge sources", "s: &u !unsafe {p: \"{{ m }}\"}\nc: {<<: [*u]}\n", []string{"c", "p"}, "ambiguous"},
		{"a nested merge", "s: &u !unsafe {p: \"{{ m }}\"}\nt: &v {<<: *u}\nc: {<<: *v}\n", []string{"c", "p"}, "ambiguous"},
		{"a merge source that is not !unsafe", "s: &u {p: \"{{ m }}\"}\nc: {<<: *u}\n", []string{"c", "p"}, "template"},
	} {
		if got := trustOfRow(t, row); got != row.want {
			t.Errorf("%s: classified %s, want %s", row.name, got, row.want)
		}
	}
}

// What Ansible's loader does with each row. The rows classified certain must
// be what the trust map says; the ambiguous rows must show both outcomes
// (otherwise "ambiguous" would only be caution), and one of the two merge rows
// is the same shape with the opposite result.
func unsafeScopeAgainstLoader(t *testing.T) {
	dir, err := os.MkdirTemp("", "unsafe-scope-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	var play strings.Builder
	play.WriteString("- hosts: localhost\n  connection: local\n  gather_facts: false\n  vars: {m: RENDERED}\n  tasks:\n")
	for i, row := range unsafeScopeRows {
		file := fmt.Sprintf("r%02d.yml", i)
		if err := os.WriteFile(filepath.Join(dir, file), []byte(row.doc), 0o600); err != nil {
			t.Fatal(err)
		}
		var expr strings.Builder
		expr.WriteString("d")
		for _, step := range row.path {
			if strings.HasPrefix(step, "#") {
				fmt.Fprintf(&expr, "[%s]", strings.TrimPrefix(step, "#"))
				continue
			}
			expr.WriteString("." + step)
		}
		fmt.Fprintf(&play, "    - ansible.builtin.include_vars: {file: %s, name: d}\n", file)
		fmt.Fprintf(&play, "    - name: \"probe %02d\"\n      ansible.builtin.debug: {msg: \"{{ %s }}\"}\n", i, expr.String())
	}
	if err := os.WriteFile(filepath.Join(dir, "play.yml"), []byte(play.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", "play.yml")
	cmd.Dir = dir
	// The default output: the json stdout callback is not part of every
	// ansible-core 2.19.x, and oracleEnv gives Ansible a home with no collections.
	cmd.Env = oracleEnv(t, dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ansible-playbook: %v\n%s", err, out)
	}
	blocks := strings.Split(string(out), "TASK [probe ")
	if len(blocks) != len(unsafeScopeRows)+1 {
		t.Fatalf("expected %d probe tasks, found %d:\n%s", len(unsafeScopeRows), len(blocks)-1, out)
	}
	seen := map[string]int{}
	for i, row := range unsafeScopeRows {
		block := blocks[i+1]
		if end := strings.Index(block, "TASK ["); end >= 0 {
			block = block[:end]
		}
		var got string
		switch {
		case strings.Contains(block, `"msg": "RENDERED"`):
			got = "template"
		case strings.Contains(block, `"msg": "{{ m }}"`):
			got = "literal"
		default:
			t.Fatalf("%s: neither rendered nor literal:\n%s", row.name, block)
		}
		if row.want == "ambiguous" {
			seen[got]++
			continue
		}
		if got != row.want {
			t.Errorf("%s: Ansible loads it as %s, the trust map says %s", row.name, got, row.want)
		}
	}
	if seen["template"] == 0 || seen["literal"] == 0 {
		t.Errorf("the ambiguous rows must show both outcomes in Ansible (rendered and literal), got %v: ambiguity would be only caution", seen)
	}
}
