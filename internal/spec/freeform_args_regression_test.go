package spec

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_FreeFormCommandsSplitInAnsible is a repo-wide lint over
// every playbooks/**/*.yml. Ansible splits a free-form shell/command/raw/
// script string with ansible.parsing.splitter.split_args before running
// it, and that splitter tracks quotes and Jinja blocks across the whole
// string, shell comment lines included. An apostrophe in a comment
// ("the test's fake nmcli", 9034c72) left a quote open, and the task file
// failed to load: "failed at splitting arguments, either an unbalanced
// jinja2 block or quotes". bash never saw the comment, so the unit test that
// runs the script passed, and `ansible-playbook --syntax-check` does not
// load include_tasks files, so only a real run found it.
func TestRegression_FreeFormCommandsSplitInAnsible(t *testing.T) {
	var files []string
	err := filepath.WalkDir("../../playbooks", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	checked := 0
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: parse: %v", path, err)
		}
		for _, c := range freeFormCommands(doc) {
			checked++
			if !ansibleSplitArgsBalanced(c.args) {
				t.Errorf("%s: task %q: Ansible's split_args would reject this free-form %s string (an unbalanced quote or Jinja block, comments included)", path, c.task, c.module)
			}
		}
	}
	// playbooks/** has a few hundred free-form commands (281 on
	// 2026-09-24); a much smaller count means the walker is broken.
	if checked < 200 {
		t.Fatalf("only %d free-form commands found; the walker is broken", checked)
	}
}

// The verdicts below were taken from ansible-core 2.19.2's
// ansible.parsing.splitter.split_args ("ok" = no exception).
func TestAnsibleSplitArgsBalanced(t *testing.T) {
	cases := []struct {
		name string
		args string
		ok   bool
	}{
		{"apostrophe in comment", "set -e\n# the test's fake nmcli\ntrue\n", false},
		{"ansi-c quoted newline", "a=\"${active%%$'\\n'*}\"\n", true},
		{"escaped apostrophe", "echo it\\'s\n", true},
		{"apostrophe inside double quotes", "echo \"it's\"\n", true},
		{"balanced jinja", "echo {{ x | quote }}\n", true},
		{"open jinja", "echo {{ x\n", false},
		{"jinja block closed in a later token", "{% if x %}echo\n", true},
		{"jinja comment open", "{# note\necho\n", false},
		{"quote at token start after backslash token", "echo \\ 'a b'\n", true},
		{"unbalanced double quote", "echo \"abc\n", false},
		{"awk program", "awk -F: '$3 >= 1000 {print $1}' /etc/passwd\n", true},
	}
	for _, tc := range cases {
		if got := ansibleSplitArgsBalanced(tc.args); got != tc.ok {
			t.Errorf("%s: ansibleSplitArgsBalanced(%q) = %v, want %v", tc.name, tc.args, got, tc.ok)
		}
	}
}

// ansibleSplitArgsBalanced reports whether Ansible's split_args accepts s:
// it splits on newlines, then spaces, and toggles a quote state on each
// ' or " not preceded by a backslash within the same token (only the
// opening quote character closes it), while counting {{ }}, {% %} and {# #}
// per token. Anything still open at the end is an error.
func ansibleSplitArgsBalanced(s string) bool {
	var quote byte
	printDepth, blockDepth, commentDepth := 0, 0, 0
	count := func(token string, depth int, open, closing string) int {
		opened, closed := strings.Count(token, open), strings.Count(token, closing)
		if opened != closed {
			depth += opened - closed
			if depth < 0 {
				depth = 0
			}
		}
		return depth
	}
	for item := range strings.SplitSeq(s, "\n") {
		for token := range strings.SplitSeq(item, " ") {
			for i := 0; i < len(token); i++ {
				c := token[i]
				if (c != '"' && c != '\'') || (i > 0 && token[i-1] == '\\') {
					continue
				}
				switch {
				case quote == 0:
					quote = c
				case c == quote:
					quote = 0
				}
			}
			printDepth = count(token, printDepth, "{{", "}}")
			blockDepth = count(token, blockDepth, "{%", "%}")
			commentDepth = count(token, commentDepth, "{#", "#}")
		}
	}
	return quote == 0 && printDepth == 0 && blockDepth == 0 && commentDepth == 0
}

type freeFormCommand struct{ module, task, args string }

// freeFormCommands returns every shell/command/raw/script task in doc whose
// module value is a free-form string (the form Ansible passes through
// split_args).
func freeFormCommands(doc any) []freeFormCommand {
	var out []freeFormCommand
	var walk func(n any)
	walk = func(n any) {
		switch v := n.(type) {
		case []any:
			for _, c := range v {
				walk(c)
			}
		case map[string]any:
			for _, module := range []string{"shell", "command", "raw", "script"} {
				for _, key := range []string{"ansible.builtin." + module, module} {
					if args, ok := v[key].(string); ok {
						name, _ := v["name"].(string)
						out = append(out, freeFormCommand{module: module, task: name, args: args})
					}
				}
			}
			for _, c := range v {
				walk(c)
			}
		}
	}
	walk(doc)
	return out
}
