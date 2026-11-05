package spec

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #244 part A, native finding D1: wazuh-transaction.py was installed 0700 as
// /usr/local/sbin/pilot-wazuh-transaction and executed directly, but its first line was
// a docstring, so every direct run failed with `[Errno 8] Exec format error`. No Python
// harness noticed because they all import the file or run it through an interpreter.
//
// A file the playbooks install with an executable mode is run by its path, so it must
// start with a `#!` line (or be a compiled binary). This lint covers every literal
// `copy: src:` with an executable mode in playbooks/**; templated sources (artifacts
// built at deploy time) cannot be resolved statically and are skipped.

// executableCopySources returns each literal src of a copy task with an executable mode.
func executableCopySources(node any, found *[]string) {
	switch value := node.(type) {
	case map[string]any:
		for _, key := range []string{"ansible.builtin.copy", "copy"} {
			if args, ok := value[key].(map[string]any); ok {
				src, _ := args["src"].(string)
				if src != "" && !strings.Contains(src, "{{") && hasExecutableMode(args["mode"]) {
					*found = append(*found, src)
				}
			}
		}
		for _, child := range value {
			executableCopySources(child, found)
		}
	case []any:
		for _, child := range value {
			executableCopySources(child, found)
		}
	}
}

func hasExecutableMode(mode any) bool {
	switch m := mode.(type) {
	case string:
		if strings.ContainsAny(m, "+=,") || strings.ContainsAny(m, "rwx") && !strings.ContainsAny(m, "01234567") {
			return strings.Contains(m, "x")
		}
		bits, err := strconv.ParseUint(strings.TrimPrefix(m, "0o"), 8, 32)
		return err == nil && bits&0o111 != 0
	case int:
		// YAML reads an unquoted 0700 as an octal integer already.
		return m&0o111 != 0
	}
	return false
}

// sourceCandidates are the places Ansible's copy looks for a relative src.
func sourceCandidates(playbookFile, src string) []string {
	dir := filepath.Dir(playbookFile)
	var out []string
	for _, base := range []string{dir, filepath.Join(dir, ".."), "../../playbooks/apply", "../../playbooks"} {
		out = append(out, filepath.Join(base, src), filepath.Join(base, "files", src))
	}
	return out
}

// checkExecutableCopies reports every executable copy whose source cannot be run by path.
func checkExecutableCopies(file string, document any, open func(string) ([]byte, bool)) []string {
	var sources []string
	executableCopySources(document, &sources)
	var problems []string
	for _, src := range sources {
		var head []byte
		found := false
		for _, candidate := range sourceCandidates(file, src) {
			if data, ok := open(candidate); ok {
				head, found = data, true
				break
			}
		}
		switch {
		case !found:
			problems = append(problems, fmt.Sprintf("%s: executable copy src %q does not resolve to a repository file", file, src))
		case !bytes.HasPrefix(head, []byte("#!")) && !bytes.HasPrefix(head, []byte("\x7fELF")):
			problems = append(problems, fmt.Sprintf("%s: %q is installed with an executable mode but does not start with a #! line (direct execution fails with Exec format error)", file, src))
		}
	}
	return problems
}

func TestRegression_ExecutableCopiesAreRunnableByPath(t *testing.T) {
	read := func(path string) ([]byte, bool) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, false
		}
		if len(data) > 8 {
			data = data[:8]
		}
		return data, true
	}
	var problems []string
	checked := 0
	err := filepath.WalkDir("../../playbooks", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !(strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			return err
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		var document any
		if yaml.Unmarshal(raw, &document) != nil {
			return nil // not a playbook (vars/roster/data file)
		}
		var sources []string
		executableCopySources(document, &sources)
		checked += len(sources)
		problems = append(problems, checkExecutableCopies(path, document, read)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("the lint saw no executable copy at all; the scan is broken")
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatal(strings.Join(problems, "\n"))
	}
	// The two Wazuh plays that install the coordinator must be among the files the lint resolved.
	for _, play := range []string{"../../playbooks/apply/wazuh-fim-apply.yml", "../../playbooks/apply/wazuh-manager-apply.yml"} {
		raw, _ := os.ReadFile(play)
		var document any
		if err := yaml.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		var sources []string
		executableCopySources(document, &sources)
		if len(sources) == 0 || sources[0] != "files/wazuh-transaction.py" {
			t.Fatalf("%s no longer installs files/wazuh-transaction.py with an executable mode (%v)", play, sources)
		}
	}
}

// Each shape is the defect (or a way to hide it); the checker must reject it, and accept the control.
func TestExecutableCopyLintFires(t *testing.T) {
	doc := func(mode string, src string) any {
		var d any
		if err := yaml.Unmarshal([]byte("- hosts: all\n  tasks:\n    - ansible.builtin.copy:\n        src: "+src+"\n        dest: /usr/local/sbin/x\n        mode: "+mode+"\n"), &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	files := map[string]string{
		"../../playbooks/apply/files/shebang.py":   "#!/usr/bin/env python3\n\"\"\"doc\"\"\"\n",
		"../../playbooks/apply/files/docstring.py": "\"\"\"Wazuh release\"\"\"\n",
		"../../playbooks/apply/files/elf":          "\x7fELF....",
	}
	open := func(path string) ([]byte, bool) {
		v, ok := files[filepath.Clean(path)]
		return []byte(v), ok
	}
	for name, tc := range map[string]struct {
		mode, src string
		bad       bool
	}{
		"shebang script, 0700":         {`"0700"`, "files/shebang.py", false},
		"compiled binary, 0755":        {`"0755"`, "files/elf", false},
		"docstring first, 0700":        {`"0700"`, "files/docstring.py", true},
		"docstring first, int 0755":    {`0755`, "files/docstring.py", true},
		"docstring first, symbolic x":  {`"u+x"`, "files/docstring.py", true},
		"docstring but not executable": {`"0644"`, "files/docstring.py", false},
		"literal src that is missing":  {`"0700"`, "files/nowhere.py", true},
		"templated src is skipped":     {`"0700"`, `"{{ artifact }}"`, false},
	} {
		t.Run(name, func(t *testing.T) {
			problems := checkExecutableCopies("../../playbooks/apply/x-apply.yml", doc(tc.mode, tc.src), open)
			if (len(problems) > 0) != tc.bad {
				t.Fatalf("problems=%v, want bad=%v", problems, tc.bad)
			}
		})
	}
}
