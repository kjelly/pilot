package spec

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_ShellTasksUsingPipefailRunUnderBash is a repo-wide lint over
// every playbooks/**/*.yml. ansible.builtin.shell runs its command with
// /bin/sh unless `executable:` says otherwise, and on Debian/Ubuntu /bin/sh
// is dash, which rejects `set -o pipefail` ("Illegal option -o pipefail",
// rc=2) before running anything after it. 869f164 fixed one instance
// (wazuh-manager-agent-deregister); a 2026-09-24 sweep found five more,
// including tasks/freeipa-dns-client-resolver.yml's rescue ROLLBACK, whose
// `failed_when: false` hid that the restore never ran on Debian/Ubuntu.
// Any shell task whose command mentions pipefail must therefore set a bash
// `executable:` (task-level `args:` or the shell mapping form).
func TestRegression_ShellTasksUsingPipefailRunUnderBash(t *testing.T) {
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
	if len(files) == 0 {
		t.Fatal("no playbooks/**/*.yml files found")
	}
	sort.Strings(files)
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		violations, err := findPipefailWithoutBash(raw)
		if err != nil {
			t.Fatalf("%s: parse: %v", path, err)
		}
		for _, v := range violations {
			t.Errorf("%s: %s", path, v)
		}
	}
}

func TestFindPipefailWithoutBash(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"free-form shell without executable", `
- name: t
  ansible.builtin.shell: |
    set -o pipefail
    a | b
`, 1},
		{"args executable bash", `
- name: t
  ansible.builtin.shell: set -o pipefail; a | b
  args:
    executable: /bin/bash
`, 0},
		{"mapping form executable bash", `
- name: t
  shell:
    cmd: set -euo pipefail; a | b
    executable: /usr/bin/bash
`, 0},
		{"executable sh is still dash on Debian", `
- name: t
  ansible.builtin.shell: set -o pipefail; a | b
  args:
    executable: /bin/sh
`, 1},
		{"nested in a play's rescue", `
- hosts: all
  tasks:
    - block:
        - ansible.builtin.command: /bin/false
      rescue:
        - name: rollback
          ansible.builtin.shell: >-
            set -o pipefail;
            ls | head -n1
          failed_when: false
`, 1},
		{"shell without pipefail is not flagged", `
- name: t
  ansible.builtin.shell: a | b
`, 0},
		{"user module shell parameter is not a shell task", `
- name: t
  ansible.builtin.user:
    name: x
    shell: /bin/bash
`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := findPipefailWithoutBash([]byte(tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d violations %v, want %d", len(got), got, tc.want)
			}
		})
	}
}

// findPipefailWithoutBash returns one message per task in raw whose shell
// command mentions pipefail but whose executable is not bash.
func findPipefailWithoutBash(raw []byte) ([]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.MappingNode {
			if cmd, exe, ok := shellTaskCommand(n); ok && strings.Contains(cmd, "pipefail") && filepath.Base(exe) != "bash" {
				name := mappingValue(n, "name")
				label := "<unnamed>"
				if name != nil {
					label = name.Value
				}
				out = append(out, fmt.Sprintf(
					"line %d: shell task %q uses pipefail but runs under %q; add `args: {executable: /bin/bash}` (dash rejects `set -o pipefail` with rc=2)",
					n.Line, label, executableOrDefault(exe)))
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&doc)
	return out, nil
}

// shellTaskCommand reports whether task is an ansible.builtin.shell task and,
// if so, its command text and configured executable ("" when unset).
func shellTaskCommand(task *yaml.Node) (cmd, exe string, ok bool) {
	for _, key := range []string{"ansible.builtin.shell", "shell"} {
		v := mappingValue(task, key)
		if v == nil {
			continue
		}
		switch v.Kind {
		case yaml.ScalarNode:
			cmd = v.Value
		case yaml.MappingNode:
			// A mapping value is only the shell module's own form when it
			// carries cmd; otherwise this "shell" key is some other
			// module's parameter (e.g. ansible.builtin.user's login shell).
			c := mappingValue(v, "cmd")
			if c == nil {
				continue
			}
			cmd = c.Value
			if e := mappingValue(v, "executable"); e != nil {
				exe = e.Value
			}
		default:
			continue
		}
		if args := mappingValue(task, "args"); args != nil && args.Kind == yaml.MappingNode {
			if e := mappingValue(args, "executable"); e != nil {
				exe = e.Value
			}
		}
		return cmd, exe, true
	}
	return "", "", false
}

func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func executableOrDefault(exe string) string {
	if exe == "" {
		return "/bin/sh (default)"
	}
	return exe
}
