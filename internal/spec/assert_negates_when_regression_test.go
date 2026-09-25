package spec

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRegression_AssertNeverNegatesItsOwnWhen is a repo-wide lint over every
// playbooks/**/*.yml. An assert only runs when its `when:` holds, and every
// `that:` item must hold for it to pass, so a `that:` item that is the exact
// negation of a `when:` condition makes the assert fail every time it runs.
// Ten "prod requires recent staging attestation" gates had
//
//	that: [stage != 'prod', (staging_attested_within_hours | int) <= 168]
//	when: stage == 'prod'
//
// so every stage=prod run failed, including `pilot deploy`'s prod path with
// a valid attestation. The first one (core-infra-provider, 2c25c9d) was
// broken from the start and later playbooks copied it; the other 28
// playbooks use `that: [(staging_attested_within_hours | int) <= 168]`.
func TestRegression_AssertNeverNegatesItsOwnWhen(t *testing.T) {
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
	gates := 0
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: parse: %v", path, err)
		}
		violations, checked := assertsNegatingWhen(doc)
		gates += checked
		for _, v := range violations {
			t.Errorf("%s: %s", path, v)
		}
	}
	// Every apply playbook has a prod attestation gate with a when:; far
	// fewer means the walker stopped finding them.
	if gates < 30 {
		t.Fatalf("only %d asserts with an equality when: found; the walker is broken", gates)
	}
}

func TestAssertsNegatingWhen(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"the broken prod gate", `
- name: g
  ansible.builtin.assert:
    that:
      - stage != 'prod'
      - (staging_attested_within_hours | int) <= 168
  when: stage == 'prod'
`, 1},
		{"os-patch-sla variant, list when, double quotes", `
- name: g
  assert:
    that: ['patch_stage != "prod"', 'x']
  when: ['patch_stage == "prod"', 'y']
`, 1},
		{"the correct prod gate", `
- name: g
  ansible.builtin.assert:
    that:
      - (staging_attested_within_hours | int) <= 168
  when: stage == 'prod'
`, 0},
		{"OR form without when is fine", `
- name: g
  ansible.builtin.assert:
    that:
      - stage != 'prod' or (staging_attested_within_hours | int) <= 168
`, 0},
		{"a different variable is fine", `
- name: g
  ansible.builtin.assert:
    that: ["mode != 'prod'"]
  when: stage == 'prod'
`, 0},
		{"nested in a block", `
- block:
    - name: g
      ansible.builtin.assert:
        that: "stage != 'prod'"
      when: "stage == 'prod'"
`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			got, _ := assertsNegatingWhen(doc)
			if len(got) != tc.want {
				t.Fatalf("got %d violations %v, want %d", len(got), got, tc.want)
			}
		})
	}
}

// equalityCondition matches a simple `<var> == '<value>'` condition.
var equalityCondition = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*==\s*(?:'([^']*)'|"([^"]*)")\s*$`)

// inequalityCondition matches a simple `<var> != '<value>'` condition.
var inequalityCondition = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*!=\s*(?:'([^']*)'|"([^"]*)")\s*$`)

// assertsNegatingWhen returns one message per assert in doc that has a
// `that:` item `<var> != '<value>'` while one of its `when:` conditions is
// `<var> == '<value>'`, and the number of asserts it checked (those with at
// least one such equality condition in `when:`).
func assertsNegatingWhen(doc any) ([]string, int) {
	var out []string
	checked := 0
	asList := func(v any) []string {
		switch x := v.(type) {
		case string:
			return []string{x}
		case []any:
			var s []string
			for _, item := range x {
				if str, ok := item.(string); ok {
					s = append(s, str)
				}
			}
			return s
		}
		return nil
	}
	key := func(m []string) string {
		value := m[2]
		if value == "" {
			value = m[3]
		}
		return m[1] + "\x00" + value
	}
	var walk func(n any)
	walk = func(n any) {
		switch v := n.(type) {
		case []any:
			for _, c := range v {
				walk(c)
			}
		case map[string]any:
			for _, module := range []string{"ansible.builtin.assert", "assert"} {
				args, ok := v[module].(map[string]any)
				if !ok {
					continue
				}
				equal := map[string]string{}
				for _, cond := range asList(v["when"]) {
					if m := equalityCondition.FindStringSubmatch(cond); m != nil {
						equal[key(m)] = strings.TrimSpace(cond)
					}
				}
				if len(equal) == 0 {
					continue
				}
				checked++
				name, _ := v["name"].(string)
				for _, item := range asList(args["that"]) {
					m := inequalityCondition.FindStringSubmatch(item)
					if m == nil {
						continue
					}
					if cond, ok := equal[key(m)]; ok {
						out = append(out, fmt.Sprintf("assert %q: that: %q can never hold when its when: %q does, so the assert always fails", name, strings.TrimSpace(item), cond))
					}
				}
			}
			for _, c := range v {
				walk(c)
			}
		}
	}
	walk(doc)
	return out, checked
}
