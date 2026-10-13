package spec

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRegression_RegisteredResultsAreNeverCombined is a repo-wide lint over
// playbooks/**. A task skipped by `when:` still registers its variable,
// as {changed: false, skipped: true, ...}, so merging two registered
// results with combine() lets whichever is merged last decide `changed`.
// prometheus-apply.yml merged its two mutually exclusive prometheus.yml
// renders that way, the "without Alertmanager" one last: with an
// Alertmanager configured, a prometheus.yml change never restarted
// pilot-prometheus, and its single-file bind mount kept serving the old
// file (2026-10-12, a dcgm-exporter target missing from a running
// Prometheus for weeks). Check each result with `is changed` and `or` them.
func TestRegression_RegisteredResultsAreNeverCombined(t *testing.T) {
	registers := 0
	for _, path := range playbookFiles(t) {
		problems, n := combinedRegisteredResults(loadYAML(t, path))
		registers += n
		for _, p := range problems {
			t.Errorf("%s: %s", strings.TrimPrefix(path, "../../"), p)
		}
	}
	// playbooks/** registers hundreds of results; none found means the
	// detection broke.
	if registers == 0 {
		t.Fatal("no registered results found; the detection is broken")
	}
}

func TestCombinedRegisteredResults(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"two exclusive renders merged with combine (the prometheus-apply.yml bug)", `
- hosts: all
  tasks:
    - copy: {dest: /a, content: x}
      register: with_am
      when: am | length > 0
    - copy: {dest: /a, content: y}
      register: no_am
      when: am | length == 0
    - set_fact:
        result: >-
          {{ with_am
             | default({'changed': False})
             | combine(no_am | default({'changed': False})) }}
`, 2},
		{"registered result as the combine() argument", `
- hosts: all
  tasks:
    - command: "true"
      register: probe
    - set_fact: {merged: "{{ {'changed': false} | combine(probe) }}"}
`, 1},
		{"each result checked with is changed", `
- hosts: all
  tasks:
    - copy: {dest: /a, content: x}
      register: with_am
    - copy: {dest: /a, content: y}
      register: no_am
    - debug:
        msg: "{{ (with_am | default({})) is changed or (no_am | default({})) is changed }}"
`, 0},
		{"combine of a set_fact dict, not a registered result (snmp-exporter)", `
- hosts: all
  tasks:
    - command: "true"
      register: probe
    - set_fact: {mods: "{{ (mods | default({})) | combine({item: probe.stdout}) }}"}
      loop: [a]
`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			got, n := combinedRegisteredResults(doc)
			if n == 0 {
				t.Fatal("registered result not detected")
			}
			if len(got) != tc.want {
				t.Fatalf("got %d problems %v, want %d", len(got), got, tc.want)
			}
		})
	}
}

// combinedRegisteredResults returns one message per registered variable in
// doc that is merged with combine(), either piped into it (optionally
// through default()) or passed as its argument, and the number of
// registered variables found.
func combinedRegisteredResults(doc any) ([]string, int) {
	names := map[string]bool{}
	var strs []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if name, ok := x["register"].(string); ok {
				names[name] = true
			}
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		case string:
			strs = append(strs, x)
		}
	}
	walk(doc)

	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)

	// default() arguments in this repo nest at most one level of
	// parentheses.
	const defaultCall = `\|\s*default\((?:[^()]|\([^()]*\))*\)\s*`
	var out []string
	for _, name := range sorted {
		q := regexp.QuoteMeta(name)
		piped := regexp.MustCompile(`\b` + q + `\s*(?:` + defaultCall + `)?\)?\s*\|\s*combine\(`)
		argument := regexp.MustCompile(`combine\(\s*\(?\s*` + q + `\b`)
		for _, s := range strs {
			if loc := piped.FindStringIndex(s); loc != nil && !isAttributeAccess(s, loc[0]) {
				out = append(out, fmt.Sprintf("registered result %s is merged with combine(); a skipped task registers changed: false, so check each result with `is changed` instead", name))
				break
			}
			if argument.MatchString(s) {
				out = append(out, fmt.Sprintf("registered result %s is passed to combine(); a skipped task registers changed: false, so check each result with `is changed` instead", name))
				break
			}
		}
	}
	return out, len(names)
}

// isAttributeAccess reports whether the identifier starting at i in s is
// an attribute of something else (foo.name), not the variable itself.
func isAttributeAccess(s string, i int) bool {
	return i > 0 && s[i-1] == '.'
}
