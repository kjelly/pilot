package evidence

import (
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ParseInventoryYAML reads the host and group names of a YAML inventory the
// way Ansible structures it (`all: hosts: ... children: <group>: hosts: ...`),
// recursively. Only names are kept: connection variables never enter a record.
func ParseInventoryYAML(text string) Inventory {
	inv := Inventory{Groups: map[string][]string{}}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return inv
	}
	hosts := map[string]bool{}
	var walk func(group string, node map[string]any)
	walk = func(group string, node map[string]any) {
		if h, ok := node["hosts"].(map[string]any); ok {
			for name := range h {
				hosts[name] = true
				if group != "all" && group != "" {
					inv.Groups[group] = append(inv.Groups[group], name)
				}
			}
		}
		if children, ok := node["children"].(map[string]any); ok {
			for child, sub := range children {
				m, _ := sub.(map[string]any)
				if m == nil {
					m = map[string]any{}
				}
				if _, listed := inv.Groups[child]; !listed {
					inv.Groups[child] = nil
				}
				walk(child, m)
			}
		}
	}
	for top, node := range doc {
		if m, ok := node.(map[string]any); ok {
			walk(top, m)
		}
	}
	for name := range hosts {
		inv.Hosts = append(inv.Hosts, name)
	}
	sort.Strings(inv.Hosts)
	for g := range inv.Groups {
		sort.Strings(inv.Groups[g])
	}
	return inv
}

// RedactCommandLine hides the whole inline extra-vars payload. Payloads can
// contain multiple assignments or JSON; inspecting only the first key leaks.
// File references remain useful for reproducing the command.
func RedactCommandLine(args []string) string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "-e" || a == "--extra-vars") && i+1 < len(args):
			i++
			out = append(out, a, redactPayload(args[i]))
		case strings.HasPrefix(a, "--extra-vars="):
			out = append(out, "--extra-vars="+redactPayload(strings.TrimPrefix(a, "--extra-vars=")))
		case strings.HasPrefix(a, "-e") && len(a) > 2:
			prefix := "-e"
			if a[2] == '=' {
				prefix += "="
			}
			out = append(out, prefix+redactPayload(strings.TrimPrefix(a[2:], "=")))
		default:
			out = append(out, a)
		}
	}
	return strings.Join(out, " ")
}
func redactPayload(value string) string {
	if strings.HasPrefix(value, "@") {
		return value
	}
	return "<redacted>"
}
