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

// RedactCommandLine joins a command line for the record, replacing the value
// of every `-e key=value` whose key sounds like a secret, so the record never
// carries a password that was passed inline.
func RedactCommandLine(args []string) string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "-e" || a == "--extra-vars") && i+1 < len(args):
			out = append(out, a, redactKV(args[i+1]))
			i++
		case strings.HasPrefix(a, "-e="):
			out = append(out, "-e="+redactKV(a[3:]))
		case strings.HasPrefix(a, "--extra-vars="):
			out = append(out, "--extra-vars="+redactKV(a[len("--extra-vars="):]))
		default:
			out = append(out, a)
		}
	}
	return strings.Join(out, " ")
}

func redactKV(kv string) string {
	if strings.HasPrefix(kv, "@") {
		return kv
	}
	key, _, ok := strings.Cut(kv, "=")
	if ok && isSecretKey(key) {
		return key + "=<redacted>"
	}
	return kv
}
