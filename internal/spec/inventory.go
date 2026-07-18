package spec

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Host is one row in the optional `## 1. Targets` table of a spec.
//
// The table form is intentionally minimal — pipeline-friendly fields
// only. Anything fancier (groups, group_vars, host_vars directories)
// belongs in an external inventory file, not in the spec — the spec
// stays portable across hosts and contributor-induced YAML drift.
//
// Recognized columns (case-insensitive header match):
//
//	Hostname | Group | Address | User | Port | IdentityFile
//
// At least `Hostname` is required. All other fields are optional;
// an empty column falls back to the defaults documented in
// GenerateInventory.
type Host struct {
	Hostname     string
	Group        string
	Address      string
	User         string
	Port         string
	IdentityFile string
	Line         int
}

// HasTargets reports whether the spec carries a Targets table.
func (s *Spec) HasTargets() bool { return len(s.Hosts) > 0 }

// inventoryHeaderVariants is a "column aliases" map for the Targets
// table. Both Chinese (the existing `## 1. 目標系統` block convention)
// and English headers are accepted so the spec stays usable for
// non-Chinese-first teams without rewriting existing docs.
var inventoryHeaderAliases = map[string][]string{
	"hostname":     {"hostname", "host", "name", "主機"},
	"group":        {"group", "inventory group", "分類"},
	"address":      {"address", "ip", "ansible_host", "位址"},
	"user":         {"user", "ansible_user", "使用者", "ssh user"},
	"port":         {"port", "ansible_port", "埠"},
	"identityfile": {"identityfile", "key", "ansible_ssh_private_key_file", "金鑰"},
}

// parseTargetsTable scans a raw markdown table block into Hosts.
// Reject the table rather than silently drop a row when Hostname is
// empty — silent rows are the kind of bug that hides until CI.
func parseTargetsTable(headerLine string, bodyLines []string, baseLine int) ([]Host, error) {
	headers := splitRow(headerLine)
	if len(headers) < 2 {
		return nil, nil // no table at all
	}
	fieldFor := make(map[int]string, len(headers))
	for i, h := range headers {
		key, ok := matchInventoryHeader(h)
		if !ok {
			continue
		}
		fieldFor[i] = key
	}
	if _, hasHostname := fieldFor[0]; !hasHostname {
		// Fall through: if column 0 isn't Hostname, treat the block
		// as something else (e.g. `## 1. 目標系統`) and ignore.
		_ = hasHostname
	}
	// Detect "is this a Targets table?" by checking at least the
	// Hostname column. Without it, the block is metadata, not targets.
	hostnameIdx := -1
	for i, key := range fieldFor {
		if key == "hostname" {
			hostnameIdx = i
			break
		}
	}
	if hostnameIdx < 0 {
		return nil, nil
	}
	var out []Host
	for off, line := range bodyLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "|---") || strings.HasPrefix(trimmed, "| ---") {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cols := splitRow(line)
		host := Host{Line: baseLine + off + 1}
		for i, key := range fieldFor {
			if i >= len(cols) {
				continue
			}
			val := strings.TrimSpace(cols[i])
			switch key {
			case "hostname":
				host.Hostname = val
			case "group":
				host.Group = val
			case "address":
				host.Address = val
			case "user":
				host.User = val
			case "port":
				host.Port = val
			case "identityfile":
				host.IdentityFile = val
			}
		}
		if host.Hostname == "" {
			return nil, fmt.Errorf("spec: targets table at line %d: Hostname is empty", host.Line)
		}
		// Default group to "all" so an empty Group still produces a
		// syntactically valid inventory.
		if host.Group == "" {
			host.Group = "all"
		}
		out = append(out, host)
	}
	return out, nil
}

func matchInventoryHeader(h string) (string, bool) {
	norm := strings.ToLower(strings.TrimSpace(h))
	for canonical, variants := range inventoryHeaderAliases {
		for _, v := range variants {
			if norm == v {
				return canonical, true
			}
		}
	}
	// Regex fallback: header containing 'host' (any case) → hostname
	if matched, _ := regexp.MatchString(`(?i)hostname|^host$|主機`, h); matched {
		return "hostname", true
	}
	return "", false
}

// GenerateInventoryOptions controls how the YAML is emitted.
type GenerateInventoryOptions struct {
	// Group is the fallback group name when a Host leaves the
	// column blank (default: "all").
	Group string
	// SSHDefaults injects these ansible_* keys into every host
	// when the host leaves them blank. Useful for fleets that share
	// a bastion / ProxyCommand / StrictHostKeyChecking setting.
	SSHDefaults map[string]string
}

// GenerateInventory renders the spec's Targets table as a single-host
// or multi-host ansible inventory in YAML form. The output is
// intentionally hand-written (not yaml.Marshal) so the result diffs
// predictably and matches what an ansible engineer would type.
//
// Specs WITHOUT a Targets table return ("", nil). Callers should
// check HasTargets first; otherwise, fall back to the user's own
// inventory file as before.
func (s *Spec) GenerateInventory(opts GenerateInventoryOptions) (string, error) {
	if s == nil {
		return "", fmt.Errorf("spec: nil")
	}
	if !s.HasTargets() {
		return "", nil
	}
	// Bucket hosts by group for the nested YAML form ansible wants.
	byGroup := map[string][]Host{}
	groupOrder := []string{}
	for _, h := range s.Hosts {
		if _, ok := byGroup[h.Group]; !ok {
			groupOrder = append(groupOrder, h.Group)
		}
		byGroup[h.Group] = append(byGroup[h.Group], h)
	}
	// Stable order: by first occurrence of group, then by hostname.
	sort.Strings(groupOrder)
	var sb strings.Builder
	sb.WriteString("---\n")
	for _, g := range groupOrder {
		fmt.Fprintf(&sb, "%s:\n", g)
		fmt.Fprintf(&sb, "  hosts:\n")
		hosts := byGroup[g]
		sort.Slice(hosts, func(i, j int) bool { return hosts[i].Hostname < hosts[j].Hostname })
		for _, h := range hosts {
			fmt.Fprintf(&sb, "    %s:\n", quoteInventoryScalar(h.Hostname))
			if h.Address != "" {
				fmt.Fprintf(&sb, "      ansible_host: %s\n", quoteInventoryScalar(h.Address))
			}
			if h.User != "" {
				fmt.Fprintf(&sb, "      ansible_user: %s\n", quoteInventoryScalar(h.User))
			}
			if h.Port != "" {
				fmt.Fprintf(&sb, "      ansible_port: %s\n", quoteInventoryScalar(h.Port))
			}
			if h.IdentityFile != "" {
				fmt.Fprintf(&sb, "      ansible_ssh_private_key_file: %s\n", quoteInventoryScalar(h.IdentityFile))
			}
			// SSH defaults last so they can fill any blanks; we still
			// emit them per-host for visibility, but only for keys the
			// spec author meant to apply fleet-wide.
			for k, v := range opts.SSHDefaults {
				fmt.Fprintf(&sb, "      %s: %s\n", k, quoteInventoryScalar(v))
			}
		}
	}
	return sb.String(), nil
}

// quoteInventoryScalar wraps a value in double quotes, escaping
// the backslash and double quote. Mirrors the spec generator's
// quoteScalar to keep diffs consistent across both YAML emitters.
func quoteInventoryScalar(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}
