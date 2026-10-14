// Package networkcheck plans and reports on directed, contract-declared
// network reachability edges (which host must reach which other host's
// port) so pilot can catch host-to-host connectivity gaps before an apply
// mutates anything. See network-connectivity-preflight-plan-2026-07-31.md
// for the design this package implements.
package networkcheck

import (
	"encoding/json"
	"fmt"
	"sort"
)

// ResolvedInventory is the subset of `ansible-inventory --list` output the
// planner needs: which hosts belong to which group (with child groups
// already expanded and deduped), and each host's fully rendered vars. It
// carries no ansible/exec dependency itself — see ParseInventoryList.
type ResolvedInventory struct {
	GroupHosts map[string][]string
	HostVars   map[string]map[string]any
	// GroupOrder holds the same membership in the order Ansible's
	// groups['<name>'] lists it: the group's own hosts in inventory order,
	// then each child group's hosts, without duplicates. GroupHosts is
	// sorted; logic that mirrors a playbook's groups[...] order (for
	// example the first three dns tier addresses a resolver gets) reads
	// this instead. Nil when the inventory was built without
	// ParseInventoryList.
	GroupOrder map[string][]string
}

// OrderedGroupHosts returns group's hosts in Ansible's groups[...] order,
// falling back to the sorted GroupHosts when GroupOrder was not filled.
func (ri ResolvedInventory) OrderedGroupHosts(group string) []string {
	if hosts, ok := ri.GroupOrder[group]; ok {
		return hosts
	}
	return ri.GroupHosts[group]
}

// HostAddr returns the host's ansible_host if set, otherwise the inventory
// hostname itself — the same fallback ansible uses when connecting.
func (ri ResolvedInventory) HostAddr(host string) string {
	if hv, ok := ri.HostVars[host]; ok {
		if addr, ok := hv["ansible_host"].(string); ok && addr != "" {
			return addr
		}
	}
	return host
}

// HostVar returns a host's fully rendered string var, if set and non-empty.
func (ri ResolvedInventory) HostVar(host, name string) (string, bool) {
	hv, ok := ri.HostVars[host]
	if !ok {
		return "", false
	}
	value, ok := hv[name]
	if !ok {
		return "", false
	}
	str, ok := value.(string)
	if !ok || str == "" {
		return "", false
	}
	return str, true
}

// ParseInventoryList parses `ansible-inventory -i <inv> --list` JSON output
// into a ResolvedInventory. It is pure and shells out to nothing, so it is
// testable with recorded/synthetic JSON — the caller owns running the actual
// ansible-inventory command.
func ParseInventoryList(listJSON []byte) (ResolvedInventory, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(listJSON, &raw); err != nil {
		return ResolvedInventory{}, fmt.Errorf("parse ansible-inventory output: %w", err)
	}

	var groups map[string]struct {
		Hosts    []string `json:"hosts"`
		Children []string `json:"children"`
	}
	if err := json.Unmarshal(listJSON, &groups); err != nil {
		return ResolvedInventory{}, fmt.Errorf("parse ansible-inventory groups: %w", err)
	}

	resolved := make(map[string][]string, len(groups))
	ordered := make(map[string][]string, len(groups))
	visiting := make(map[string]bool, len(groups))
	var expand func(string) ([]string, error)
	expand = func(group string) ([]string, error) {
		if hosts, ok := ordered[group]; ok {
			return hosts, nil
		}
		if visiting[group] {
			return nil, fmt.Errorf("inventory group cycle at %q", group)
		}
		visiting[group] = true
		seen := make(map[string]struct{})
		inOrder := make([]string, 0)
		add := func(host string) {
			if _, dup := seen[host]; !dup {
				seen[host] = struct{}{}
				inOrder = append(inOrder, host)
			}
		}
		entry := groups[group]
		for _, host := range entry.Hosts {
			add(host)
		}
		for _, child := range entry.Children {
			hosts, err := expand(child)
			if err != nil {
				return nil, err
			}
			for _, host := range hosts {
				add(host)
			}
		}
		delete(visiting, group)
		sorted := append([]string(nil), inOrder...)
		sort.Strings(sorted)
		resolved[group] = sorted
		ordered[group] = inOrder
		return inOrder, nil
	}
	for group := range groups {
		if group == "_meta" {
			continue
		}
		if _, err := expand(group); err != nil {
			return ResolvedInventory{}, err
		}
	}

	var meta struct {
		HostVars map[string]map[string]any `json:"hostvars"`
	}
	if metaRaw, ok := raw["_meta"]; ok {
		if err := json.Unmarshal(metaRaw, &meta); err != nil {
			return ResolvedInventory{}, fmt.Errorf("parse ansible-inventory _meta: %w", err)
		}
	}

	return ResolvedInventory{GroupHosts: resolved, HostVars: meta.HostVars, GroupOrder: ordered}, nil
}
