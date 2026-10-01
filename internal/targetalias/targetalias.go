// Package targetalias renders the `--hosts` aliases of a disposable target
// (vm-target and docker-target) as Ansible groups. Both backends render
// their inventories from here, so they cannot drift on what an alias means.
//
// An alias is a single-host group whose only member is the target's
// primary host. It is not a second inventory host: two host entries for
// one machine made `hosts: all` run every play once per alias against the
// same machine, cached facts once per alias, and put the alias, not the
// target, into the execution scope that verification compares with a
// spec's target groups (a v1 spec targeting group `ntp` refused a VM named
// anything but `ntp`). The group form keeps `-l <alias>`, `hosts: <alias>`
// and `groups['<alias>']` working, and since no alias is also a host name,
// Ansible has no "Found both group and host with same name" warning to give
// (the reason 7ed605c dropped the groups when aliases were also hosts).
package targetalias

import (
	"fmt"
	"strings"
)

// implicitGroups are Ansible's built-in groups; an alias with one of these
// names would redefine them, so it is not rendered.
var implicitGroups = map[string]bool{"all": true, "ungrouped": true}

// Groups returns the aliases of primary that become groups, in order:
// hosts without primary, duplicates, empty names and Ansible's implicit
// groups.
func Groups(primary string, hosts []string) []string {
	seen := map[string]bool{primary: true}
	var out []string
	for _, h := range hosts {
		if h == "" || seen[h] || implicitGroups[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// WriteChildren appends an `all.children` block (indented for a document
// whose root is `all:`) with one group per alias, each containing only
// primary. Nothing is written when there are no aliases.
func WriteChildren(sb *strings.Builder, primary string, hosts []string) {
	groups := Groups(primary, hosts)
	if len(groups) == 0 {
		return
	}
	sb.WriteString("  children:\n")
	for _, g := range groups {
		fmt.Fprintf(sb, "    %s:\n      hosts:\n        %s: {}\n", g, primary)
	}
}
