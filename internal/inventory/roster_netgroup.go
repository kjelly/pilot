// roster_netgroup.go validates the first-class `netgroups:` section schema
// v2 introduces (see roster_validate.go's ValidateRosterV2) and provides
// the small set of Go helpers other netgroup-aware code (a future FreeIPA
// reconciler, MCP inspection) needs to read them back — mirroring
// RosterGroupNames/RosterHostgroupNames (roster.go) for consistency.
//
// A FreeIPA netgroup can contain users, user groups, hosts, hostgroups,
// and nested netgroups; this only validates the roster's own declared
// membership.* references resolve to something else in the roster and
// that the nested-netgroup graph is acyclic — it does not talk to a real
// FreeIPA server (that reconciliation is a separate, later feature).
package inventory

import (
	"fmt"
	"regexp"
	"strings"
)

// netgroupNameRe is the recommended custom-netgroup naming convention: a
// "ng-" prefix distinguishes roster-declared netgroups from any netgroup
// FreeIPA itself creates for other purposes.
var (
	netgroupNameRe = regexp.MustCompile(`^ng-[a-z0-9][a-z0-9_.-]*$`)

	knownNetgroupKeys           = []string{"name", "state", "description", "nis_domain", "membership"}
	knownNetgroupMembershipKeys = []string{"authoritative", "users", "groups", "hosts", "hostgroups", "netgroups"}
)

// RosterNetgroupNames returns every netgroup name in the roster at path, in
// file order — for display only.
func RosterNetgroupNames(path string) ([]string, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return namesOf(listField(root, "netgroups")), nil
}

// checkNetgroups validates the netgroups: list against the roster-schema-v2
// migration spec's netgroup contract: structural fields, that every
// membership.* reference resolves to something else declared in the
// roster, that no netgroup directly contains itself, and that the nested
// -netgroup membership graph has no cycles. Called only from
// ValidateRosterV2 — netgroups don't exist in schema v1.
func checkNetgroups(root map[string]any) []RosterViolation {
	var out []RosterViolation

	netgroups := listField(root, "netgroups")
	userNames := namesOf(listField(root, "users"))
	groupNames := namesOf(listField(root, "groups"))
	hostNames := namesOf(listField(root, "hosts"))
	hostgroupNames := namesOf(listField(root, "hostgroups"))
	netgroupNames := namesOf(netgroups)

	if dupes := findDuplicates(netgroupNames); len(dupes) > 0 {
		out = append(out, RosterViolation{Rule: "unique netgroup names", Detail: fmt.Sprintf("duplicate netgroup name(s): %s", strings.Join(dupes, ", "))})
	}
	for _, name := range netgroupNames {
		if contains(hostgroupNames, name) {
			out = append(out, RosterViolation{Rule: "netgroup/hostgroup name collision", Detail: fmt.Sprintf("netgroup %q collides with a hostgroup of the same name", name)})
		}
	}

	netgroupsByName := map[string]map[string]any{}
	for _, raw := range netgroups {
		ng := asMap(raw)
		label := labelOf(ng)
		name := stringField(ng, "name")

		if !netgroupNameRe.MatchString(name) {
			out = append(out, RosterViolation{Rule: "netgroup name", Detail: fmt.Sprintf("netgroup %q: name must match %s", label, netgroupNameRe.String())})
		}
		state := stateOrDefault(ng, "present")
		if state != "present" && state != "absent" {
			out = append(out, RosterViolation{Rule: "netgroup state", Detail: fmt.Sprintf("netgroup %q: state %q must be present/absent", label, state)})
		}
		if unk := unknownKeys(ng, knownNetgroupKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "netgroup keys", Detail: fmt.Sprintf("netgroup %q: unknown field(s) %s", label, strings.Join(unk, ", "))})
		}

		membership := mapField(ng, "membership")
		if unk := unknownKeys(membership, knownNetgroupMembershipKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "netgroup membership keys", Detail: fmt.Sprintf("netgroup %q: unknown membership field(s) %s", label, strings.Join(unk, ", "))})
		}
		if !boolFieldDefault(membership, "authoritative", false) {
			out = append(out, RosterViolation{Rule: "netgroup membership authoritative", Detail: fmt.Sprintf("netgroup %q: membership.authoritative must be true", label)})
		}

		for _, u := range stringListField(membership, "users") {
			if !contains(userNames, u) {
				out = append(out, RosterViolation{Rule: "netgroup membership user reference", Detail: fmt.Sprintf("netgroup %q: membership.users references unknown user %q", label, u)})
			}
		}
		for _, g := range stringListField(membership, "groups") {
			if !contains(groupNames, g) {
				out = append(out, RosterViolation{Rule: "netgroup membership group reference", Detail: fmt.Sprintf("netgroup %q: membership.groups references unknown group %q", label, g)})
			}
		}
		for _, h := range stringListField(membership, "hosts") {
			if !contains(hostNames, h) {
				out = append(out, RosterViolation{Rule: "netgroup membership host reference", Detail: fmt.Sprintf("netgroup %q: membership.hosts references unknown host %q", label, h)})
			}
		}
		for _, hg := range stringListField(membership, "hostgroups") {
			if !contains(hostgroupNames, hg) {
				out = append(out, RosterViolation{Rule: "netgroup membership hostgroup reference", Detail: fmt.Sprintf("netgroup %q: membership.hostgroups references unknown hostgroup %q", label, hg)})
			}
		}
		nested := stringListField(membership, "netgroups")
		for _, ngRef := range nested {
			if !contains(netgroupNames, ngRef) {
				out = append(out, RosterViolation{Rule: "netgroup membership netgroup reference", Detail: fmt.Sprintf("netgroup %q: membership.netgroups references unknown netgroup %q", label, ngRef)})
			}
		}
		if name != "" && contains(nested, name) {
			out = append(out, RosterViolation{Rule: "netgroup self-reference", Detail: fmt.Sprintf("netgroup %q: cannot list itself in its own membership.netgroups", label)})
		}

		if name != "" {
			netgroupsByName[name] = ng
		}
	}

	// Cycle detection across the nested-netgroup graph. A direct
	// self-reference is already reported above as its own, more specific
	// rule, so only a genuine multi-node cycle (len > 2: start, at least
	// one other member, back to start) is reported here — one report is
	// enough to fail the roster, so this stops at the first cycle found.
	// Unlike expandGroupMembers/expandHostgroupHosts (roster_effective.go),
	// which silently stop at a revisited node so effective-access
	// resolution never infinite-loops on a roster that already passed
	// validation, this must actually report the cycle: strict acyclicity
	// is something schema v2 can enforce with no v1-compatibility risk,
	// since netgroups didn't exist in v1 at all.
	for _, name := range netgroupNames {
		if cycle := findNetgroupCycle(netgroupsByName, name, map[string]bool{}, nil); len(cycle) > 2 {
			out = append(out, RosterViolation{Rule: "netgroup cycle", Detail: fmt.Sprintf("netgroup membership cycle: %s", strings.Join(cycle, " -> "))})
			break
		}
	}

	return out
}

// findNetgroupCycle performs a DFS from name, returning the exact cycle
// path (e.g. ["ng-a", "ng-b", "ng-c", "ng-a"]) the first time it finds a
// revisited node still on the current path, or nil if name's nested-
// netgroup subgraph is acyclic. path is copied (not appended in place)
// before each recursive call so sibling branches in the same loop never
// alias and corrupt each other's slice.
func findNetgroupCycle(byName map[string]map[string]any, name string, visiting map[string]bool, path []string) []string {
	if visiting[name] {
		return append(path, name)
	}
	ng, ok := byName[name]
	if !ok {
		return nil
	}
	visiting[name] = true
	defer delete(visiting, name)
	nextPath := append(append([]string{}, path...), name)
	for _, nested := range stringListField(mapField(ng, "membership"), "netgroups") {
		if cycle := findNetgroupCycle(byName, nested, visiting, nextPath); cycle != nil {
			return cycle
		}
	}
	return nil
}
