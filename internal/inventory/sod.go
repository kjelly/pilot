// sod.go implements the v3.0 Core Access Governance spec's (spec.md §13,
// Phase 2) Separation of Duties: `security.conflicts:` declares sets of
// role-* groups that no single user may effectively belong to at once.
// checkSoDConflicts validates the section's shape; EvaluateSoD is the
// actual semantic resolver spec.md §13 requires ("MUST evaluate effective
// nested group membership" — team-* can feed role-*, so this reuses
// roster_effective.go's expandGroupMembers rather than inspecting only
// direct role members).
package inventory

import (
	"fmt"
	"sort"
	"strings"
)

var knownSoDConflictKeys = []string{"name", "state", "mutually_exclusive"}

// checkSoDConflicts validates security.conflicts: per spec.md §13.
func checkSoDConflicts(root map[string]any) []RosterViolation {
	var out []RosterViolation

	roleGroupNames := namesWithCategoryFunc(listField(root, "groups"), IsSudoSubjectGroupCategory) // "role" category — see IsSudoSubjectGroupCategory
	security := mapField(root, "security")

	names := namesOf(listField(security, "conflicts"))
	if dupes := findDuplicates(names); len(dupes) > 0 {
		out = append(out, RosterViolation{Rule: "unique conflict names", Detail: fmt.Sprintf("duplicate conflict name(s): %s", strings.Join(dupes, ", "))})
	}

	for _, raw := range listField(security, "conflicts") {
		item := asMap(raw)
		label := labelOf(item)

		if unk := unknownKeys(item, knownSoDConflictKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "conflict keys", Detail: fmt.Sprintf("conflict %q: unknown field(s) %s", label, strings.Join(unk, ", "))})
		}

		state := stateOrDefault(item, "present")
		if state != "present" && state != "absent" {
			out = append(out, RosterViolation{Rule: "conflict state", Detail: fmt.Sprintf("conflict %q: state %q must be present/absent", label, state)})
		}

		groups := stringListField(item, "mutually_exclusive")
		if len(groups) < 2 {
			out = append(out, RosterViolation{Rule: "conflict mutually_exclusive", Detail: fmt.Sprintf("conflict %q: mutually_exclusive needs at least two groups", label)})
		}
		if dupes := findDuplicates(groups); len(dupes) > 0 {
			out = append(out, RosterViolation{Rule: "conflict mutually_exclusive", Detail: fmt.Sprintf("conflict %q: mutually_exclusive lists %s more than once", label, strings.Join(dupes, ", "))})
		}
		for _, g := range groups {
			if !contains(roleGroupNames, g) {
				out = append(out, RosterViolation{Rule: "conflict group category", Detail: fmt.Sprintf("conflict %q: mutually_exclusive %q must be a group with category: role — v3.0 guarantees role-group SoD only", label, g)})
			}
		}
	}

	return out
}

// SoDConflict is one violation EvaluateSoD found: a single user who is an
// effective (possibly nested-team-feeding-role) member of two or more
// groups a security.conflicts rule declared mutually exclusive.
type SoDConflict struct {
	RuleName string
	User     string
	// Groups is the 2+ conflicting groups this user is effectively a
	// member of, sorted for deterministic output.
	Groups []string
}

// EvaluateSoD resolves every enabled security.conflicts rule against
// effective (nested) group membership and reports every user who ends up
// in two or more of a rule's mutually_exclusive groups at once. Callers
// MUST have already run ValidateRosterV3 (checkSoDConflicts) — this does
// not re-validate shape.
func EvaluateSoD(root map[string]any) []SoDConflict {
	groupsByName := rosterGroupsByName(root)
	security := mapField(root, "security")

	var out []SoDConflict
	for _, raw := range listField(security, "conflicts") {
		rule := asMap(raw)
		if stateOrDefault(rule, "present") == "absent" {
			continue
		}
		ruleName := stringField(rule, "name")
		groupNames := stringListField(rule, "mutually_exclusive")

		membership := map[string]map[string]bool{} // user -> set of conflicting groups they're effectively in
		for _, g := range groupNames {
			members := map[string]bool{}
			expandGroupMembers(groupsByName, g, map[string]bool{}, members)
			for u := range members {
				if membership[u] == nil {
					membership[u] = map[string]bool{}
				}
				membership[u][g] = true
			}
		}

		users := make([]string, 0, len(membership))
		for u := range membership {
			users = append(users, u)
		}
		sort.Strings(users)
		for _, u := range users {
			if len(membership[u]) < 2 {
				continue
			}
			groups := make([]string, 0, len(membership[u]))
			for g := range membership[u] {
				groups = append(groups, g)
			}
			sort.Strings(groups)
			out = append(out, SoDConflict{RuleName: ruleName, User: u, Groups: groups})
		}
	}
	return out
}

// EvaluateSoDFile is EvaluateSoD's file-reading counterpart, mirroring
// RosterUserNames' read/parse/dispatch shape (roster.go).
func EvaluateSoDFile(path string) ([]SoDConflict, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return EvaluateSoD(root), nil
}
