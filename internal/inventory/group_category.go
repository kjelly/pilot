package inventory

import "fmt"

// This file is the single source of truth for group-category policy
// (spec.md §6.3/§21.1): which categories exist, what name prefix each
// requires, which may be newly created by sanctioned authoring surfaces,
// and which may be referenced as an HBAC or sudo subject group. TUI,
// structured actions, and MCP tooling must consume these functions rather
// than hand-maintaining their own category lists, so that a change here
// can't silently drift out of sync with what those surfaces allow.

// GroupCategoryPrefix returns the canonical roster-name prefix required for
// category, and whether category is a structurally known group category at
// all (including the deprecated "access" category, which remains
// structurally valid for backward compatibility).
func GroupCategoryPrefix(category string) (string, bool) {
	prefix, ok := groupCategoryPrefix[category]
	return prefix, ok
}

// IsCreatableGroupCategory reports whether sanctioned authoring surfaces
// (pilot edit, structured --actions, MCP edit tools) may create a *new*
// group with this category. "access" is deprecated compatibility data only:
// existing access groups remain valid, editable, and reconciled, but no
// sanctioned surface may create another one (spec.md §1, §6.1).
func IsCreatableGroupCategory(category string) bool {
	switch category {
	case "team", "filesystem", "role":
		return true
	default:
		return false
	}
}

// IsHBACSubjectGroupCategory reports whether a group with this category may
// be referenced by hbac.rules[].subjects.groups. "access" is accepted for
// backward compatibility with rosters authored before this policy existed;
// "filesystem" groups are a distinct privilege domain and are never valid
// HBAC subjects (spec.md §5.5, §6.3).
func IsHBACSubjectGroupCategory(category string) bool {
	switch category {
	case "team", "role", "access":
		return true
	default:
		return false
	}
}

// IsSudoSubjectGroupCategory reports whether a group with this category may
// be referenced by sudo.rules[].subjects.groups. Only "role" is a reusable
// authorization/principal set; "team" is identity-only and "access" is
// HBAC-only legacy compatibility data (spec.md §6.3).
func IsSudoSubjectGroupCategory(category string) bool {
	return category == "role"
}

// IsDeprecatedGroupCategory reports whether category is retained only for
// backward compatibility with rosters authored before this policy existed.
func IsDeprecatedGroupCategory(category string) bool {
	return category == "access"
}

// RosterWarning is a non-fatal, non-blocking observation about a roster.
// Unlike RosterViolation, a RosterWarning never fails validation or lint
// (spec.md §8) — it exists purely to surface a deprecation notice that
// structural validation deliberately keeps accepting.
type RosterWarning struct {
	Rule   string
	Detail string
}

func (w RosterWarning) String() string {
	return fmt.Sprintf("[%s] %s", w.Rule, w.Detail)
}

// RosterDeprecationWarnings returns one warning per category: access group
// in root, in file order (deterministic) — the only sanctioned-authoring
// deprecation this delivery reports (spec.md §1/§6.2/§8). Callers should
// only call this on a roster that has already passed ValidateRoster; it
// does not itself re-run structural validation.
func RosterDeprecationWarnings(root map[string]any) []RosterWarning {
	var out []RosterWarning
	for _, raw := range listField(root, "groups") {
		g := asMap(raw)
		category := stringField(g, "category")
		if !IsDeprecatedGroupCategory(category) {
			continue
		}
		out = append(out, RosterWarning{
			Rule:   "deprecated group category",
			Detail: fmt.Sprintf("group %q uses deprecated category %q; new HBAC policies should reference team-/role- groups or direct users instead", labelOf(g), category),
		})
	}
	return out
}

// RosterDeprecationWarningsFile is RosterDeprecationWarnings' file-reading
// counterpart, mirroring ValidateRosterFile's read/parse/dispatch shape.
func RosterDeprecationWarningsFile(path string) ([]RosterWarning, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return RosterDeprecationWarnings(root), nil
}

// namesWithCategoryFunc returns the names of every group in items whose
// category satisfies allowed. It generalizes namesWithCategory to an
// arbitrary category policy function so callers (e.g. checkHBAC) can filter
// by IsHBACSubjectGroupCategory instead of a single hardcoded category.
func namesWithCategoryFunc(items []any, allowed func(category string) bool) []string {
	var out []string
	for _, raw := range items {
		m := asMap(raw)
		if allowed(stringField(m, "category")) {
			out = append(out, stringField(m, "name"))
		}
	}
	return out
}
