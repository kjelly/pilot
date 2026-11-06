package identityreconcile

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/spec"
)

const identitySpec = "docs/verification/freeipa-identity.md"

// usersGroupsRows are the rows the freeipa-identity contract traces to
// the users or groups tags: a new such row joins this check by itself.
func usersGroupsRows(t *testing.T) []string {
	t.Helper()
	loader, err := contract.NewLoader(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	c, err := loader.LoadFile("contracts/freeipa-identity.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for ref, trace := range c.Traceability.Rows {
		if slices.Contains(trace.Tags, "users") || slices.Contains(trace.Tags, "groups") {
			_, id, _ := cutLast(ref, "#")
			rows = append(rows, id)
		}
	}
	sort.Strings(rows)
	return rows
}

func cutLast(s, sep string) (string, string, bool) {
	for i := len(s) - len(sep); i >= 0; i-- {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}

// TestSpecRowsMapToPlannerOperations locks the users/groups rows of the
// identity spec to the planner's operation kinds in both directions
// (spec §10.2, after TestSpecPlaybookTagAlignment).
func TestSpecRowsMapToPlannerOperations(t *testing.T) {
	for _, problem := range specRowMappingProblems(usersGroupsRows(t), SpecRowKinds, SpecRowsExempt, KindsWithoutSpecRow, specRowIDs(t)) {
		t.Error(problem)
	}
}

func specRowIDs(t *testing.T) map[string]bool {
	t.Helper()
	s, err := spec.Parse(filepath.Join("..", "..", identitySpec))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range s.Rows {
		ids[r.ID] = true
	}
	return ids
}

type rowMapping = map[string]struct {
	Kinds  []string
	Verify []string
}

// specRowMappingProblems lists every way the mapping disagrees with the
// spec and the planner.
func specRowMappingProblems(rows []string, mapped rowMapping, exempt, unmappedKinds map[string]string, inSpec map[string]bool) []string {
	var out []string
	problem := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	if len(rows) == 0 {
		problem("the contract traces no row to users or groups")
	}
	for _, row := range rows {
		_, isMapped := mapped[row]
		_, isExempt := exempt[row]
		switch {
		case !inSpec[row]:
			problem("%s is traced by the contract but missing from %s", row, identitySpec)
		case isMapped && isExempt:
			problem("%s is both mapped and exempt: drop the stale exemption", row)
		case !isMapped && !isExempt:
			problem("users/groups row %s maps to no operation kind and is not exempt", row)
		}
	}
	covered := map[string]bool{}
	for row, m := range mapped {
		if !slices.Contains(rows, row) {
			problem("SpecRowKinds names %s, which is not a users/groups row of %s", row, identitySpec)
		}
		if len(m.Kinds) == 0 || len(m.Verify) == 0 {
			problem("%s needs operation kinds and verifying attributes", row)
		}
		for _, k := range m.Kinds {
			if !slices.Contains(Kinds, k) {
				problem("%s maps to unknown kind %s", row, k)
			}
			covered[k] = true
		}
	}
	for row := range exempt {
		if !slices.Contains(rows, row) {
			problem("SpecRowsExempt names %s, which is not a users/groups row", row)
		}
	}
	for _, k := range Kinds {
		_, unmapped := unmappedKinds[k]
		switch {
		case covered[k] && unmapped:
			problem("%s is verified by a row now: drop it from KindsWithoutSpecRow", k)
		case !covered[k] && !unmapped:
			problem("operation kind %s maps to no row and is not listed in KindsWithoutSpecRow", k)
		}
	}
	for k := range unmappedKinds {
		if !slices.Contains(Kinds, k) {
			problem("KindsWithoutSpecRow names unknown kind %s", k)
		}
	}
	return out
}

// The check fails when a mapping is dropped, a stale exemption stays or
// a kind goes unaccounted for (AGENTS.md §5.7: prove the check fires).
func TestSpecRowMappingCheckFires(t *testing.T) {
	rows, inSpec := usersGroupsRows(t), specRowIDs(t)
	clone := func() (rowMapping, map[string]string, map[string]string) {
		m := rowMapping{}
		for k, v := range SpecRowKinds {
			m[k] = v
		}
		e, u := map[string]string{}, map[string]string{}
		for k, v := range SpecRowsExempt {
			e[k] = v
		}
		for k, v := range KindsWithoutSpecRow {
			u[k] = v
		}
		return m, e, u
	}
	for name, edit := range map[string]func(rowMapping, map[string]string, map[string]string){
		"row loses its mapping": func(m rowMapping, _, _ map[string]string) { delete(m, "C10") },
		"stale row exemption":   func(_ rowMapping, e, _ map[string]string) { e["C9"] = "stale" },
		"unaccounted kind":      func(_ rowMapping, _, u map[string]string) { delete(u, KindUserDelete) },
		"stale kind exemption":  func(_ rowMapping, _, u map[string]string) { u[KindUserCreate] = "stale" },
		"mapping to a non-row":  func(m rowMapping, _, _ map[string]string) { m["C3"] = m["C9"] },
	} {
		m, e, u := clone()
		edit(m, e, u)
		if len(specRowMappingProblems(rows, m, e, u, inSpec)) == 0 {
			t.Errorf("%s: the check did not fail", name)
		}
	}
}
