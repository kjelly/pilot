package decommission

import (
	"fmt"
	"sort"

	"github.com/kjelly/pilot/internal/contract"
)

// DependencyResult is dependency ordering's outcome for one host's selected
// component set (spec.md §13).
type DependencyResult struct {
	// TeardownOrder lists component IDs in reverse-dependency order:
	// consumers before the providers they depend on. Empty when Cycle is
	// true — planning fails closed rather than guessing an order.
	TeardownOrder []string
	Cycle         bool
	CycleDetail   string
}

// resolveTeardownOrder builds the reverse-dependency teardown order for
// componentIDs (the target host's own selected components), using each
// component's contract.Dependencies. Only edges between two components
// that are BOTH in componentIDs participate in ordering/cycle detection —
// a dependency on a component not selected for this host (e.g. a shared
// FreeIPA server running elsewhere) is not an ordering edge here; whether
// that shared provider can safely lose this host is
// required_provider_loss's concern, not ordering's.
//
// Adapted from internal/contract/lint.go's validateDependencyCycles (that
// function is unexported and only proves acyclicity across an entire
// catalog for lint purposes; this one also derives an order restricted to
// one host's selected components, so it can't just call that function).
func resolveTeardownOrder(componentIDs []string, catalog contract.Catalog) DependencyResult {
	selected := make(map[string]bool, len(componentIDs))
	for _, id := range componentIDs {
		selected[id] = true
	}

	const (
		white = 0
		gray  = 1
		black = 2
	)
	state := make(map[string]int, len(componentIDs))
	var buildOrder []string // dependency-first: providers before consumers
	var cycleDetail string

	var visit func(id string) bool
	visit = func(id string) bool {
		switch state[id] {
		case gray:
			cycleDetail = fmt.Sprintf("dependency cycle at component %q", id)
			return false
		case black:
			return true
		}
		state[id] = gray
		if comp, ok := catalog.Component(id); ok {
			deps := append([]contract.Dependency(nil), comp.Dependencies...)
			sort.Slice(deps, func(i, j int) bool { return deps[i].Component < deps[j].Component })
			for _, dep := range deps {
				if !selected[dep.Component] {
					continue
				}
				if !visit(dep.Component) {
					return false
				}
			}
		}
		state[id] = black
		buildOrder = append(buildOrder, id)
		return true
	}

	sortedIDs := append([]string(nil), componentIDs...)
	sort.Strings(sortedIDs)
	for _, id := range sortedIDs {
		if !visit(id) {
			return DependencyResult{Cycle: true, CycleDetail: cycleDetail}
		}
	}

	teardown := make([]string, len(buildOrder))
	for i, id := range buildOrder {
		teardown[len(buildOrder)-1-i] = id
	}
	return DependencyResult{TeardownOrder: teardown}
}
