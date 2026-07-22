package delivery

import (
	"fmt"
	"sort"

	"github.com/kjelly/pilot/internal/contract"
)

// ComponentPlan is a deterministic dependency-first view of the components a
// requested capability needs. It is presentation-neutral so the deploy TUI and
// future non-interactive callers cannot disagree about dependency order.
type ComponentPlan struct {
	Requested []string
	Ordered   []contract.Contract
}

// PlanComponents resolves required dependencies in topological order. An
// experimental component is hidden by default; callers must explicitly opt in
// rather than accidentally selecting one via a display-only catalog entry.
func PlanComponents(catalog contract.Catalog, requested []string, includeExperimental bool) (ComponentPlan, error) {
	if len(requested) == 0 {
		return ComponentPlan{}, fmt.Errorf("component plan requires at least one requested component")
	}
	state := make(map[string]uint8)
	ordered := make([]contract.Contract, 0, len(requested))
	var visit func(string) error
	visit = func(id string) error {
		switch state[id] {
		case 1:
			return fmt.Errorf("component dependency cycle includes %q", id)
		case 2:
			return nil
		}
		component, ok := catalog.Component(id)
		if !ok {
			return fmt.Errorf("component %q is not in the contract catalog", id)
		}
		if component.Experimental && !includeExperimental {
			return fmt.Errorf("component %q is experimental; rerun with --show-experimental after reviewing its evidence requirement", id)
		}
		state[id] = 1
		dependencies := append([]contract.Dependency(nil), component.Dependencies...)
		sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].Component < dependencies[j].Component })
		for _, dependency := range dependencies {
			if dependency.Required {
				if err := visit(dependency.Component); err != nil {
					return err
				}
			}
		}
		state[id] = 2
		ordered = append(ordered, component)
		return nil
	}
	unique := make(map[string]struct{}, len(requested))
	for _, id := range requested {
		unique[id] = struct{}{}
	}
	roots := make([]string, 0, len(unique))
	for id := range unique {
		roots = append(roots, id)
	}
	sort.Strings(roots)
	for _, id := range roots {
		if err := visit(id); err != nil {
			return ComponentPlan{}, err
		}
	}
	return ComponentPlan{Requested: roots, Ordered: ordered}, nil
}
