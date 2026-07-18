package delivery

import (
	"fmt"
	"sort"

	"github.com/anomalyco/pilot/internal/contract"
)

// Scope is the inventory truth resolved for this transaction. Host lists are
// keyed by contract role, never inferred from a display label.
type Scope struct{ HostsByRole map[string][]string }

// ValidatePreflight enforces contract cardinality and selected dependency
// placement before an apply can mutate a host. It returns all deterministic
// findings so a TUI and non-interactive caller show the same failure set.
func ValidatePreflight(selected []contract.Contract, scope Scope) error {
	byID := make(map[string]contract.Contract, len(selected))
	for _, component := range selected {
		if _, exists := byID[component.ID]; exists {
			return fmt.Errorf("duplicate selected component %q", component.ID)
		}
		byID[component.ID] = component
		if err := validateCardinality(component, scope.HostsByRole[component.Role]); err != nil {
			return err
		}
	}
	for _, component := range selected {
		for _, dependency := range component.Dependencies {
			if !dependency.Required {
				continue
			}
			provider, ok := byID[dependency.Component]
			if !ok {
				return fmt.Errorf("component %q requires selected dependency %q", component.ID, dependency.Component)
			}
			if dependency.Relation == "sameHosts" && !hostSetsEqual(scope.HostsByRole[component.Role], scope.HostsByRole[provider.Role]) {
				return fmt.Errorf("component %q requires dependency %q on the same hosts", component.ID, dependency.Component)
			}
		}
	}
	return nil
}

func validateCardinality(component contract.Contract, hosts []string) error {
	n := len(uniqueHosts(hosts))
	switch component.HostCardinality {
	case "exactly-one":
		if n != 1 {
			return fmt.Errorf("component %q role %q requires exactly one host, got %d", component.ID, component.Role, n)
		}
	case "one-or-more":
		if n < 1 {
			return fmt.Errorf("component %q role %q requires at least one host", component.ID, component.Role)
		}
	case "zero-or-more":
	default:
		return fmt.Errorf("component %q has unsupported host cardinality %q", component.ID, component.HostCardinality)
	}
	return nil
}

func uniqueHosts(hosts []string) []string {
	set := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		if host != "" {
			set[host] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}
func hostSetsEqual(left, right []string) bool {
	left = uniqueHosts(left)
	right = uniqueHosts(right)
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
