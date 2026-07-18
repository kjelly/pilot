package delivery

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/anomalyco/pilot/internal/contract"
)

// Scope is the inventory truth resolved for this transaction. Host lists are
// keyed by contract role, never inferred from a display label.
type Scope struct{ HostsByRole map[string][]string }

// HostFacts is the inventory fact subset used by contract preflight.
type HostFacts struct {
	Available bool
	Distro    string
	Version   string
	CPU       int
	RAMMiB    int
	DiskGiB   int
}

// PreflightRequest contains only resolved, non-secret values. Secret inputs
// are represented by key presence; plaintext secret values must never be
// copied into diagnostics or evidence.
type PreflightRequest struct {
	Selected          []contract.Contract
	Scope             Scope
	Inputs            map[string]map[string]any
	ProviderSelection map[string][]string
	Facts             map[string]HostFacts
}

// PreflightResult contains non-fatal evidence gaps. A missing fact is a
// warning; a known fact below the contract minimum is an error.
type PreflightResult struct {
	Warnings []string
}

// ValidatePreflight enforces contract cardinality and selected dependency
// placement before an apply can mutate a host. It returns all deterministic
// findings so a TUI and non-interactive caller show the same failure set.
func ValidatePreflight(selected []contract.Contract, scope Scope) error {
	_, err := ValidateContractPreflight(PreflightRequest{Selected: selected, Scope: scope})
	return err
}

// ValidateContractPreflight validates a fully resolved deployment plan before
// any mutation. It fails closed on missing inputs, ambiguous providers,
// placement errors, known resource deficits, unsupported OSes, and inputRule
// violations.
func ValidateContractPreflight(request PreflightRequest) (PreflightResult, error) {
	selected := request.Selected
	scope := request.Scope
	var result PreflightResult
	byID := make(map[string]contract.Contract, len(selected))
	for _, component := range selected {
		if _, exists := byID[component.ID]; exists {
			return result, fmt.Errorf("duplicate selected component %q", component.ID)
		}
		byID[component.ID] = component
		if err := validateCardinality(component, scope.HostsByRole[component.Role]); err != nil {
			return result, err
		}
		if err := validateInputs(component, request.Inputs[component.ID]); err != nil {
			return result, err
		}
		for _, host := range uniqueHosts(scope.HostsByRole[component.Role]) {
			facts, ok := request.Facts[host]
			if !ok || !facts.Available {
				result.Warnings = append(result.Warnings, fmt.Sprintf("component %q host %q facts unavailable; OS/resource minimums not verified", component.ID, host))
				continue
			}
			if err := validateHostFacts(component, host, facts); err != nil {
				return result, err
			}
		}
	}
	for _, component := range selected {
		for _, dependency := range component.Dependencies {
			provider, selectedProvider := byID[dependency.Component]
			if dependency.Required && !selectedProvider {
				return result, fmt.Errorf("component %q requires selected dependency %q", component.ID, dependency.Component)
			}
			if !selectedProvider {
				continue
			}
			if dependency.Relation == "sameHosts" && !hostSetsEqual(scope.HostsByRole[component.Role], scope.HostsByRole[provider.Role]) {
				return result, fmt.Errorf("component %q requires dependency %q on the same hosts", component.ID, dependency.Component)
			}
			if dependency.Relation == "providerEndpoint" {
				if err := validateProviderBindings(component, provider, scope, request.ProviderSelection); err != nil {
					return result, err
				}
			}
		}
	}
	sort.Strings(result.Warnings)
	return result, nil
}

func validateInputs(component contract.Contract, values map[string]any) error {
	for _, input := range component.GroupVars {
		value, provided := values[input.Name]
		if !provided && input.Default != nil {
			value, provided = input.Default, true
		}
		if input.Required && (!provided || emptyInput(value)) {
			return fmt.Errorf("component %q requires input %q", component.ID, input.Name)
		}
		if !provided {
			continue
		}
		if err := validateInputType(input, value); err != nil {
			return fmt.Errorf("component %q input %q: %w", component.ID, input.Name, err)
		}
	}
	for _, rule := range component.InputRules {
		conditions := rule.All
		requireAll := true
		if len(rule.Any) > 0 {
			conditions = rule.Any
			requireAll = false
		}
		matches := 0
		for _, condition := range conditions {
			value, ok := values[condition.Input]
			if !ok {
				for _, declared := range component.GroupVars {
					if declared.Name == condition.Input && declared.Default != nil {
						value, ok = declared.Default, true
						break
					}
				}
			}
			if evaluateInputCondition(value, ok, condition) {
				matches++
			}
		}
		if (requireAll && matches != len(conditions)) || (!requireAll && matches == 0) {
			return fmt.Errorf("component %q input rule failed: %s", component.ID, rule.Reason)
		}
	}
	return nil
}

func validateInputType(input contract.GroupVar, value any) error {
	valid := false
	switch input.Type {
	case "string", "duration":
		_, valid = value.(string)
	case "stringList":
		switch value.(type) {
		case []string, []any:
			valid = true
		}
	case "integer":
		_, valid = value.(int)
	case "boolean":
		_, valid = value.(bool)
	}
	if !valid {
		return fmt.Errorf("must be %s", input.Type)
	}
	if input.Validation != "" {
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("validation requires a string value")
		}
		matched, err := regexp.MatchString(input.Validation, text)
		if err != nil || !matched {
			return fmt.Errorf("does not match validation")
		}
	}
	return nil
}

func emptyInput(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(typed) == ""
	case []string:
		return len(typed) == 0
	case []any:
		return len(typed) == 0
	default:
		return false
	}
}

func evaluateInputCondition(value any, provided bool, condition contract.InputCondition) bool {
	switch condition.Operator {
	case "nonEmpty":
		return provided && !emptyInput(value)
	case "equals":
		return provided && fmt.Sprint(value) == fmt.Sprint(condition.Value)
	case "notEquals":
		return !provided || fmt.Sprint(value) != fmt.Sprint(condition.Value)
	case "contains":
		return provided && strings.Contains(fmt.Sprint(value), fmt.Sprint(condition.Value))
	case "notContains":
		return !provided || !strings.Contains(fmt.Sprint(value), fmt.Sprint(condition.Value))
	default:
		return false
	}
}

func validateHostFacts(component contract.Contract, host string, facts HostFacts) error {
	if facts.CPU < component.Resources.MinCPU || facts.RAMMiB < component.Resources.MinRAMMiB || facts.DiskGiB < component.Resources.MinDiskGiB {
		return fmt.Errorf("component %q host %q resources cpu=%d ramMiB=%d diskGiB=%d are below minimum cpu=%d ramMiB=%d diskGiB=%d",
			component.ID, host, facts.CPU, facts.RAMMiB, facts.DiskGiB,
			component.Resources.MinCPU, component.Resources.MinRAMMiB, component.Resources.MinDiskGiB)
	}
	if len(component.OS) == 0 {
		return nil
	}
	for _, supported := range component.OS {
		if supported.Distro != facts.Distro {
			continue
		}
		for _, version := range supported.Versions {
			if version == "any" || version == facts.Version {
				return nil
			}
		}
	}
	return fmt.Errorf("component %q host %q OS %s %s is unsupported", component.ID, host, facts.Distro, facts.Version)
}

func validateProviderBindings(component, provider contract.Contract, scope Scope, selections map[string][]string) error {
	providerHosts := uniqueHosts(scope.HostsByRole[provider.Role])
	for _, binding := range component.Bindings {
		if binding.From.Component != provider.ID {
			continue
		}
		key := component.ID + "." + binding.Input
		selected := uniqueHosts(selections[key])
		switch binding.SourceSelection {
		case "exactlyOne":
			if len(selected) == 0 && len(providerHosts) == 1 {
				selected = providerHosts
			}
			if len(selected) != 1 {
				return fmt.Errorf("component %q binding %q requires exactly one explicit provider host from %q; candidates=%v", component.ID, binding.Input, provider.ID, providerHosts)
			}
		case "all":
			if len(selected) == 0 {
				selected = providerHosts
			}
			if !hostSetsEqual(selected, providerHosts) {
				return fmt.Errorf("component %q binding %q must select all provider hosts", component.ID, binding.Input)
			}
		case "explicit":
			if len(selected) == 0 {
				return fmt.Errorf("component %q binding %q requires explicit provider selection", component.ID, binding.Input)
			}
		default:
			return fmt.Errorf("component %q binding %q has unsupported sourceSelection %q", component.ID, binding.Input, binding.SourceSelection)
		}
		for _, host := range selected {
			if !containsHost(providerHosts, host) {
				return fmt.Errorf("component %q binding %q selected host %q outside provider %q scope", component.ID, binding.Input, host, provider.ID)
			}
		}
	}
	return nil
}

func containsHost(hosts []string, wanted string) bool {
	for _, host := range hosts {
		if host == wanted {
			return true
		}
	}
	return false
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
