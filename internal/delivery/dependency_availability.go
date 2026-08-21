package delivery

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/inventory"
)

// DependencyAvailabilityRequest bundles the contract-aware inputs spec.md
// §16 dependency-availability gating needs on top of the pure host-level
// resolution ResolveExecutionScope already performs. Selected/Scope/
// ProviderSelection deliberately mirror PreflightRequest's fields of the
// same name (see preflight.go) so a caller reuses the exact plan, role→host
// scope, and provider selection it already resolved for contract preflight
// validation, instead of a second, potentially divergent resolution.
type DependencyAvailabilityRequest struct {
	// Candidates is the same host-level candidate list ResolveExecutionScope
	// would receive: every host under consideration for the current
	// deployment's mutation scope, with its effective policy.
	Candidates []CandidateHost
	// Selected is the deployment's resolved component plan (e.g.
	// ComponentPlan.Ordered from PlanComponents), so required dependencies
	// are already present even when the operator only requested the
	// consumer by name.
	Selected []contract.Contract
	// Scope maps each selected component's Role to its resolved inventory
	// hosts, exactly as contract preflight validation uses it.
	ProviderSelection map[string][]string
	Scope             Scope
	// Reachable is the pre-run probe outcome for every host this request
	// needs an answer for: every Candidates host AND every host returned by
	// DependencySupportHosts for the same Selected/Scope/ProviderSelection —
	// a "support host" (spec §6/§16.2) may need probing purely to satisfy a
	// dependency check even though it is never itself a mutation target. A
	// host absent from this map is treated as unreachable (fail closed):
	// callers must probe every support host, not just mutation candidates.
	Reachable map[string]bool
}

// DependencySupportHosts returns every additional host — beyond whatever a
// caller already probes for its own mutation candidates — that must be
// probed because some selected component's providerEndpoint dependency is
// bound to a provider role resolving to that host (spec §16.2). Callers
// call this before probing so the probe endpoint list covers support hosts
// too; the result is sorted and may overlap with the caller's own mutation
// candidates (that overlap is harmless — probing a host twice is not an
// error, it is simply redundant).
func DependencySupportHosts(selected []contract.Contract, scope Scope, providerSelection map[string][]string) []string {
	byID := indexContractsByID(selected)
	seen := map[string]struct{}{}
	for _, component := range selected {
		for _, dependency := range component.Dependencies {
			if dependency.Relation != "providerEndpoint" {
				continue
			}
			provider, providerSelected := byID[dependency.Component]
			if !providerSelected {
				continue
			}
			providerHosts := uniqueHosts(scope.HostsByRole[provider.Role])
			for _, binding := range component.Bindings {
				if binding.From.Component != provider.ID {
					continue
				}
				for _, host := range bindingProviderCandidates(providerHosts, binding, providerSelection, component.ID) {
					seen[host] = struct{}{}
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for host := range seen {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

// ResolveExecutionScopeWithDependencies applies spec §12's pure host-level
// decision table first (via ResolveExecutionScope), then spec §16's
// contract-aware provider-dependency gating on top of whatever remained
// Included: for each such host, every selected component active on that
// host (per req.Scope.HostsByRole) is checked for a providerEndpoint
// dependency with zero reachable provider hosts. The first such gap found
// (in deterministic (component ID, dependency component ID) order) defers
// or blocks the *entire* host — the conservative, host-granular v1 policy
// spec §16.3 calls for, rather than a partial per-component limit.
//
// A gap's consequence follows the affected host's own effective policy
// (spec §16.4), not the provider's: optional → deferred with
// DeferredDependencyUnavailable and Dependency set to "<providerID>@<host
// candidates tried>"; required (including a host missing from
// req.Candidates' policy, which cannot happen for a host already in
// Included) → moved into Blocking.
//
// Hosts that ResolveExecutionScope already deferred or blocked purely on
// their own reachability are left untouched; only Included hosts are
// subject to dependency gating, per the execution architecture in spec §8
// ("resolve dependency support hosts" happens alongside, not instead of,
// host-level probing).
func ResolveExecutionScopeWithDependencies(req DependencyAvailabilityRequest) ExecutionScope {
	scope := ResolveExecutionScope(req.Candidates)

	policyByHost := make(map[string]inventory.DeploymentAvailability, len(req.Candidates))
	for _, c := range req.Candidates {
		policyByHost[c.Host] = c.Policy
	}
	byID := indexContractsByID(req.Selected)
	ordered := append([]contract.Contract(nil), req.Selected...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	var stillIncluded []string
	for _, host := range scope.Included {
		dependency, ok := firstUnmetDependency(host, ordered, byID, req.Scope, req.ProviderSelection, req.Reachable)
		if !ok {
			stillIncluded = append(stillIncluded, host)
			continue
		}
		if policyByHost[host].Effective() == inventory.DeploymentAvailabilityRequired {
			scope.Blocking = append(scope.Blocking, host)
			continue
		}
		scope.Deferred = append(scope.Deferred, DeferredHost{
			Host:       host,
			Policy:     inventory.DeploymentAvailabilityOptional,
			Reason:     DeferredDependencyUnavailable,
			Dependency: dependency,
		})
	}

	scope.Included = stillIncluded
	sort.Strings(scope.Included)
	sort.Strings(scope.Blocking)
	sort.Slice(scope.Deferred, func(i, j int) bool { return scope.Deferred[i].Host < scope.Deferred[j].Host })
	return scope
}

// firstUnmetDependency returns a human-readable "<providerID>@<hosts>"
// label for the first providerEndpoint dependency (in the deterministic
// order ordered/its Dependencies already carry — see caller) active on
// host that has no reachable provider host, or ok=false if host has none.
func firstUnmetDependency(host string, ordered []contract.Contract, byID map[string]contract.Contract, scope Scope, providerSelection map[string][]string, reachable map[string]bool) (string, bool) {
	for _, component := range ordered {
		if !containsHost(scope.HostsByRole[component.Role], host) {
			continue
		}
		dependencies := append([]contract.Dependency(nil), component.Dependencies...)
		sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].Component < dependencies[j].Component })
		for _, dependency := range dependencies {
			if dependency.Relation != "providerEndpoint" {
				continue
			}
			provider, providerSelected := byID[dependency.Component]
			if !providerSelected {
				continue
			}
			providerHosts := uniqueHosts(scope.HostsByRole[provider.Role])
			for _, binding := range component.Bindings {
				if binding.From.Component != provider.ID {
					continue
				}
				candidates := bindingProviderCandidates(providerHosts, binding, providerSelection, component.ID)
				if len(candidates) == 0 || anyReachable(candidates, reachable) {
					continue
				}
				return fmt.Sprintf("%s@%s", provider.ID, strings.Join(candidates, ",")), true
			}
		}
	}
	return "", false
}

// bindingProviderCandidates resolves which of providerHosts a binding would
// use, mirroring validateProviderBindings' sourceSelection rules (see
// preflight.go) so dependency-availability gating and contract preflight
// validation agree on "which host answers this dependency" without a
// second selection algorithm. Unlike validateProviderBindings, this never
// errors on ambiguity: an exactlyOne/all/explicit binding with no explicit
// selection recorded degrades to "every candidate provider host", so
// availability gating treats any one reachable candidate as satisfying the
// dependency (spec §16.5 — ambiguity itself remains solely a preflight
// validation concern, not an availability one).
func bindingProviderCandidates(providerHosts []string, binding contract.Binding, providerSelection map[string][]string, componentID string) []string {
	key := componentID + "." + binding.Input
	if selected := uniqueHosts(providerSelection[key]); len(selected) > 0 {
		return selected
	}
	return providerHosts
}

func anyReachable(hosts []string, reachable map[string]bool) bool {
	for _, host := range hosts {
		if reachable[host] {
			return true
		}
	}
	return false
}

func indexContractsByID(components []contract.Contract) map[string]contract.Contract {
	byID := make(map[string]contract.Contract, len(components))
	for _, c := range components {
		byID[c.ID] = c
	}
	return byID
}
