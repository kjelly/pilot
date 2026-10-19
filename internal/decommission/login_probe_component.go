package decommission

import (
	"context"
	"strings"

	"github.com/kjelly/pilot/internal/decommission/providers"
	"github.com/kjelly/pilot/internal/inventory"
)

// loginProbeRole is the login-probe component's role (contracts/login-probe.yaml).
const loginProbeRole = "login-probe"

// planLoginProbeTargets extends the plan with a reference-driven
// "login-probe-targets" component (spec.md §19: an active alert-target
// mapping that keeps contacting the retired host is active residue) when
// a login-probe provider is registered and has another login-probe host
// that may still list target as a probe target. The provider's Plan
// decides whether any such host exists; the step's own Inspect decides
// at execution time whether a re-render is still needed.
//
// Like planInternalEndpointReferences it is keyed off the retiring host
// being REFERENCED (a probe target), not one of its own roles, and its
// step runs only on the login-probe hosts — the component does not need
// the retiring host to be reachable (RequiresReachableHost stays false).
// A retiring host that itself carries the login-probe role is left to the
// role loop, which fails closed for it (no local login-probe decommission
// support yet), so this returns nil for it.
func planLoginProbeTargets(ctx context.Context, provs map[string]providers.Provider, target inventory.Host, fqdn string) *ComponentPlan {
	for _, r := range target.Roles {
		if strings.EqualFold(r, loginProbeRole) {
			return nil
		}
	}
	provider, ok := provs[providers.LoginProbeTargetsProviderID]
	if !ok || provider == nil {
		return nil
	}
	cp := ComponentPlan{ComponentID: providers.LoginProbeTargetsProviderID, ProviderRegistered: true}
	steps, err := provider.Plan(ctx, providers.PlanInput{HostName: target.Name, FQDN: fqdn})
	if err != nil {
		cp.Blockers = append(cp.Blockers, Blocker{Code: classifyProviderPlanError(err), Detail: err.Error()})
		return &cp
	}
	if len(steps) == 0 {
		return nil
	}
	cp.Steps = steps
	return &cp
}
