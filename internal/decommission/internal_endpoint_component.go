package decommission

import (
	"context"

	"github.com/kjelly/pilot/internal/decommission/providers"
)

// planInternalEndpointReferences extends plan.Components with a
// reference-driven "internal-endpoint" component when refs contains any
// internal-endpoints.yaml reference to the target host AND a provider is
// registered for it (spec.md §37 Phase 4, HD13). Unlike every other
// ComponentPlan (built per host ROLE by planComponent), this one is built
// per REFERENCE — the retiring host need not itself carry any particular
// role for an internal-endpoint reference to exist: it is only ever the
// BACKEND a DIFFERENT host's endpoint entry (route.target/route.proxy
// inventory_host) points at, per contracts/internal-endpoint.yaml's own
// role: freeipa-server (the endpoint reconciler always runs on the
// FreeIPA server, never on the backend host itself).
//
// refs is mutated in place: a reference this reclassifies from
// RequiresReplacement to AutoRemove reflects that a registered provider
// now owns cleaning it up (mirroring how FreeIPA roster references are
// AUTO_REMOVE from scanFreeIPARoster itself, since those are always tied
// to a role-matched component and don't need this separate step).
// Returns nil when there is nothing to do (no reference at all), or when
// no provider is registered (refs stay exactly as ScanReferences
// classified them — still blocking, INV-7's fail-closed default) — the
// caller must not treat a nil return as an error.
func planInternalEndpointReferences(ctx context.Context, provs map[string]providers.Provider, refs []Reference, hostName, fqdn string) *ComponentPlan {
	hasReference := false
	for _, r := range refs {
		if r.Source == "internal-endpoints.yaml" && r.Classification == RequiresReplacement {
			hasReference = true
			break
		}
	}
	if !hasReference {
		return nil
	}

	provider, ok := provs[providers.InternalEndpointProviderID]
	if !ok || provider == nil {
		return nil
	}

	cp := ComponentPlan{ComponentID: providers.InternalEndpointProviderID, HasContract: true, ProviderRegistered: true}
	steps, err := provider.Plan(ctx, providers.PlanInput{HostName: hostName, FQDN: fqdn})
	if err != nil {
		cp.Blockers = append(cp.Blockers, Blocker{Code: classifyProviderPlanError(err), Detail: err.Error()})
		return &cp
	}
	if len(steps) == 0 {
		// Provider found nothing to do after all (e.g. a race between
		// ScanReferences and this provider's own manifest read) —
		// nothing to add, leave refs untouched.
		return nil
	}
	cp.Steps = steps

	for i := range refs {
		if refs[i].Source == "internal-endpoints.yaml" && refs[i].Classification == RequiresReplacement {
			refs[i].Classification = AutoRemove
			refs[i].Detail += " — handled by the internal-endpoint decommission provider (spec.md §37 Phase 4)"
		}
	}
	return &cp
}
