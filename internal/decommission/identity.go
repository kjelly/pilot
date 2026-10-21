package decommission

import (
	"strings"

	"github.com/kjelly/pilot/internal/decommission/providers"
	"github.com/kjelly/pilot/internal/inventory"
)

// freeIPAPlanIdentity reads only the FreeIPA host cleanup actions, whose
// target comes from resolveAuthoritativeFQDN. Other providers may target
// referenced endpoints rather than the retiring host. After host deletion
// these actions fall back to the inventory name, which can itself be FQDN.
func freeIPAPlanIdentity(plan *Plan) (string, providers.HostIdentitySource) {
	for _, component := range plan.Components {
		if component.ComponentID != providers.FreeIPAClientProviderID {
			continue
		}
		for _, step := range component.Steps {
			if step.Provider != providers.FreeIPAClientProviderID ||
				(step.Action != providers.ActionFreeIPARosterHostAbsent && step.Action != providers.ActionFreeIPAIdentityApplyConverge) {
				continue
			}
			if identity := normalizeFQDN(step.TargetIdentity); identity != "" {
				return identity, step.HostIdentitySource
			}
		}
	}
	return "", ""
}

// planFQDN also handles legacy PlanJSON without FQDN: its original
// FreeIPA steps retain the authoritative identity whenever it was known.
func planFQDN(plan *Plan) string {
	if saved := normalizeFQDN(plan.FQDN); saved != "" {
		return saved
	}
	if resolved, _ := freeIPAPlanIdentity(plan); resolved != "" {
		return resolved
	}
	return normalizeFQDN(providerFQDN(inventory.Host{Name: plan.Host.Name, AnsibleHost: plan.Host.AnsibleHost}))
}

// retainPlanFQDN runs only after the normal freshness check. It carries
// descriptive metadata across cleanup/replans after IPA deletes the host;
// it never copies execution steps, changes plan hashes, or bypasses gates.
func retainPlanFQDN(fresh, previous *Plan) {
	identity, source := freeIPAPlanIdentity(fresh)
	if source == providers.HostIdentityAuthoritative {
		fresh.FQDN = identity
		return
	}
	if source == providers.HostIdentityFallback {
		fresh.FQDN = planFQDN(previous)
		return
	}
	// Legacy steps lack provenance; preserve their previous identity only
	// when the current metadata is indistinguishable from the fallback.
	fallback := normalizeFQDN(providerFQDN(inventory.Host{Name: fresh.Host.Name, AnsibleHost: fresh.Host.AnsibleHost}))
	if planFQDN(fresh) == fallback {
		fresh.FQDN = planFQDN(previous)
	}
}

func normalizeFQDN(identity string) string {
	return strings.ToLower(strings.TrimSpace(identity))
}
