package decommission

import (
	"strings"

	"github.com/kjelly/pilot/internal/decommission/providers"
	"github.com/kjelly/pilot/internal/inventory"
)

// freeIPAPlanFQDN reads only the FreeIPA host cleanup actions, whose
// target comes from resolveAuthoritativeFQDN. Other providers may target
// referenced endpoints rather than the retiring host. After host deletion
// these actions fall back to the inventory name, which can itself be FQDN.
func freeIPAPlanFQDN(plan *Plan) string {
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
				return identity
			}
		}
	}
	return ""
}

// planFQDN also handles legacy PlanJSON without FQDN: its original
// FreeIPA steps retain the authoritative identity whenever it was known.
func planFQDN(plan *Plan) string {
	if saved := normalizeFQDN(plan.FQDN); saved != "" {
		return saved
	}
	if resolved := freeIPAPlanFQDN(plan); resolved != "" {
		return resolved
	}
	return normalizeFQDN(providerFQDN(inventory.Host{Name: plan.Host.Name, AnsibleHost: plan.Host.AnsibleHost}))
}

// retainPlanFQDN runs only after the normal freshness check. It carries
// descriptive metadata across cleanup/replans after IPA deletes the host;
// it never copies execution steps, changes plan hashes, or bypasses gates.
func retainPlanFQDN(fresh, previous *Plan) {
	identity := planFQDN(previous)
	fallback := normalizeFQDN(providerFQDN(inventory.Host{Name: previous.Host.Name, AnsibleHost: previous.Host.AnsibleHost}))
	if identity != fallback {
		// Once the provider resolves an inventory alias, keep that identity
		// even when a subsequent lookup falls back to an FQDN-shaped alias.
		fresh.FQDN = identity
	}
}

func normalizeFQDN(identity string) string {
	return strings.ToLower(strings.TrimSpace(identity))
}
