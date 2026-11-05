package decommission

import (
	"fmt"
	"strings"

	"github.com/kjelly/pilot/internal/decommission/providers"
	"github.com/kjelly/pilot/internal/inventory"
)

// bindPreviousRetirement runs before any provider probe. The approval hash does
// not include FQDN or step targets, so identity additionally needs an unchanged
// host/inventory binding and agreement among every persisted FreeIPA identity.
// This cannot alter the current provider's authority, runner or configuration.
func bindPreviousRetirement(previous, current *Plan) (*providers.RetirementIdentity, error) {
	if previous == nil {
		return nil, nil
	}
	registered := false
	for _, component := range previous.Components {
		if component.ComponentID == providers.FreeIPAClientProviderID && component.ProviderRegistered {
			registered = true
		}
	}
	if !registered {
		return nil, nil
	}
	stale := func(detail string) (*providers.RetirementIdentity, error) {
		return nil, newError(ErrPlanStale, "cannot recover persisted FreeIPA retirement identity: %s; re-plan required", detail)
	}
	if previous.InventoryRevision == "" || previous.InventoryRevision != current.InventoryRevision ||
		jsonHash(canonicalHostSnapshot(previous.Host)) != jsonHash(canonicalHostSnapshot(current.Host)) ||
		previous.Environment != current.Environment || previous.Environment != previous.Host.Env {
		return stale("host alias, snapshot, environment or inventory revision changed")
	}
	stage := normalizeStage(previous.Environment)
	if stage == "" {
		stage = "sandbox"
	}
	identity := ""
	add := func(value string) error {
		fqdn, err := providers.CanonicalFreeIPAFQDN(value)
		if err != nil {
			return err
		}
		if identity != "" && identity != fqdn {
			return fmt.Errorf("persisted canonical identities disagree")
		}
		identity = fqdn
		return nil
	}
	if previous.FQDN != "" {
		if err := add(previous.FQDN); err != nil {
			return stale(err.Error())
		}
	}
	for _, component := range previous.Components {
		if component.ComponentID != providers.FreeIPAClientProviderID {
			continue
		}
		for _, step := range component.Steps {
			if step.Provider != providers.FreeIPAClientProviderID {
				continue
			}
			if alias := step.Params["inventory_alias"]; alias != "" && alias != current.Host.Name {
				return stale("step alias differs from the bound host")
			}
			if savedStage := step.Params["retirement_stage"]; savedStage != "" && savedStage != stage {
				return stale("step retirement stage differs from the bound environment")
			}
			var target string
			switch step.Action {
			case providers.ActionFreeIPARosterHostAbsent, providers.ActionFreeIPAIdentityApplyConverge:
				target = step.TargetIdentity
			case providers.ActionFreeIPAClientUninstall:
				target = step.Params["retirement_fqdn"]
			default:
				continue
			}
			if target != "" {
				if err := add(target); err != nil {
					return stale(err.Error())
				}
			}
		}
	}
	if identity == "" {
		return stale("canonical plan metadata and unambiguous legacy cleanup identity are missing")
	}
	if explicit := current.Host.Extra["ipa_client_fqdn"]; explicit != "" {
		fqdn, err := providers.CanonicalFreeIPAFQDN(explicit)
		if err != nil || fqdn != identity {
			return stale("explicit current inventory FQDN differs from the persisted identity")
		}
	}
	return &providers.RetirementIdentity{InventoryAlias: current.Host.Name, Stage: stage, FQDN: identity}, nil
}

// freeIPAPlanIdentity reads only the FreeIPA host cleanup actions, whose
// target comes from resolveAuthoritativeFQDN. Other providers may target
// referenced endpoints rather than the retiring host. Lifecycle recovery has
// already validated any persisted canonical identity before these steps exist.
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
