// Package providers defines the typed decommission provider contract
// (spec.md §8.1). Phase 1 defines only this interface and its supporting
// types — nothing implements it yet, so every component's planning
// classification in internal/decommission is external_state_unsupported
// until a Phase 3 (FreeIPA client), Phase 4 (internal-endpoint/Wazuh), or
// Phase 5 (generic contract-driven) provider registers here.
package providers

import "context"

// Provider is the contract every live cleanup implementation (FreeIPA
// client, Wazuh agent, internal-endpoint, generic contract-driven
// component) must satisfy. Every method is deliberately typed and narrow:
// no caller-supplied shell field, no raw command, server-side target
// resolution only (spec.md §31) — a Step names a closed, provider-defined
// action, never executable content.
type Provider interface {
	// ID is the provider's stable identity, matching the component ID it
	// implements decommission for (e.g. "freeipa-client").
	ID() string
	// Inspect reports the provider's read-only view of live state for one
	// host. It must not mutate anything.
	Inspect(ctx context.Context, in InspectInput) (Inspection, error)
	// Plan returns the ordered, typed steps this provider would execute.
	// Plan itself never executes anything — see internal/decommission's
	// executor (Phase 2+).
	Plan(ctx context.Context, in PlanInput) ([]Step, error)
	// Verify independently re-queries live state and reports whether any
	// active residue remains (INV-10/INV-11) — it must never trust a prior
	// step's exit code alone.
	Verify(ctx context.Context, in VerifyInput) ([]Verification, error)
}

// InspectInput is Provider.Inspect's typed input — target identity only,
// resolved server-side by the provider; never a caller-supplied command or
// path.
type InspectInput struct {
	HostName string
	FQDN     string
}

// Inspection is one provider's read-only snapshot of live state for a host.
type Inspection struct {
	Provider string
	Detail   string
	Found    bool
}

// PlanInput is Provider.Plan's typed input.
type PlanInput struct {
	HostName           string
	FQDN               string
	OfflineDisposition string
}

// Step is one planned, typed provider action (spec.md §8.1). It
// deliberately has no "shell"/"command"/"args" field: Action is a closed
// enum the provider itself defines and executes (e.g.
// "freeipa_client_uninstall"), never caller-supplied executable content.
type Step struct {
	Provider       string
	Phase          string // local_cleanup | central_cleanup
	Action         string
	TargetIdentity string
}

// VerifyInput is Provider.Verify's typed input.
type VerifyInput struct {
	HostName string
	FQDN     string
}

// Verification is one provider's independently re-queried live-state
// result (spec.md §25).
type Verification struct {
	Provider   string
	Kind       string
	Identity   string
	Status     string // pass | active_residue | unknown_ownership | unreachable_unverified | historical_only | not_applicable
	Detail     string
	Active     bool
	Historical bool
	Ownership  string
}
