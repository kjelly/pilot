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
	// RosterPath is the resolved (absolute, or already relative to the
	// planning caller's own workspace) path to the canonical FreeIPA
	// roster declaring this host, when the host has one — "" when it
	// doesn't. Server-resolved by the caller (planner.go), never a raw
	// caller-supplied file the provider blindly trusts as executable
	// content — it is only ever read, never written, during Plan (spec.md
	// §10.1: planning itself must not mutate anything).
	RosterPath string
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
	// Params carries small, provider-defined, non-secret key/value data a
	// later ExecutorForStep call needs to actually run this step for real
	// (e.g. a resolved roster file path) — never executable content
	// (spec.md §8.1/§31). It round-trips through Plan's persisted output
	// (Store.SavePlan/LoadPlan), so a later `apply`/`resume` process
	// invocation has it without re-deriving anything from a caller-
	// supplied value.
	Params map[string]string `json:",omitempty"`
}

// StepExecutor is one planned Step's real Inspect-then-Execute contract
// (spec.md §27.1/§27.2, INV-9/HD18, Phase 3b). Its method set is
// deliberately identical to internal/decommission's own StepExecutor
// interface (same two method signatures) without importing that package
// — providers cannot import internal/decommission, since
// internal/decommission already imports providers; Go's structural
// interface typing lets a providers.StepExecutor value be handed directly
// to decommission.NewExecStep anyway.
type StepExecutor interface {
	// Inspect reports whether the step's target state is already
	// converged, i.e. no execution needed. Called before Execute on every
	// attempt, including a resume in a brand-new process — this is what
	// makes resume-safety real: it re-queries LIVE state, never trusts
	// in-memory/persisted Go step status alone.
	Inspect(ctx context.Context) (converged bool, err error)
	// Execute performs the step's one destructive action for real. Only
	// called when Inspect just reported the step is not yet converged.
	Execute(ctx context.Context) error
}

// StepRunner is implemented by a provider whose planned Steps (Plan's
// output) can actually be executed for real (Phase 3+). A provider that
// only supports read-only Plan/Verify does not need to implement it; a
// caller that finds a Step with no corresponding StepRunner fails closed
// (cleanup_failed_terminal at the internal/decommission call site) rather
// than silently skipping the step.
type StepRunner interface {
	// ExecutorForStep returns the real Inspect/Execute pair for one
	// specific Step this provider's own Plan returned. Returns an error
	// if step.Action is not one this provider recognizes.
	ExecutorForStep(step Step) (StepExecutor, error)
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
