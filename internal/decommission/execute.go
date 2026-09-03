// execute.go implements Phase 3b's apply/resume orchestration — the piece
// Phase 2 deliberately left out (finalizer.go's own doc comment: "Phase 2
// registers no live provider... nothing in the real `pilot host
// decommission apply` CLI path ever builds a non-empty step list today").
// Once a real provider IS registered (Phase 3+, e.g. FreeIPAClientProvider),
// something has to actually walk each planned component's ordered Steps,
// execute them for real (QUIESCING -> LOCAL_CLEANUP -> CENTRAL_CLEANUP),
// independently re-verify (VERIFYING), and only then hand off to Finalize
// (FINALIZING) — that is exactly what Apply below does. cmd/pilot/cmd's
// `pilot host decommission apply|resume` and the TUI's decommission flow
// call Apply, not Finalize directly, so the two surfaces can never diverge.
//
// Resume-safety (INV-9/HD18) is achieved WITHOUT any new persisted step
// state: every apply/resume invocation builds a fresh []*ExecStep (all
// StepPending), and executor.go's existing Run always calls Inspect before
// Execute — so a step whose real-world effect already happened (checked by
// re-querying LIVE state, e.g. "is this host still enrolled", "is the
// FreeIPA host object still present") is reported converged and skipped
// without a second destructive call, regardless of which process
// invocation performed the original mutation. This matches exactly what
// executor.go's own doc comment anticipated: "Phase 3+'s real providers
// only need to implement StepExecutor — the resume semantics around it are
// already correct and already tested."
package decommission

import (
	"context"
	"fmt"
	"time"

	"github.com/kjelly/pilot/internal/decommission/providers"
)

// ApplyInput is Apply's typed input.
type ApplyInput struct {
	// Plan is the persisted plan record as currently stored.
	Plan *Plan
	// PlanInputForFreshness re-derives the plan from current on-disk
	// workspace/live state immediately before executing anything (spec.md
	// §23 step 2 / INV-3) — MUST carry the SAME Providers registry the
	// original `plan` command used, or the freshness re-derivation will
	// classify every provider-backed component as
	// external_state_unsupported again and reject as stale.
	PlanInputForFreshness PlanInput

	DecommissionID string
	Reason         string
	StartedAt      time.Time
	// Now overrides time.Now for deterministic tests. Nil means time.Now.
	Now func() time.Time

	// Store persists the completed plan/receipt on success (passed
	// straight through to Finalize) — nil skips persistence.
	Store *Store
}

func (in ApplyInput) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now().UTC()
}

// Apply is the full apply/resume orchestration (spec.md §10.3/§10.4): an
// already-completed plan replays without touching anything further
// (delegated to Finalize's own INV-15 check); otherwise it re-derives
// freshness, executes every component's planned provider steps in
// teardown order (skipping any already-converged step per Inspect —
// resume-safe), independently re-collects each registered provider's
// Verify results (INV-10), and only then calls Finalize.
func Apply(ctx context.Context, in ApplyInput) (*FinalizeResult, error) {
	if in.Plan == nil {
		return nil, newError(ErrHostNotFound, "apply: no plan supplied")
	}

	// Mirror Finalize's own INV-15 replay check here too, before touching
	// anything live: a completed plan's already-cleaned-up host may no
	// longer even be reachable, so re-executing steps against it would be
	// meaningless at best.
	if in.Plan.Status == PlanStatusCompleted && in.Plan.Receipt != nil {
		return &FinalizeResult{Status: "already_completed", Receipt: in.Plan.Receipt, Plan: in.Plan}, nil
	}

	fresh, err := CheckFreshness(ctx, in.PlanInputForFreshness, in.Plan.PlanHash)
	if err != nil {
		return nil, err
	}
	if fresh.Blocked() {
		return &FinalizeResult{Status: "blocked", Blockers: blockerDetails(fresh), Plan: fresh}, nil
	}

	if err := executeComponents(ctx, fresh, in.PlanInputForFreshness.Providers); err != nil {
		return nil, err
	}

	verifications, err := collectVerifications(ctx, fresh, in.PlanInputForFreshness.Providers)
	if err != nil {
		return nil, err
	}

	// Bug found via Phase 3b live-target testing: central/local cleanup
	// steps just intentionally mutated live state (e.g. the roster's
	// hostgroup/netgroup/HBAC/sudo membership and its host entry's own
	// state: absent) as their whole purpose — but Finalize's own internal
	// freshness re-check (defense in depth, spec.md §23 step 2) compares
	// against in.Plan.PlanHash, the PRE-cleanup snapshot. Passing the
	// original in.Plan straight through made that re-check compare
	// "roster now shows zero references" against a hash computed when the
	// roster still showed 3 references, always reporting plan_stale even
	// though nothing UNEXPECTED changed — the decommission's own intended
	// progress was indistinguishable from external drift. Re-derive once
	// more here (server-side, same as every other freshness step, INV-3)
	// so Finalize's internal re-check compares against what the situation
	// legitimately is right now, post-cleanup — and persist it, so a crash
	// between here and Finalize still resumes from the post-cleanup state
	// rather than trying to redo already-completed destructive work.
	postCleanup, err := PlanHost(ctx, in.PlanInputForFreshness)
	if err != nil {
		return nil, fmt.Errorf("decommission: re-derive plan after cleanup steps: %w", err)
	}
	postCleanup.ID = in.Plan.ID
	if in.Store != nil {
		if err := in.Store.SavePlan(postCleanup); err != nil {
			return nil, fmt.Errorf("decommission: persist post-cleanup plan: %w", err)
		}
	}

	return Finalize(ctx, FinalizeInput{
		Plan:                  postCleanup,
		PlanInputForFreshness: in.PlanInputForFreshness,
		Verifications:         verifications,
		DecommissionID:        in.DecommissionID,
		Reason:                in.Reason,
		StartedAt:             in.StartedAt,
		Now:                   in.Now,
		Store:                 in.Store,
	})
}

// executeComponents walks plan's components in teardown order (consumers
// before providers, spec.md §13) and, for each component with planned
// Steps, drives them through a fresh Executor. A component with steps but
// no registered provider, or a registered provider that does not
// implement providers.StepRunner, fails closed
// (cleanup_failed_terminal) — this should not normally happen, since
// planComponent only ever produces Steps for a registered provider, but a
// caller passing a DIFFERENT Providers map to Apply than the one `plan`
// used could otherwise silently skip real execution.
func executeComponents(ctx context.Context, plan *Plan, provs map[string]providers.Provider) error {
	byID := make(map[string]*ComponentPlan, len(plan.Components))
	for i := range plan.Components {
		c := &plan.Components[i]
		if c.ComponentID != "" {
			byID[c.ComponentID] = c
		}
	}

	order := plan.TeardownOrder
	if len(order) == 0 {
		for _, c := range plan.Components {
			if c.ComponentID != "" {
				order = append(order, c.ComponentID)
			}
		}
	}

	for _, id := range order {
		c := byID[id]
		if c == nil || len(c.Steps) == 0 {
			continue
		}
		provider := provs[id]
		if provider == nil {
			return newError(ErrCleanupFailedTerminal, "component %s has planned steps but no provider is registered to execute them", id)
		}
		runner, ok := provider.(providers.StepRunner)
		if !ok {
			return newError(ErrCleanupFailedTerminal, "component %s provider %q does not implement StepRunner — cannot execute its planned steps", id, provider.ID())
		}

		var execSteps []*ExecStep
		for i, step := range c.Steps {
			if step.Phase == "local_cleanup" && c.LocalCleanupStatus == LocalCleanupUnavailableAttested {
				// spec.md §21.2: a permanently-lost host's local cleanup is
				// recorded as attested-unavailable, never attempted (and
				// never faked as verified_removed) — skip real execution
				// of this step entirely.
				continue
			}
			se, err := runner.ExecutorForStep(step)
			if err != nil {
				return newError(ErrCleanupFailedTerminal, "component %s: build step executor for %s: %v", id, step.Action, err)
			}
			execSteps = append(execSteps, NewExecStep(fmt.Sprintf("%s:%d:%s", id, i, step.Action), step.Provider, step.Action, se))
		}
		if len(execSteps) == 0 {
			continue
		}
		if err := NewExecutor(execSteps).Run(ctx); err != nil {
			return err
		}
	}
	return nil
}

// collectVerifications independently re-collects every registered
// provider's Verify results for components this plan selected (INV-10) —
// once per unique component/provider ID, never trusting the steps that
// were just executed. A component that was ProviderRegistered at plan
// time but somehow has no provider in provs now is a caller error (a
// different Providers map than `plan` used) and fails closed rather than
// silently treating a missing check as zero residue.
func collectVerifications(ctx context.Context, plan *Plan, provs map[string]providers.Provider) ([]providers.Verification, error) {
	var out []providers.Verification
	seen := map[string]bool{}
	for _, c := range plan.Components {
		if c.ComponentID == "" || !c.ProviderRegistered || seen[c.ComponentID] {
			continue
		}
		seen[c.ComponentID] = true
		provider := provs[c.ComponentID]
		if provider == nil {
			return nil, newError(ErrCleanupFailedTerminal, "component %s was planned against a registered provider but none is registered now — refusing to treat missing verification as zero residue", c.ComponentID)
		}
		verifs, err := provider.Verify(ctx, providers.VerifyInput{
			HostName: plan.Host.Name,
			// Same FQDN precedence bug/fix as planner.go's providerFQDN:
			// host.Name (this repo's roster convention: hosts[] entries are
			// named by FQDN) over AnsibleHost (often just a bare
			// connection IP, never the FreeIPA/DNS identity).
			FQDN: firstNonEmpty(plan.Host.Name, plan.Host.AnsibleHost),
		})
		if err != nil {
			return nil, newError(ErrCleanupFailedTerminal, "component %s: verify: %v", c.ComponentID, err)
		}
		out = append(out, verifs...)
	}
	if len(seen) > 0 && len(out) == 0 {
		return nil, newError(ErrCleanupFailedTerminal, "expected verification results from %d registered provider(s) but got none — refusing to treat as zero residue", len(seen))
	}
	return out, nil
}
