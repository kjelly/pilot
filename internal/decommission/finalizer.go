// finalizer.go implements spec.md §23's finalization boundary — the
// single place a decommission is allowed to mutate hosts.yml/
// inventory.yml/host_vars, and only after every gate in §23's required
// order passes. Domain decision logic (what to mutate, whether
// verification allows proceeding, what the receipt/retired_hosts record
// contains) lives here; the actual lock/snapshot/restore mechanics it
// needs live in workspace.go (this package, to avoid an import cycle with
// cmd/pilot/cmd — see that file's doc comment). cmd/pilot/cmd's `pilot
// host decommission apply|resume` and the TUI's decommission flow are
// thin callers of Finalize; neither reimplements this logic.
package decommission

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kjelly/pilot/internal/decommission/providers"
	"github.com/kjelly/pilot/internal/inventory"
)

// FinalizeInput is Finalize's typed input.
type FinalizeInput struct {
	// Plan is the persisted plan record as currently stored — its Status/
	// Receipt reflect any prior finalize attempt. A Status of
	// PlanStatusCompleted with a non-nil Receipt makes Finalize a no-op
	// replay (INV-15/HD24), checked BEFORE anything else — critically,
	// before re-deriving a fresh plan, since re-deriving would fail with
	// host_not_found once the host is already gone from hosts.yml.
	Plan *Plan
	// PlanInputForFreshness re-derives the plan from current on-disk
	// workspace state immediately before mutating (spec.md §23 step 2 /
	// INV-3) — WorkspaceDir/HostName/Catalog must match whatever produced
	// Plan. Its Now, if set, is also used for expiry/receipt timestamps.
	PlanInputForFreshness PlanInput
	// Verifications is the independently-collected verifier output
	// (INV-10) — Finalize only evaluates it (EvaluateVerifications), it
	// never queries a live system itself. Phase 2 passes an empty slice
	// for the only plan shape that ever reaches here unblocked (zero
	// registered providers), which vacuously satisfies the formula.
	Verifications []providers.Verification

	DecommissionID string
	Reason         string
	StartedAt      time.Time
	// Now overrides time.Now for deterministic tests. Nil means time.Now.
	Now func() time.Time

	// Store persists the completed plan/receipt and the retired_hosts
	// marker on success. Nil skips persistence entirely (useful for a
	// pure in-memory test of the mutation/verification logic alone) — but
	// then INV-15 replay-safety has nothing to check against on a later
	// call, since there is nowhere to read a prior completion from.
	Store *Store
}

func (in FinalizeInput) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now().UTC()
}

// FinalizeResult is Finalize's outcome.
type FinalizeResult struct {
	// Status is "completed", "blocked", or "already_completed".
	Status   string
	Blockers []string
	Receipt  *Receipt
	// Plan is the plan Finalize actually evaluated — for "completed" this
	// is the freshly re-derived plan (with Status/Receipt updated); for
	// "blocked" it is that same fresh plan (so callers can show why); for
	// "already_completed" it is the original persisted plan unchanged.
	Plan *Plan
}

// RemoveHostFromHostsFile removes hostName's entry from hf.Hosts. This is
// the pure, disk-free mutation primitive INV-1's finalization step is
// built on — it never runs before verification has passed (Finalize is
// its only caller in this package's decommission flow).
func RemoveHostFromHostsFile(hf *inventory.HostsFile, hostName string) bool {
	out := hf.Hosts[:0]
	removed := false
	for _, h := range hf.Hosts {
		if h.Name == hostName {
			removed = true
			continue
		}
		out = append(out, h)
	}
	hf.Hosts = out
	return removed
}

// blockerDetails renders plan's plan- and component-level blockers as
// short human-readable lines.
func blockerDetails(plan *Plan) []string {
	var out []string
	for _, b := range plan.Blockers {
		out = append(out, fmt.Sprintf("[%s] %s", b.Code, b.Detail))
	}
	for _, c := range plan.Components {
		for _, b := range c.Blockers {
			out = append(out, fmt.Sprintf("[%s] component %s: %s", b.Code, c.Role, b.Detail))
		}
	}
	return out
}

// Finalize implements spec.md §23's required order: already-completed
// replay check -> expiry -> workspace mutation lock -> freshness
// re-derivation -> independent zero-residue verification -> atomic
// mutation (hosts.yml, host_vars, inventory.yml regeneration+lint) ->
// persist retired_hosts + completed plan + receipt. INV-1 holds
// structurally: nothing below the verification gate can run before it
// passes, and any failure after mutation starts restores the exact
// pre-mutation file bytes before returning.
func Finalize(ctx context.Context, in FinalizeInput) (*FinalizeResult, error) {
	if in.Plan == nil {
		return nil, newError(ErrHostNotFound, "finalize: no plan supplied")
	}

	// INV-15/HD24: replay-safety must be checked BEFORE any re-derivation
	// — PlanHost would return host_not_found once the host is already
	// gone from hosts.yml, which must never masquerade as a new failure
	// on a plan that already completed successfully.
	if in.Plan.Status == PlanStatusCompleted && in.Plan.Receipt != nil {
		return &FinalizeResult{Status: "already_completed", Receipt: in.Plan.Receipt, Plan: in.Plan}, nil
	}

	now := in.now()
	if in.Plan.ExpiresAt != "" {
		if expires, err := time.Parse(time.RFC3339Nano, in.Plan.ExpiresAt); err == nil && now.After(expires) {
			return nil, newError(ErrPlanExpired, "plan %s expired at %s — re-plan required", in.Plan.ID, in.Plan.ExpiresAt)
		}
	}

	dir := in.PlanInputForFreshness.WorkspaceDir
	lock, err := acquireDecommissionLock(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = lock.release() }()

	fresh, err := CheckFreshness(ctx, in.PlanInputForFreshness, in.Plan.PlanHash)
	if err != nil {
		// ErrPlanStale (or a workspace error) — nothing has been mutated.
		return nil, err
	}
	if fresh.Blocked() {
		return &FinalizeResult{Status: "blocked", Blockers: blockerDetails(fresh), Plan: fresh}, nil
	}

	outcome := EvaluateVerifications(in.Verifications)
	if !outcome.Passed {
		// INV-11/HD19/HD20: zero active residue is required before
		// FINALIZING is reachable at all — the host stays in hosts.yml,
		// untouched, and no receipt is produced.
		return &FinalizeResult{Status: "blocked", Blockers: outcome.BlockerDetails(), Plan: fresh}, nil
	}

	hostsPath := filepath.Join(dir, "hosts.yml")
	hf, err := loadHostsFile(hostsPath)
	if err != nil {
		return nil, err
	}
	initialInventoryRevision := fresh.InventoryRevision

	snapshot, err := snapshotWorkspaceFiles(dir, fresh.Host.Name)
	if err != nil {
		return nil, err
	}

	if !RemoveHostFromHostsFile(hf, fresh.Host.Name) {
		// Freshness just confirmed the host exists on disk; this would
		// only happen from a programming error, not a normal runtime
		// condition — fail closed rather than silently "succeeding".
		return nil, newError(ErrFinalizationFailed, "host %q vanished from hosts.yml between freshness check and mutation", fresh.Host.Name)
	}
	hostVarsRemoved := removeHostVarsFileIfPresent(dir, fresh.Host.Name)

	mutateErr := writeFinalizedWorkspace(dir, hf)
	if mutateErr != nil {
		if restoreErr := restoreWorkspaceFiles(dir, snapshot); restoreErr != nil {
			return nil, fmt.Errorf("finalize failed (%v) and rollback also failed: %w", mutateErr, restoreErr)
		}
		return nil, newError(ErrFinalizationFailed,
			"workspace restored to its pre-finalize state; decommission %s remains resumable at finalization (no already-completed control-plane cleanup was undone): %v",
			in.DecommissionID, mutateErr)
	}

	finalInventoryRevision := canonicalInventoryHash(hf)

	receipt := &Receipt{
		DecommissionID:            in.DecommissionID,
		Host:                      fresh.Host.Name,
		FQDN:                      fresh.Host.AnsibleHost,
		Environment:               fresh.Environment,
		Reason:                    in.Reason,
		StartedAt:                 in.StartedAt.Format(time.RFC3339Nano),
		CompletedAt:               now.Format(time.RFC3339Nano),
		PlanHash:                  fresh.PlanHash,
		InitialInventoryRevision:  initialInventoryRevision,
		FinalInventoryRevision:    finalInventoryRevision,
		Components:                append([]string(nil), fresh.TeardownOrder...),
		Verified:                  true,
		HistoricalRecordsRetained: true,
	}
	if hostVarsRemoved {
		receipt.Warnings = append(receipt.Warnings, "host_vars/<host>.yml removed as exclusively host-owned")
	}

	completed := *fresh
	completed.ID = in.Plan.ID // preserve the original plan identity for show/replay lookups
	completed.Status = PlanStatusCompleted
	completed.Receipt = receipt

	if in.Store != nil {
		if err := in.Store.SavePlan(&completed); err != nil {
			return nil, fmt.Errorf("finalize: persist completed plan: %w", err)
		}
		if err := in.Store.SaveRetiredHost(fresh.Host.Name, fresh.Host.AnsibleHost, in.DecommissionID, in.Reason, now, finalInventoryRevision); err != nil {
			return nil, fmt.Errorf("finalize: persist retired_hosts record: %w", err)
		}
	}

	return &FinalizeResult{Status: "completed", Receipt: receipt, Plan: &completed}, nil
}

func loadHostsFile(path string) (*inventory.HostsFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, newError(ErrWorkspaceMalformed, "read %s: %v", path, err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		return nil, newError(ErrWorkspaceMalformed, "parse %s: %v", path, err)
	}
	return hf, nil
}

// removeHostVarsFileIfPresent removes host_vars/<hostName>.yml when
// present. Every host_vars file names exactly one host by construction
// (spec.md §23 step 5's "exclusively host-owned" is always true for this
// path), so its presence alone is enough to remove it.
func removeHostVarsFileIfPresent(dir, hostName string) bool {
	path := filepath.Join(dir, "host_vars", hostName+".yml")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false
	} else if err != nil {
		return false
	}
	if err := os.Remove(path); err != nil {
		return false
	}
	return true
}

// writeFinalizedWorkspace lints hf, writes hosts.yml, then regenerates and
// writes inventory.yml via internal/inventory.Generate (spec.md §23 steps
// 6-7 — Generate itself refuses to render over a lint error, so a bad
// post-removal hosts.yml is caught here rather than silently written).
func writeFinalizedWorkspace(dir string, hf *inventory.HostsFile) error {
	if issues := inventory.Lint(hf); inventory.HasErrors(issues) {
		return fmt.Errorf("post-removal hosts.yml failed lint: %v", issues)
	}
	rendered, err := inventory.Render(hf)
	if err != nil {
		return fmt.Errorf("render hosts.yml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(rendered), 0o644); err != nil {
		return fmt.Errorf("write hosts.yml: %w", err)
	}

	generated, err := inventory.Generate(hf)
	if err != nil {
		return fmt.Errorf("regenerate inventory.yml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "inventory.yml"), []byte(generated), 0o644); err != nil {
		return fmt.Errorf("write inventory.yml: %w", err)
	}
	return nil
}
