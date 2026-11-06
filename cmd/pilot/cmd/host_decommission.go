// host_decommission.go implements `pilot host decommission plan|show|
// apply|resume` — Phase 1 (plan/show, read-only, see the package doc
// comments in internal/decommission) and Phase 2
// (docs/superpowers/specs/2026-09-02-host-decommission-spec.md §37) of
// the host decommission feature. `apply`/`resume` are thin orchestration
// over internal/decommission.Finalize — the domain logic (freshness
// re-check, verification evaluation, workspace mutation, replay-safety)
// lives there, not here (spec.md §8's "CLI/TUI is orchestration only"
// rule). The TUI's decommission flow (edit_tui_decommission.go) calls the
// same runHostDecommissionApply helper this file's `apply` command uses,
// so the two surfaces can never diverge in behavior.
//
// Style/flag conventions mirror internal_endpoint_cli.go: package-level
// flag vars, --dir/--json, cobra.NoArgs, errors returned rather than
// printed+swallowed.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/decommission"
	"github.com/kjelly/pilot/internal/decommission/providers"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/inventory"
)

var (
	hostDecommissionPlanDir       string
	hostDecommissionPlanHost      string
	hostDecommissionPlanJSON      bool
	hostDecommissionPlanRetention []string

	hostDecommissionShowID   string
	hostDecommissionShowJSON bool

	hostDecommissionApplyID          string
	hostDecommissionApplyDir         string
	hostDecommissionApplyConfirmHost string
	hostDecommissionApplyJSON        bool

	hostDecommissionResumeID   string
	hostDecommissionResumeDir  string
	hostDecommissionResumeJSON bool
)

var hostCmd = &cobra.Command{
	Use:   "host",
	Short: "Host lifecycle operations",
}

var hostDecommissionCmd = &cobra.Command{
	Use:   "decommission",
	Short: "Plan, apply, and resume host decommission (spec.md §10)",
}

var hostDecommissionPlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Produce a read-only host decommission plan and persist it (spec.md §10.1)",
	Args:  cobra.NoArgs,
	RunE:  runHostDecommissionPlanCmd,
}

var hostDecommissionShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show a persisted host decommission plan",
	Args:  cobra.NoArgs,
	RunE:  runHostDecommissionShowCmd,
}

var hostDecommissionApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply a previously planned host decommission (spec.md §10.3). Only a zero-blocker plan can execute — any component with no registered decommission provider still blocks",
	Long: `pilot host decommission apply runs the steps of a persisted plan. A plan with a
FreeIPA client has a last, central step that runs the identity apply playbook,
and the whole run holds the FreeIPA server's /etc/ipa lock: it is taken once,
after the approval is recorded and before the first step (the client's
uninstall), waiting up to 30 minutes for another pilot run to give it back, and
given back when the run ends. A lock that is busy, a wait that runs out, an
interrupt during the wait or a refusal therefore leaves the client, the roster
and the server as they were, with the approval kept: run apply again or
'pilot host decommission resume' with the same plan once the lock is free.

` + identityLockHelp + `

For apply that check is made before the approval is recorded and before the
client is uninstalled. 'pilot host decommission plan' prints the same refusal as
a warning on stderr; it does not block the plan.`,
	Args: cobra.NoArgs,
	RunE: runHostDecommissionApplyCmd,
}

var hostDecommissionResumeCmd = &cobra.Command{
	Use:   "resume",
	Short: "Resume a host decommission after a failure/interruption (spec.md §10.4)",
	Long: `pilot host decommission resume continues an interrupted apply. A plan with a
FreeIPA client holds the FreeIPA server's /etc/ipa lock for the whole run, taken
before its first step (waiting up to 30 minutes for another pilot run to give it
back) and given back when the run ends, so a lock it cannot get changes nothing:
resume it again later.

` + identityLockHelp + `

For resume that check is made before any step. A plan whose converge step already
ran is checked all the same: an inventory that stopped being lockable since is
refused, not skipped.`,
	Args: cobra.NoArgs,
	RunE: runHostDecommissionResumeCmd,
}

func init() {
	hostDecommissionPlanCmd.Flags().StringVar(&hostDecommissionPlanDir, "dir", ".", "workspace directory containing hosts.yml")
	hostDecommissionPlanCmd.Flags().StringVar(&hostDecommissionPlanHost, "host", "", "host name to plan decommission for (required)")
	hostDecommissionPlanCmd.Flags().BoolVar(&hostDecommissionPlanJSON, "json", false, "print the plan as JSON")
	hostDecommissionPlanCmd.Flags().StringArrayVar(&hostDecommissionPlanRetention, "retention", nil, "explicit retention disposition for a stateful component, repeatable: --retention <component-id>=<exported|migrated|retain_on_disk|destroy_authorized> (spec.md §20.1, INV-8)")
	hostDecommissionCmd.AddCommand(hostDecommissionPlanCmd)

	hostDecommissionShowCmd.Flags().StringVar(&hostDecommissionShowID, "id", "", "plan id to show (required)")
	hostDecommissionShowCmd.Flags().BoolVar(&hostDecommissionShowJSON, "json", false, "print the plan as JSON")
	hostDecommissionCmd.AddCommand(hostDecommissionShowCmd)

	hostDecommissionApplyCmd.Flags().StringVar(&hostDecommissionApplyID, "id", "", "plan id to apply (required)")
	hostDecommissionApplyCmd.Flags().StringVar(&hostDecommissionApplyDir, "dir", ".", "workspace directory containing hosts.yml (must match the plan's workspace)")
	hostDecommissionApplyCmd.Flags().StringVar(&hostDecommissionApplyConfirmHost, "confirm-host", "", "exact host name being decommissioned — required, must match the plan's host exactly (spec.md §10.3 requirement 6; no generic --yes)")
	hostDecommissionApplyCmd.Flags().BoolVar(&hostDecommissionApplyJSON, "json", false, "print the result as JSON")
	addHostDecommissionStageFlags(hostDecommissionApplyCmd, &hostDecommissionApplyStage)
	hostDecommissionCmd.AddCommand(hostDecommissionApplyCmd)

	hostDecommissionResumeCmd.Flags().StringVar(&hostDecommissionResumeID, "id", "", "plan id to resume (required)")
	hostDecommissionResumeCmd.Flags().StringVar(&hostDecommissionResumeDir, "dir", ".", "workspace directory containing hosts.yml (must match the plan's workspace)")
	hostDecommissionResumeCmd.Flags().BoolVar(&hostDecommissionResumeJSON, "json", false, "print the result as JSON")
	addHostDecommissionStageFlags(hostDecommissionResumeCmd, &hostDecommissionResumeStage)
	hostDecommissionCmd.AddCommand(hostDecommissionResumeCmd)

	hostCmd.AddCommand(hostDecommissionCmd)
	rootCmd.AddCommand(hostCmd)
}

// runHostDecommissionPlanCmd implements `pilot host decommission plan`.
// Planning itself (decommission.PlanHost) is strictly read-only; the only
// write this command performs is persisting the resulting plan to Pilot's
// own SQLite store (so `show` can read it back) — spec.md §10.1's
// "planning must not touch X" list is about live external systems
// (FreeIPA, Wazuh, services, workspace YAML files, Agent Controller), not
// Pilot's own store.
func runHostDecommissionPlanCmd(cmd *cobra.Command, _ []string) error {
	if strings.TrimSpace(hostDecommissionPlanHost) == "" {
		return fmt.Errorf("--host is required")
	}
	dir, err := filepath.Abs(hostDecommissionPlanDir)
	if err != nil {
		return fmt.Errorf("resolve --dir: %w", err)
	}

	catalog, err := loadHostDecommissionCatalog()
	if err != nil {
		return err
	}

	provs, err := buildHostDecommissionProviders(dir, hostDecommissionPlanHost, catalog, cmd.ErrOrStderr(), noStageAuthorization())
	if err != nil {
		return err
	}

	retentionDispositions, err := parseRetentionDispositionFlags(hostDecommissionPlanRetention)
	if err != nil {
		return err
	}

	plan, err := decommission.PlanHost(cmd.Context(), decommission.PlanInput{
		WorkspaceDir:          dir,
		HostName:              hostDecommissionPlanHost,
		Catalog:               catalog,
		Providers:             provs,
		RetentionDispositions: retentionDispositions,
	})
	if err != nil {
		return err
	}

	st, err := openSpecStore()
	if err != nil {
		return fmt.Errorf("open pilot store: %w", err)
	}
	defer func() { _ = st.Close() }()
	if err := decommission.NewStore(st).SavePlan(plan); err != nil {
		return fmt.Errorf("persist plan: %w", err)
	}

	out := cmd.OutOrStdout()
	if err := printHostDecommissionPlan(out, plan, hostDecommissionPlanJSON); err != nil {
		return err
	}
	if !hostDecommissionPlanJSON {
		printHostDecommissionStageNeeds(out, dir, plan)
	}
	// A plan that apply would refuse is said so now, on stderr (the JSON on
	// stdout is untouched). It is a warning and not a blocker on purpose: a
	// blocker is part of what the plan hash and the freshness re-derivation
	// compare, and this one depends on connection variables of the inventory
	// that are no part of the plan's recorded external state, so it would turn
	// a change of those into plan_stale and make a plan nobody can apply look
	// like a plan that is merely out of date. apply and resume refuse it
	// themselves, before their first step (runHostDecommissionApply).
	warnIfDecommissionIsUnlockable(cmd.Context(), cmd.ErrOrStderr(), dir, plan)

	// Exit behavior per spec.md §10.1: a successful, unblocked plan is
	// success (nil); a valid-but-blocked plan is a non-zero structured
	// result — the plan has already been printed above, so this error
	// only drives the exit code, it does not hide anything from the
	// operator.
	if plan.Blocked() {
		return fmt.Errorf("plan %s is blocked — see blockers above; resolve them (e.g. register a decommission provider, supply a --retention disposition, or clean up unknown-ownership state) and plan again before apply", plan.ID)
	}
	return nil
}

// runHostDecommissionShowCmd implements `pilot host decommission show`.
// Read-only.
func runHostDecommissionShowCmd(cmd *cobra.Command, _ []string) error {
	if strings.TrimSpace(hostDecommissionShowID) == "" {
		return fmt.Errorf("--id is required")
	}
	st, err := openSpecStore()
	if err != nil {
		return fmt.Errorf("open pilot store: %w", err)
	}
	defer func() { _ = st.Close() }()

	plan, err := decommission.NewStore(st).LoadPlan(hostDecommissionShowID)
	if err != nil {
		return fmt.Errorf("load plan %s: %w", hostDecommissionShowID, err)
	}
	return printHostDecommissionPlan(cmd.OutOrStdout(), plan, hostDecommissionShowJSON)
}

func loadHostDecommissionCatalog() (contract.Catalog, error) {
	root, err := resolveContractRoot("")
	if err != nil {
		return contract.Catalog{}, err
	}
	loader, err := contract.NewLoader(root)
	if err != nil {
		return contract.Catalog{}, err
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		return contract.Catalog{}, fmt.Errorf("load contract catalog: %w", err)
	}
	return catalog, nil
}

// validRetentionDispositions is the CLI-facing string form of
// decommission.RetentionDisposition's non-empty values (spec.md §20.1) —
// kept as an explicit allowlist here (rather than accepting any string)
// so a typo produces a clear error at plan time instead of a silently
// unsatisfied retention gate.
var validRetentionDispositions = map[string]decommission.RetentionDisposition{
	"exported":           decommission.RetentionDispositionExported,
	"migrated":           decommission.RetentionDispositionMigrated,
	"retain_on_disk":     decommission.RetentionDispositionRetainOnDisk,
	"destroy_authorized": decommission.RetentionDispositionDestroyAuthorized,
}

// parseRetentionDispositionFlags parses repeated --retention
// <component-id>=<disposition> flags into the map PlanInput.
// RetentionDispositions expects (spec.md §20.1, INV-8). nil input yields
// a nil (not empty) map — every stateful/retention:required component
// simply stays gated exactly as it was before this flag existed.
func parseRetentionDispositionFlags(raw []string) (map[string]decommission.RetentionDisposition, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[string]decommission.RetentionDisposition, len(raw))
	for _, entry := range raw {
		componentID, value, ok := strings.Cut(entry, "=")
		componentID = strings.TrimSpace(componentID)
		value = strings.TrimSpace(value)
		if !ok || componentID == "" || value == "" {
			return nil, fmt.Errorf("--retention %q: expected <component-id>=<disposition>", entry)
		}
		disposition, ok := validRetentionDispositions[value]
		if !ok {
			return nil, fmt.Errorf("--retention %q: unknown disposition %q (want one of exported, migrated, retain_on_disk, destroy_authorized)", entry, value)
		}
		out[componentID] = disposition
	}
	return out, nil
}

// retentionDispositionsFromPlan recovers the SAME retention dispositions
// a persisted plan's RetentionRequirements already recorded (spec.md
// §9.1) — apply/resume must rebuild the exact same
// PlanInput.RetentionDispositions the original `plan` command used (same
// reasoning as buildHostDecommissionProviders's own doc comment: the
// freshness re-derivation inside Apply/Finalize re-runs PlanHost against
// it), without requiring the operator to repeat --retention flags they
// already supplied once at plan time.
func retentionDispositionsFromPlan(plan *decommission.Plan) map[string]decommission.RetentionDisposition {
	if len(plan.RetentionRequirements) == 0 {
		return nil
	}
	out := make(map[string]decommission.RetentionDisposition, len(plan.RetentionRequirements))
	for _, r := range plan.RetentionRequirements {
		if r.Disposition != decommission.RetentionDispositionNone {
			out[r.ComponentID] = r.Disposition
		}
	}
	return out
}

func printHostDecommissionPlan(out io.Writer, plan *decommission.Plan, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(plan)
	}

	fmt.Fprintf(out, "PLAN %s host=%s status=%s hash=%s\n", plan.ID, plan.Host.Name, plan.Status, shortHash(plan.PlanHash))
	if len(plan.Host.Roles) > 0 {
		fmt.Fprintf(out, "  roles: %s\n", strings.Join(plan.Host.Roles, ", "))
	} else {
		fmt.Fprintln(out, "  roles: (none)")
	}
	if len(plan.TeardownOrder) > 0 {
		fmt.Fprintf(out, "  teardown order: %s\n", strings.Join(plan.TeardownOrder, " -> "))
	}
	for _, c := range plan.Components {
		fmt.Fprintf(out, "  component role=%s id=%s supported=%v\n", c.Role, c.ComponentID, !c.Blocked())
		for _, b := range c.Blockers {
			fmt.Fprintf(out, "    blocker[%s]: %s\n", b.Code, b.Detail)
		}
		if c.LocalCleanupStatus != "" {
			fmt.Fprintf(out, "    local_cleanup_status: %s\n", c.LocalCleanupStatus)
		}
	}
	for _, r := range plan.References {
		fmt.Fprintf(out, "  reference %s/%s %q -> %s (%s)\n", r.Source, r.Kind, r.Identity, r.Classification, r.Detail)
	}
	for _, b := range plan.Blockers {
		fmt.Fprintf(out, "  blocker[%s]: %s\n", b.Code, b.Detail)
	}
	for _, w := range plan.Warnings {
		fmt.Fprintf(out, "  warning[%s]: %s\n", w.Code, w.Detail)
	}
	fmt.Fprintf(out, "  expires_at: %s\n", plan.ExpiresAt)
	return nil
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// runHostDecommissionApplyCmd implements `pilot host decommission apply`
// (spec.md §10.3). Requirements 1-5/7 (plan exists, no blocker, not
// expired, freshness re-derivation, hash match, not already completed)
// are enforced inside decommission.Finalize; requirement 6 (explicit
// human confirmation, exact host name, no generic --yes) is enforced
// right here before an approval is even recorded.
func runHostDecommissionApplyCmd(cmd *cobra.Command, _ []string) error {
	if strings.TrimSpace(hostDecommissionApplyID) == "" {
		return fmt.Errorf("--id is required")
	}
	if strings.TrimSpace(hostDecommissionApplyConfirmHost) == "" {
		return fmt.Errorf("--confirm-host is required (spec.md §10.3 requirement 6) — pilot does not support a generic --yes for host decommission")
	}
	auth, err := hostDecommissionApplyStage.authorization()
	if err != nil {
		return err
	}
	dir, err := filepath.Abs(hostDecommissionApplyDir)
	if err != nil {
		return fmt.Errorf("resolve --dir: %w", err)
	}

	st, err := openSpecStore()
	if err != nil {
		return fmt.Errorf("open pilot store: %w", err)
	}
	defer func() { _ = st.Close() }()
	ds := decommission.NewStore(st)

	plan, err := ds.LoadPlan(hostDecommissionApplyID)
	if err != nil {
		return fmt.Errorf("load plan %s: %w", hostDecommissionApplyID, err)
	}

	if plan.Status != decommission.PlanStatusCompleted && hostDecommissionApplyConfirmHost != plan.Host.Name {
		return fmt.Errorf("--confirm-host %q does not match plan %s's host %q — refusing to apply (spec.md §10.3 requirement 6)", hostDecommissionApplyConfirmHost, plan.ID, plan.Host.Name)
	}

	catalog, err := loadHostDecommissionCatalog()
	if err != nil {
		return err
	}

	result, err := runHostDecommissionApply(cmd.Context(), ds, plan, dir, catalog, "apply via `pilot host decommission apply --confirm-host`", auth)
	if err != nil {
		return err
	}
	return reportHostDecommissionResult(cmd.OutOrStdout(), result, hostDecommissionApplyJSON)
}

// runHostDecommissionResumeCmd implements `pilot host decommission
// resume` (spec.md §10.4): re-derives freshness first (inside Finalize);
// if external state changed in a way that invalidates already-completed
// assumptions, the caller sees stale_resume. It requires an approval
// already recorded by a prior `apply` attempt — resume never collects a
// fresh --confirm-host itself, since the operator already confirmed once
// for this plan_hash (spec.md §30: approval survives across resume as
// long as the hash has not changed; a changed hash means CheckFreshness
// itself returns plan_stale here, not stale_resume specifically — Phase 2
// does not yet distinguish the two failure shapes further).
func runHostDecommissionResumeCmd(cmd *cobra.Command, _ []string) error {
	if strings.TrimSpace(hostDecommissionResumeID) == "" {
		return fmt.Errorf("--id is required")
	}
	auth, err := hostDecommissionResumeStage.authorization()
	if err != nil {
		return err
	}
	dir, err := filepath.Abs(hostDecommissionResumeDir)
	if err != nil {
		return fmt.Errorf("resolve --dir: %w", err)
	}

	st, err := openSpecStore()
	if err != nil {
		return fmt.Errorf("open pilot store: %w", err)
	}
	defer func() { _ = st.Close() }()
	ds := decommission.NewStore(st)

	plan, err := ds.LoadPlan(hostDecommissionResumeID)
	if err != nil {
		return fmt.Errorf("load plan %s: %w", hostDecommissionResumeID, err)
	}

	catalog, err := loadHostDecommissionCatalog()
	if err != nil {
		return err
	}

	if plan.Status != decommission.PlanStatusCompleted {
		if err := decommission.RequireApproval(ds, plan.ID, plan.PlanHash, plan.Environment); err != nil {
			return fmt.Errorf("resume requires an approval already recorded by a prior `apply` attempt for the exact current plan_hash: %w", err)
		}
	}

	result, err := runHostDecommissionApply(cmd.Context(), ds, plan, dir, catalog, "resume via `pilot host decommission resume`", auth)
	if err != nil {
		if decommission.ClassOf(err) == decommission.ErrPlanStale {
			return fmt.Errorf("stale_resume: %w — external/workspace state changed since this plan was created; a new plan is required", err)
		}
		return err
	}
	return reportHostDecommissionResult(cmd.OutOrStdout(), result, hostDecommissionResumeJSON)
}

// runHostDecommissionApply is the CLI-layer orchestration shared by
// `apply` and `resume` (and, via the same call shape, the TUI's
// decommission flow — edit_tui_decommission.go). It records the human
// approval (apply's --confirm-host having just matched IS the human
// confirmation spec.md §10.3 requirement 6 asks for), gates on it via
// decommission.RequireApproval, then calls decommission.Apply — all
// domain logic. Already-completed plans record no new approval (nothing
// left to confirm) and go straight to Apply, which recognizes the
// replay and returns already_completed without touching approval state.
//
// A plan with the freeipa-identity converge step holds the FreeIPA server's
// /etc/ipa lock for the whole of Apply, not for that step. D1 of
// docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md takes the
// lock after the confirmation and before the first thing that changes anything,
// and the first change a decommission makes is the client's uninstall, many steps
// before the converge: a lock taken only at the converge (as it was) that is busy,
// runs out of time or is interrupted had already uninstalled the client and
// tombstoned the roster entry (found live, the E41 row of that spec). So the lock
// is taken once, after the confirmation (the approval) and before the first
// step, and a refusal, a busy lock, a wait that runs out or a cancel changes
// nothing: the approval is kept, and apply again or resume carries on with the
// same plan. Apply's context is bound to it (Held.Bind), so a lock that is lost
// stops the run before its next step and kills the playbook that is running; the
// converge step finds the lock in that context (identitylock.Require) and takes
// none of its own. The freshness re-derivation at the start of Apply runs under
// the lock too: it reads state no other pilot run can change until this one ends,
// at the price of waiting for the lock before an out-of-date plan is reported as
// such. This is about when the lock is taken; it does not change what a half-done
// decommission needs in order to be resumable (see issue #303: a workspace without
// ipa_client_fqdn cannot finish after the uninstall, with or without this lock).
func runHostDecommissionApply(ctx context.Context, ds *decommission.Store, plan *decommission.Plan, dir string, catalog contract.Catalog, reason string, auth decommission.StageAuthorization) (*decommission.FinalizeResult, error) {
	now := time.Now().UTC()
	if plan.Status != decommission.PlanStatusCompleted {
		// Resume repeats the stage confirmation instead of reusing the one
		// given to apply: the attestation age it carries goes stale.
		if err := checkHostDecommissionStage(dir, plan, auth); err != nil {
			return nil, err
		}
	}

	// The SAME provider registry `plan` used must be rebuilt here — the
	// freshness re-derivation inside Apply/Finalize re-runs PlanHost
	// against it, and a plan that was executable because a provider WAS
	// registered would otherwise stale-reject as soon as that provider
	// vanished from freshness's view (spec.md §28/INV-3). It is built before
	// the approval is recorded, so that what refuses a run does so before it
	// leaves anything behind, and it regenerates inventory.yml, which the lock
	// precheck below reads.
	provs, err := buildHostDecommissionProviders(dir, plan.Host.Name, catalog, os.Stderr, auth)
	if err != nil {
		return nil, err
	}

	// Only a plan that is not completed and runs the converge step takes the
	// lock: an already completed plan replays its receipt and runs nothing, and a
	// plan without the step never runs the identity apply playbook.
	needsLock := plan.Status != decommission.PlanStatusCompleted && planHasIdentityConverge(plan)
	var acquire identitylock.Acquirer
	if needsLock {
		// Before the first step, and before the approval: an inventory the lock
		// cannot be taken through is refused before the run leaves anything
		// behind. identityLockFor makes that check (no ssh) and builds the
		// Acquirer, which is called once, below.
		lockRequest, requestErr := hostDecommissionLockRequest(dir)
		if requestErr != nil {
			return nil, requestErr
		}
		acquire, err = identityLockFor(ctx, lockRequest)
		if err != nil {
			return nil, err
		}
	}
	if plan.Status != decommission.PlanStatusCompleted {
		if err := ds.RecordApproval(plan.ID, plan.PlanHash, decommissionActor(), "approve", reason, now); err != nil {
			return nil, fmt.Errorf("record approval: %w", err)
		}
		if err := decommission.RequireApproval(ds, plan.ID, plan.PlanHash, plan.Environment); err != nil {
			return nil, err
		}
	}

	var held *identitylock.Held
	if needsLock {
		// After the confirmation, before anything is executed (D1).
		held, err = acquire(ctx)
		if err != nil {
			return nil, fmt.Errorf("host decommission %s was not started: the FreeIPA identity lock could not be taken, so no step ran and the client, the roster and the server are as they were; the approval is kept, so `pilot host decommission resume --id %s` (or apply again) carries on with this plan once the lock is free: %w", plan.ID, plan.ID, err)
		}
		defer func() { _ = held.Release() }()
		bound, cancel := held.Bind(ctx)
		defer cancel()
		ctx = bound
	}

	result, err := decommission.Apply(ctx, decommission.ApplyInput{
		Plan: plan,
		PlanInputForFreshness: decommission.PlanInput{
			WorkspaceDir: dir, HostName: plan.Host.Name, Catalog: catalog, Providers: provs,
			// Recovered from the plan itself (spec.md §9.1) — see
			// retentionDispositionsFromPlan's own doc comment: the
			// operator supplied these once at `plan` time; apply/resume
			// must not require repeating them, and re-deriving from a
			// caller-supplied flag here would risk apply/resume silently
			// using a DIFFERENT disposition than what was actually
			// approved.
			RetentionDispositions: retentionDispositionsFromPlan(plan),
		},
		DecommissionID: plan.ID,
		Reason:         reason,
		StartedAt:      now,
		Store:          ds,
	})
	if held != nil {
		// Whatever Apply ended with: a run whose lock was lost did not run under it
		// (see accessgrants.applyPlan), and what the loss cancelled would otherwise
		// be reported as a bare "context canceled".
		if lostErr := held.Check(); lostErr != nil {
			if err != nil {
				return nil, fmt.Errorf("host decommission %s stopped: %w (the run ended with: %v)", plan.ID, lostErr, err)
			}
			return nil, fmt.Errorf("host decommission %s: %w", plan.ID, lostErr)
		}
	}
	return result, err
}

// buildHostDecommissionProviders constructs the live decommission
// provider registry for hostName in the workspace at dir (spec.md §8.1).
// Phase 3a wired FreeIPAClientProvider's Go-level contract
// (internal/decommission/providers/freeipa_client.go) but never actually
// registered it anywhere the real CLI could reach — its own report
// explicitly deferred "CLI-level provider registration... needs live-run
// validation of playbook/inventory path resolution first". This is that
// wiring: every `pilot host decommission plan|apply|resume` invocation
// calls this to populate decommission.PlanInput.Providers, so a
// freeipa-client host's steps actually get planned/executed instead of
// unconditionally falling back to external_state_unsupported.
//
// It returns an empty (non-nil) map, never an error, whenever hostName
// isn't found or the workspace is otherwise not ready for it (e.g. no
// hosts.yml yet) — planning/apply then simply behaves exactly as it did
// before this function existed (Phase 1/2's fail-closed default), rather
// than surfacing a confusing error from a helper whose only job is to
// opportunistically enrich the registry. PlanHost/CheckFreshness
// themselves already produce the authoritative "workspace malformed"
// error from the SAME hosts.yml read.
func buildHostDecommissionProviders(dir, hostName string, catalog contract.Catalog, out io.Writer, auth decommission.StageAuthorization) (map[string]providers.Provider, error) {
	empty := map[string]providers.Provider{}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		return empty, nil
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		return empty, nil
	}
	var host *inventory.Host
	for i := range hf.Hosts {
		if hf.Hosts[i].Name == hostName {
			host = &hf.Hosts[i]
			break
		}
	}
	if host == nil {
		return empty, nil
	}

	invPath := filepath.Join(dir, "inventory.yml")
	if _, err := autoRegenerateInventoryFromHosts(out, invPath); err != nil {
		return nil, fmt.Errorf("regenerate inventory.yml for host decommission: %w", err)
	}
	if _, statErr := os.Stat(invPath); statErr != nil {
		return empty, nil
	}

	rosterPath := decommission.RosterPathFor(dir, hf.Hosts, *host)

	// Every other ansible.Runner caller (pilot deploy/reconcile/edit/mcp)
	// goes through prepareDeployAnsibleRuntime first, which MkdirAlls a
	// scratch ansible/{home,tmp,fact-cache} tree plus a private SSH control
	// directory and points ANSIBLE_SSH_ARGS' ControlPath at the latter.
	// Skipping that here left this runner relying on ansible.cfg's default
	// `~/.ansible/cp/...` ControlPath, which silently doesn't exist in a
	// fresh/ephemeral container (`docker run --rm ... pilot host
	// decommission plan`) — the very first SSH connection then fails with
	// "unix_listener: cannot bind to path ...: No such file or directory",
	// which Ansible reports as UNREACHABLE on whatever task happens to run
	// first, and no_log (as on freeipa-identity-apply.yml's "Kinit admin"
	// task) censors that real reason into an opaque "censored" blob that
	// looks like a Kerberos/credential failure. Found via a live
	// decommission-plan repro against p6k-baremetal (2026-09-11).
	runtime, err := prepareDeployAnsibleRuntime(resolvePilotDataDir())
	if err != nil {
		return nil, fmt.Errorf("prepare ansible runtime for host decommission: %w", err)
	}
	runner := ansible.NewRunner()
	runner.Env = runtime.Env
	runner.LogPath = runtime.LogPath
	runner.StdoutWriter = out
	runner.StderrWriter = out

	extraArgs := hostDecommissionFreeIPAExtraArgs(invPath, rosterPath)

	// Each playbook run carries the stage of the hosts it targets
	// (internal/decommission/stage.go): the retired host for local steps,
	// the freeipa-server or wazuh-manager hosts for central ones.
	scope := decommission.NewStageScope(hf.Hosts, auth)
	hostStage := scope.ArgsFunc([]string{hostName})
	retirementStage, err := scope.Stage([]string{hostName})
	if err != nil {
		return nil, err
	}
	var retirementFQDN string
	for _, host := range hf.Hosts {
		if host.Name == hostName {
			retirementFQDN = host.Extra["ipa_client_fqdn"]
			break
		}
	}

	freeipaClient := providers.NewFreeIPAClientProvider(providers.FreeIPAClientProviderConfig{
		Executor:              runner,
		InventoryAlias:        hostName,
		InventoryFQDN:         retirementFQDN,
		RetirementStage:       retirementStage,
		ClientInventory:       invPath,
		ServerInventory:       invPath,
		DecommissionPlaybook:  "playbooks/decommission/freeipa-client-decommission.yml",
		IdentityApplyPlaybook: "playbooks/apply/freeipa-identity-apply.yml",
		ExtraArgs:             extraArgs,
		ClientStageArgs:       hostStage,
		ServerStageArgs:       scope.ArgsFunc(scope.RoleHosts(stageRoleFreeIPAServer)),
		// No lock here: the converge runs freeipa-identity-apply.yml under the
		// FreeIPA server's /etc/ipa lock, but the run's owner takes it before the
		// first step (runHostDecommissionApply) and the step reads it from its
		// context. plan builds this registry too and never locks.
	})

	// Wazuh agent (spec.md §37 Phase 4, HD14) — registered unconditionally,
	// same posture as freeipaClient above: the map KEY is what gates
	// whether planComponent's role-match ever consults it, so registering
	// here regardless of whether hostName actually carries role wazuh-fim
	// is harmless (planner.go only calls Plan() when a role resolved to
	// this exact component ID).
	wazuhAgent := providers.NewWazuhAgentProvider(providers.WazuhAgentProviderConfig{
		Executor:                  runner,
		AgentInventory:            invPath,
		ServerInventory:           invPath,
		AgentDecommissionPlaybook: "playbooks/decommission/wazuh-agent-decommission.yml",
		ManagerDeregisterPlaybook: "playbooks/decommission/wazuh-manager-agent-deregister.yml",
		AgentStageArgs:            hostStage,
		ManagerStageArgs:          scope.ArgsFunc(scope.RoleHosts(stageRoleWazuhManager)),
	})

	// Internal-endpoint (spec.md §37 Phase 4, HD13) — reference-driven, not
	// role-driven (see internal/decommission/internal_endpoint_component.go's
	// doc comment): registered unconditionally too, gated instead by
	// whether internal-endpoints.yaml even exists and references hostName
	// at all (InternalEndpointProvider.Plan's own no-op-when-nothing-
	// references-this-host behavior).
	internalEndpoint := providers.NewInternalEndpointProvider(providers.InternalEndpointProviderConfig{
		Executor:        runner,
		ManifestPath:    filepath.Join(dir, "internal-endpoints.yaml"),
		ServerInventory: invPath,
		ApplyPlaybook:   "playbooks/apply/internal-endpoint-apply.yml",
		ExtraArgs: []string{
			"-e", "internal_endpoint_manifest_file=" + filepath.Join(dir, "internal-endpoints.yaml"),
			"-e", "freeipa_dns_manifest_file=" + filepath.Join(dir, "freeipa-dns.yaml"),
		},
		ApplyStageArgs: scope.ArgsFunc(scope.AllHosts()),
	})

	// FreeIPA NFS server (spec.md §37 Phase 6, §20.2) — role-driven, single
	// identity, same shape as freeipaClient above. Reuses the SAME roster
	// path resolution (a host with role freeipa-nfs-server always also
	// carries freeipa-client via the contract's sameHosts dependency, so
	// its freeipa_roster_file extra var is the same one freeipaClient
	// already resolved).
	freeipaNFSServer := providers.NewFreeIPANFSServerProvider(providers.FreeIPANFSServerProviderConfig{
		Executor:             runner,
		Inventory:            invPath,
		DecommissionPlaybook: "playbooks/decommission/freeipa-nfs-server-decommission.yml",
		ExtraArgs:            extraArgs,
		StageArgs:            hostStage,
	})

	// login-probe targets (spec.md §19, GitHub issue #11) — reference-driven
	// like internal-endpoint: every login-probe host renders the retiring
	// host into its probe target list, so the step re-renders those hosts
	// (with their own stage) without it. The probe hosts are resolved here,
	// server-side, from hosts.yml — never from caller input. The re-render
	// is a full login-probe-apply.yml run, whose always-tagged gates read
	// node_exporter_basic_auth_password from the vault, so it gets the
	// workspace's main vault exactly as `pilot deploy` passes it.
	loginProbeTargets := providers.NewLoginProbeTargetsProvider(providers.LoginProbeTargetsProviderConfig{
		Executor:       runner,
		Inventory:      invPath,
		QueryPlaybook:  "playbooks/decommission/login-probe-target-query.yml",
		ApplyPlaybook:  "playbooks/apply/login-probe-apply.yml",
		ProbeHosts:     scope.RoleHosts(stageRoleLoginProbe),
		ExtraArgs:      hostDecommissionVaultArgs(invPath),
		ApplyStageArgs: scope.ArgsFunc(scope.RoleHosts(stageRoleLoginProbe)),
	})

	result := map[string]providers.Provider{
		providers.FreeIPAClientProviderID:     freeipaClient,
		providers.WazuhAgentProviderID:        wazuhAgent,
		providers.InternalEndpointProviderID:  internalEndpoint,
		providers.FreeIPANFSServerProviderID:  freeipaNFSServer,
		providers.LoginProbeTargetsProviderID: loginProbeTargets,
	}

	// Generic contract-driven components (spec.md §37 Phase 5, §15): every
	// OTHER component with a declared playbooks.decommission gets one
	// GenericComponentProvider instance, keyed by its own contract ID —
	// never for a component already covered by a bespoke provider above
	// (registering both would be harmless in practice, since planComponent
	// only ever consults ONE map entry per component ID, but skipping them
	// keeps this list the single source of truth for "which components
	// have a hand-written provider", matching
	// internal/contract/lint.go's componentsWithBespokeDecommissionProvider).
	for _, comp := range catalog.Components() {
		if _, bespoke := result[comp.ID]; bespoke {
			continue
		}
		if comp.Playbooks.Decommission == nil {
			continue
		}
		result[comp.ID] = providers.NewGenericComponentProvider(providers.GenericComponentProviderConfig{
			Executor:             runner,
			ComponentID:          comp.ID,
			Inventory:            invPath,
			DecommissionPlaybook: *comp.Playbooks.Decommission,
			StageArgs:            hostStage,
		})
	}

	return result, nil
}

// hostDecommissionLockRequest is the lock request of a decommission run: the
// workspace's generated inventory (dir's inventory.yml is the one
// buildHostDecommissionProviders generated), the default wait and the
// workspace's Ansible runtime (the decommission runner has its own). The lock of
// apply and resume (identityLockFor) and the warning of plan
// (precheckHostDecommissionIdentityLock) are both made from it, so they ask the
// same question.
func hostDecommissionLockRequest(dir string) (identityLockRequest, error) {
	runtime, err := prepareDeployAnsibleRuntime(resolvePilotDataDir())
	if err != nil {
		return identityLockRequest{}, fmt.Errorf("prepare ansible runtime for host decommission: %w", err)
	}
	return identityLockRequest{Inventory: filepath.Join(dir, "inventory.yml"), Wait: identityLockWaitDefault, Progress: os.Stderr, Runtime: &runtime}, nil
}

// planHasIdentityConverge reports whether a plan runs the central
// freeipa-identity-apply.yml converge step: the one step of a decommission that
// needs the FreeIPA server's /etc/ipa lock, and the reason the whole run holds it
// (runHostDecommissionApply).
func planHasIdentityConverge(plan *decommission.Plan) bool {
	for _, component := range plan.Components {
		for _, step := range component.Steps {
			if step.Provider == providers.FreeIPAClientProviderID && step.Action == providers.ActionFreeIPAIdentityApplyConverge {
				return true
			}
		}
	}
	return false
}

// precheckHostDecommissionIdentityLock is what `plan` asks (it takes no lock):
// whether apply and resume would refuse a plan with an identity converge step
// because the inventory its lock would be taken through cannot give it
// (checkIdentityLockTarget). A plan without that step is not asked. apply and
// resume make the same check through identityLockFor, in
// runHostDecommissionApply, and then take the lock.
func precheckHostDecommissionIdentityLock(ctx context.Context, dir string, plan *decommission.Plan) error {
	if !planHasIdentityConverge(plan) {
		return nil
	}
	req, err := hostDecommissionLockRequest(dir)
	if err != nil {
		return err
	}
	return checkIdentityLockTarget(ctx, req)
}

// warnIfDecommissionIsUnlockable tells the operator, after `plan`, that apply
// and resume will refuse a plan whose converge step needs a lock the
// inventory cannot give (precheckHostDecommissionIdentityLock). A blocked plan
// cannot be applied anyway and says nothing.
func warnIfDecommissionIsUnlockable(ctx context.Context, w io.Writer, dir string, plan *decommission.Plan) {
	if plan.Blocked() {
		return
	}
	if err := precheckHostDecommissionIdentityLock(ctx, dir, plan); err != nil {
		fmt.Fprintf(w, "⚠️  apply／resume 會拒絕這份計畫(它的 freeipa-identity 收斂步驟需要 FreeIPA server 的 /etc/ipa 鎖，而這份 inventory 取不到它；plan 不改動任何東西，所以只是警告)：%v\n", err)
	}
}

// hostDecommissionFreeIPAExtraArgs passes only FILE REFERENCES to Ansible;
// it never reads, serializes, or persists a secret value.  The workspace's
// conventional main vault is the authoritative source of ipa_admin_password.
// The canonical roster remains the source of identity declarations and is a
// compatibility fallback for older workspaces that still carry its duplicate
// freeipa.admin.password field.
func hostDecommissionFreeIPAExtraArgs(inventoryPath, rosterPath string) []string {
	var extraArgs []string
	if rosterPath == "" {
		return extraArgs
	}

	// Extra-vars go through a bare `-e k=v` here (not a @file), matching
	// FreeIPAClientProvider's own existing query()/exec() call sites, which
	// already only ever pass simple, space-free values. A roster path with
	// whitespace is a pre-existing workspace-authoring constraint.
	extraArgs = append(extraArgs, "-e", "freeipa_roster_file="+rosterPath)
	return append(extraArgs, hostDecommissionVaultArgs(inventoryPath)...)
}

// hostDecommissionVaultArgs references the workspace's main vault (the file
// `pilot deploy` passes, never its values) when it exists, for decommission
// steps that re-run an apply playbook whose gates read vault keys.
func hostDecommissionVaultArgs(inventoryPath string) []string {
	if vaultPath := defaultVaultFile(inventoryPath); vaultPath != "" {
		return []string{"-e", "@" + vaultPath}
	}
	return nil
}

func reportHostDecommissionResult(out io.Writer, result *decommission.FinalizeResult, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(out, "STATUS %s", result.Status)
		if result.Plan != nil {
			fmt.Fprintf(out, " plan=%s", result.Plan.ID)
		}
		fmt.Fprintln(out)
		for _, b := range result.Blockers {
			fmt.Fprintf(out, "  blocker: %s\n", b)
		}
		if result.Receipt != nil {
			fmt.Fprintf(out, "  receipt: decommission_id=%s host=%s completed_at=%s final_inventory_revision=%s\n",
				result.Receipt.DecommissionID, result.Receipt.Host, result.Receipt.CompletedAt, result.Receipt.FinalInventoryRevision)
		}
	}
	switch result.Status {
	case "completed", "already_completed":
		return nil
	default: // "blocked"
		return fmt.Errorf("decommission is blocked — see blockers above; workspace unchanged")
	}
}

// decommissionActor resolves the human operator identity recorded on an
// approval — $PILOT_ACTOR, else the OS user, else a generic fallback.
// Never a caller-suppliable "autonomous"/service identity (INV-4/HD5: no
// environment or actor value bypasses the human-approval gate).
func decommissionActor() string {
	if v := strings.TrimSpace(os.Getenv("PILOT_ACTOR")); v != "" {
		return v
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "operator"
}
