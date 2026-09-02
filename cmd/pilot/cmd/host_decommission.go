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

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/decommission"
)

var (
	hostDecommissionPlanDir  string
	hostDecommissionPlanHost string
	hostDecommissionPlanJSON bool

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
	Short: "Plan and inspect host decommission (Phase 1: read-only plan/show — no live cleanup yet)",
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
	Short: "Apply a previously planned host decommission (spec.md §10.3). Phase 2: only a zero-blocker plan (e.g. a zero-role host) can execute — any unsupported live provider still blocks",
	Args:  cobra.NoArgs,
	RunE:  runHostDecommissionApplyCmd,
}

var hostDecommissionResumeCmd = &cobra.Command{
	Use:   "resume",
	Short: "Resume a host decommission after a failure/interruption (spec.md §10.4)",
	Args:  cobra.NoArgs,
	RunE:  runHostDecommissionResumeCmd,
}

func init() {
	hostDecommissionPlanCmd.Flags().StringVar(&hostDecommissionPlanDir, "dir", ".", "workspace directory containing hosts.yml")
	hostDecommissionPlanCmd.Flags().StringVar(&hostDecommissionPlanHost, "host", "", "host name to plan decommission for (required)")
	hostDecommissionPlanCmd.Flags().BoolVar(&hostDecommissionPlanJSON, "json", false, "print the plan as JSON")
	hostDecommissionCmd.AddCommand(hostDecommissionPlanCmd)

	hostDecommissionShowCmd.Flags().StringVar(&hostDecommissionShowID, "id", "", "plan id to show (required)")
	hostDecommissionShowCmd.Flags().BoolVar(&hostDecommissionShowJSON, "json", false, "print the plan as JSON")
	hostDecommissionCmd.AddCommand(hostDecommissionShowCmd)

	hostDecommissionApplyCmd.Flags().StringVar(&hostDecommissionApplyID, "id", "", "plan id to apply (required)")
	hostDecommissionApplyCmd.Flags().StringVar(&hostDecommissionApplyDir, "dir", ".", "workspace directory containing hosts.yml (must match the plan's workspace)")
	hostDecommissionApplyCmd.Flags().StringVar(&hostDecommissionApplyConfirmHost, "confirm-host", "", "exact host name being decommissioned — required, must match the plan's host exactly (spec.md §10.3 requirement 6; no generic --yes)")
	hostDecommissionApplyCmd.Flags().BoolVar(&hostDecommissionApplyJSON, "json", false, "print the result as JSON")
	hostDecommissionCmd.AddCommand(hostDecommissionApplyCmd)

	hostDecommissionResumeCmd.Flags().StringVar(&hostDecommissionResumeID, "id", "", "plan id to resume (required)")
	hostDecommissionResumeCmd.Flags().StringVar(&hostDecommissionResumeDir, "dir", ".", "workspace directory containing hosts.yml (must match the plan's workspace)")
	hostDecommissionResumeCmd.Flags().BoolVar(&hostDecommissionResumeJSON, "json", false, "print the result as JSON")
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

	plan, err := decommission.PlanHost(cmd.Context(), decommission.PlanInput{
		WorkspaceDir: dir,
		HostName:     hostDecommissionPlanHost,
		Catalog:      catalog,
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

	// Exit behavior per spec.md §10.1: a successful, unblocked plan is
	// success (nil); a valid-but-blocked plan is a non-zero structured
	// result — the plan has already been printed above, so this error
	// only drives the exit code, it does not hide anything from the
	// operator.
	if plan.Blocked() {
		return fmt.Errorf("plan %s is blocked — see blockers above; no host decommission mutation exists yet in this phase regardless", plan.ID)
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

	result, err := runHostDecommissionApply(cmd.Context(), ds, plan, dir, catalog, "apply via `pilot host decommission apply --confirm-host`")
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

	result, err := runHostDecommissionApply(cmd.Context(), ds, plan, dir, catalog, "resume via `pilot host decommission resume`")
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
// decommission.RequireApproval, then calls decommission.Finalize — all
// domain logic. Already-completed plans record no new approval (nothing
// left to confirm) and go straight to Finalize, which recognizes the
// replay and returns already_completed without touching approval state.
func runHostDecommissionApply(ctx context.Context, ds *decommission.Store, plan *decommission.Plan, dir string, catalog contract.Catalog, reason string) (*decommission.FinalizeResult, error) {
	now := time.Now().UTC()
	if plan.Status != decommission.PlanStatusCompleted {
		if err := ds.RecordApproval(plan.ID, plan.PlanHash, decommissionActor(), "approve", reason, now); err != nil {
			return nil, fmt.Errorf("record approval: %w", err)
		}
		if err := decommission.RequireApproval(ds, plan.ID, plan.PlanHash, plan.Environment); err != nil {
			return nil, err
		}
	}

	return decommission.Finalize(ctx, decommission.FinalizeInput{
		Plan: plan,
		PlanInputForFreshness: decommission.PlanInput{
			WorkspaceDir: dir, HostName: plan.Host.Name, Catalog: catalog,
		},
		DecommissionID: plan.ID,
		Reason:         reason,
		StartedAt:      now,
		Store:          ds,
	})
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
