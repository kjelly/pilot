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
	hostDecommissionPlanCmd.Flags().StringArrayVar(&hostDecommissionPlanRetention, "retention", nil, "explicit retention disposition for a stateful component, repeatable: --retention <component-id>=<exported|migrated|retain_on_disk|destroy_authorized> (spec.md §20.1, INV-8)")
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

	provs, err := buildHostDecommissionProviders(dir, hostDecommissionPlanHost, catalog, cmd.ErrOrStderr())
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

	// The SAME provider registry `plan` used must be rebuilt here — the
	// freshness re-derivation inside Apply/Finalize re-runs PlanHost
	// against it, and a plan that was executable because a provider WAS
	// registered would otherwise stale-reject as soon as that provider
	// vanished from freshness's view (spec.md §28/INV-3).
	provs, err := buildHostDecommissionProviders(dir, plan.Host.Name, catalog, os.Stderr)
	if err != nil {
		return nil, err
	}

	return decommission.Apply(ctx, decommission.ApplyInput{
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
func buildHostDecommissionProviders(dir, hostName string, catalog contract.Catalog, out io.Writer) (map[string]providers.Provider, error) {
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

	rosterPath := decommission.RosterPathFor(dir, *host)

	runner := ansible.NewRunner()
	runner.StdoutWriter = out
	runner.StderrWriter = out

	var extraArgs []string
	if rosterPath != "" {
		// Extra-vars go through a bare `-e k=v` here (not a @file), matching
		// FreeIPAClientProvider's own existing query()/exec() call sites,
		// which already only ever pass simple, space-free values
		// (pilot_decommission_query, pilot_decommission_target_fqdn) this
		// same way — a roster path containing whitespace is a pre-existing
		// workspace-authoring assumption shared by every other caller of
		// this same freeipa_roster_file convention.
		extraArgs = append(extraArgs, "-e", "freeipa_roster_file="+rosterPath)
	}

	freeipaClient := providers.NewFreeIPAClientProvider(providers.FreeIPAClientProviderConfig{
		Executor:              runner,
		ClientInventory:       invPath,
		ServerInventory:       invPath,
		DecommissionPlaybook:  "playbooks/decommission/freeipa-client-decommission.yml",
		IdentityApplyPlaybook: "playbooks/apply/freeipa-identity-apply.yml",
		ExtraArgs:             extraArgs,
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
	})

	result := map[string]providers.Provider{
		providers.FreeIPAClientProviderID:    freeipaClient,
		providers.WazuhAgentProviderID:       wazuhAgent,
		providers.InternalEndpointProviderID: internalEndpoint,
		providers.FreeIPANFSServerProviderID: freeipaNFSServer,
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
		})
	}

	return result, nil
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
