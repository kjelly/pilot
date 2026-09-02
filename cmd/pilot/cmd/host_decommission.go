// host_decommission.go implements `pilot host decommission plan` and
// `pilot host decommission show` — Phase 1 of
// docs/superpowers/specs/2026-09-02-host-decommission-spec.md. Only
// planning and inspection exist here: `apply`/`resume`/`verify` are a
// later phase (spec.md §37 Phase 2+), so this file deliberately does not
// add those subcommands yet — Phase 1's brief is explicit that no live
// delete exists yet.
//
// Style/flag conventions mirror internal_endpoint_cli.go: package-level
// flag vars, --dir/--json, cobra.NoArgs, errors returned rather than
// printed+swallowed.
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

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

func init() {
	hostDecommissionPlanCmd.Flags().StringVar(&hostDecommissionPlanDir, "dir", ".", "workspace directory containing hosts.yml")
	hostDecommissionPlanCmd.Flags().StringVar(&hostDecommissionPlanHost, "host", "", "host name to plan decommission for (required)")
	hostDecommissionPlanCmd.Flags().BoolVar(&hostDecommissionPlanJSON, "json", false, "print the plan as JSON")
	hostDecommissionCmd.AddCommand(hostDecommissionPlanCmd)

	hostDecommissionShowCmd.Flags().StringVar(&hostDecommissionShowID, "id", "", "plan id to show (required)")
	hostDecommissionShowCmd.Flags().BoolVar(&hostDecommissionShowJSON, "json", false, "print the plan as JSON")
	hostDecommissionCmd.AddCommand(hostDecommissionShowCmd)

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
