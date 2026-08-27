// access_drift_cli.go implements spec.md v3.1 §12/§13's CLI surface:
// `pilot access drift` is a read-only comparison of desired vs live
// FreeIPA state (internal/accessgrants.DriftOnce — never mutates);
// `pilot access drift --repair-managed` additionally reconciles any
// drift found via the existing `pilot access reconcile` apply path
// (internal/accessgrants.RepairManaged), scoped to Pilot-owned managed
// constructs only (§13.1). See internal/accessgrants/drift.go's header
// comment for this delivery's drift-coverage scope.
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/accessgrants"
	"github.com/kjelly/pilot/internal/inventory"
)

var (
	accessDriftFormat            string
	accessDriftInventory         string
	accessDriftTargetGroup       string
	accessDriftVaultPasswordFile string
	accessDriftRepairManaged     bool
)

var accessDriftCmd = &cobra.Command{
	Use:   "drift <roster-file>",
	Short: "Compare desired vs live FreeIPA access-governance state",
	Long: `pilot access drift probes live FreeIPA state and compares it
against the roster's desired compiled state. It runs once and exits — no
recurring loop is introduced (spec.md v3.1 §12).

Coverage in this delivery: existence/orphan drift for compiled login/sudo
grant rules, and native-attribute value drift for account_policies'
principal expiration and auth_policies' authentication indicators. Full
subject/target/service attribute drift for HBAC/sudo rules is not covered
— see internal/accessgrants/drift.go.

--repair-managed additionally reconciles any drift found, via the same
apply path 'pilot access reconcile --once' uses (§13) — it never touches
anything outside Pilot's own managed namespace.`,
	Args: cobra.ExactArgs(1),
	RunE: runAccessDriftCmd,
}

func init() {
	accessDriftCmd.Flags().StringVar(&accessDriftFormat, "format", "table", "output format: table|json")
	accessDriftCmd.Flags().StringVarP(&accessDriftInventory, "inventory", "i", "inventory.yml", "inventory to probe live state against")
	accessDriftCmd.Flags().StringVar(&accessDriftTargetGroup, "target-group", "", "override the probe playbook's default host-targeting group")
	accessDriftCmd.Flags().StringVar(&accessDriftVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")
	accessDriftCmd.Flags().BoolVar(&accessDriftRepairManaged, "repair-managed", false, "explicitly repair any drift found (Pilot-owned managed constructs only)")
	accessCmd.AddCommand(accessDriftCmd)
}

func runAccessDriftCmd(cmd *cobra.Command, args []string) error {
	path := args[0]
	readPath, cleanup, err := resolveGrantsReadPath(path, accessDriftVaultPasswordFile)
	if err != nil {
		return err
	}
	defer cleanup()

	if accessDriftFormat != "table" && accessDriftFormat != "json" {
		return fmt.Errorf("--format must be table or json, got %q", accessDriftFormat)
	}

	violations, err := inventory.ValidateRosterFile(readPath)
	if err != nil {
		return err
	}
	if len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintln(cmd.OutOrStdout(), v.String())
		}
		return fmt.Errorf("%d roster issue(s) found; fix them before checking drift", len(violations))
	}

	driftOpts := accessgrants.DriftProbeOptions{
		RosterFile:        readPath,
		Inventory:         accessDriftInventory,
		TargetGroup:       accessDriftTargetGroup,
		VaultPasswordFile: accessDriftVaultPasswordFile,
		StateDir:          resolveDataDir(),
		Now:               time.Now(),
	}

	out := cmd.OutOrStdout()

	if !accessDriftRepairManaged {
		report, err := accessgrants.DriftOnce(cmd.Context(), driftOpts)
		if err != nil {
			return err
		}
		return printDriftReport(out, report)
	}

	before, plan, result, err := accessgrants.RepairManaged(cmd.Context(), driftOpts, accessgrants.ReconcileOptions{
		RosterFile: readPath,
		Inventory:  accessDriftInventory,
		StateDir:   resolveDataDir(),
		Now:        time.Now(),
	})
	if perr := printDriftReport(out, before); perr != nil {
		return perr
	}
	if before.Empty() {
		fmt.Fprintln(out, "no drift found; nothing to repair")
		return nil
	}
	fmt.Fprintf(out, "repaired via reconcile: %d hbac rule(s), %d sudo rule(s), %d account expiration(s)\n", len(plan.HBACRules), len(plan.SudoRules), len(plan.AccountExpirations))
	if result != nil {
		fmt.Fprint(out, result.Stdout)
	}
	return err
}

func printDriftReport(out io.Writer, report accessgrants.DriftReport) error {
	if accessDriftFormat == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	if accessDriftFormat != "table" {
		return fmt.Errorf("--format must be table or json, got %q", accessDriftFormat)
	}
	if report.Empty() {
		fmt.Fprintln(out, "no drift found")
		return nil
	}
	for _, item := range report.Items {
		fmt.Fprintf(out, "%s\tname=%s\tdetail=%s\n", item.Category, item.Name, item.Detail)
	}
	return nil
}
