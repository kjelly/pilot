// access_health_cli.go implements spec.md v3.1 §16's CLI surface:
// `pilot access health` runs once, aggregates drift/grant/breakglass
// state (internal/accessgrants.EvaluateHealth), and exits — it does not
// monitor continuously.
package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/accessgrants"
	"github.com/kjelly/pilot/internal/inventory"
)

var (
	accessHealthFormat            string
	accessHealthInventory         string
	accessHealthTargetGroup       string
	accessHealthVaultPasswordFile string
)

var accessHealthCmd = &cobra.Command{
	Use:   "health <roster-file>",
	Short: "One-shot access-governance health summary",
	Long: `pilot access health evaluates drift, breakglass, and reconcile-
required grant state once and reports a single healthy/degraded/critical/
unknown status (spec.md v3.1 §16). It does not monitor continuously —
there is no scheduler behind this command.`,
	Args: cobra.ExactArgs(1),
	RunE: runAccessHealthCmd,
}

func init() {
	accessHealthCmd.Flags().StringVar(&accessHealthFormat, "format", "table", "output format: table|json")
	accessHealthCmd.Flags().StringVarP(&accessHealthInventory, "inventory", "i", "inventory.yml", "inventory to probe live state against")
	accessHealthCmd.Flags().StringVar(&accessHealthTargetGroup, "target-group", "", "override the probe playbook's default host-targeting group")
	accessHealthCmd.Flags().StringVar(&accessHealthVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")
	accessCmd.AddCommand(accessHealthCmd)
}

func runAccessHealthCmd(cmd *cobra.Command, args []string) error {
	path := args[0]
	readPath, cleanup, err := resolveGrantsReadPath(path, accessHealthVaultPasswordFile)
	if err != nil {
		return err
	}
	defer cleanup()

	if accessHealthFormat != "table" && accessHealthFormat != "json" {
		return fmt.Errorf("--format must be table or json, got %q", accessHealthFormat)
	}

	violations, err := inventory.ValidateRosterFile(readPath)
	if err != nil {
		return err
	}
	if len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintln(cmd.OutOrStdout(), v.String())
		}
		return fmt.Errorf("%d roster issue(s) found; fix them before checking health", len(violations))
	}

	health, err := accessgrants.EvaluateHealth(cmd.Context(), accessgrants.HealthOptions{
		DriftProbeOptions: accessgrants.DriftProbeOptions{
			RosterFile:        readPath,
			Inventory:         accessHealthInventory,
			TargetGroup:       accessHealthTargetGroup,
			VaultPasswordFile: accessHealthVaultPasswordFile,
			Now:               time.Now(),
		},
		StateDir: resolveDataDir(),
	})
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if accessHealthFormat == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(health)
	}
	if accessHealthFormat != "table" {
		return fmt.Errorf("--format must be table or json, got %q", accessHealthFormat)
	}

	fmt.Fprintf(out, "status=%s\n", health.Status)
	fmt.Fprintf(out, "evaluated_at=%s\n", health.EvaluatedAt.Format(time.RFC3339))
	fmt.Fprintf(out, "freeipa_reachable=%v\n", health.FreeIPAReachable)
	fmt.Fprintf(out, "compiled_grant_hbac_drift_count=%d\n", health.CompiledGrantHBACDriftCount)
	fmt.Fprintf(out, "sudo_drift_count=%d\n", health.SudoDriftCount)
	fmt.Fprintf(out, "auth_policy_drift_count=%d\n", health.AuthPolicyDriftCount)
	fmt.Fprintf(out, "account_expiration_drift_count=%d\n", health.AccountExpirationDriftCount)
	fmt.Fprintf(out, "static_hbac_drift_count=%d (not computed in this delivery)\n", health.StaticHBACDriftCount)
	fmt.Fprintf(out, "review_overdue_count=%d (not implemented in this delivery)\n", health.ReviewOverdueCount)
	fmt.Fprintf(out, "active_breakglass_count=%d\n", health.ActiveBreakglassCount)
	fmt.Fprintf(out, "reconcile_required_temporary_grant_count=%d\n", health.ReconcileRequiredTemporaryGrantCount)
	return nil
}
