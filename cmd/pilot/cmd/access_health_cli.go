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
	accessHealthVarsFile          string
)

var accessHealthCmd = &cobra.Command{
	Use:   "health <roster-file>",
	Short: "One-shot access-governance health summary",
	Long: `pilot access health evaluates drift, breakglass, and reconcile-
required grant state once and reports a single healthy/degraded/critical/
unknown status (spec.md v3.1 §16). It does not monitor continuously —
there is no scheduler behind this command. A probe that cannot run is reported
as status unknown, with probe_error saying why.

The probe reads the FreeIPA admin password from the vault vars file's
ipa_admin_password first (the same order 'pilot deploy' uses), then from the
roster's freeipa.admin.password. The vars file is --vars-file, or by default
<inventory dir>/.vault/main.yaml when it exists; it is only handed to
ansible-playbook as a file, never read by pilot. --vault-password-file decrypts
both an encrypted roster and an encrypted vars file, so they must share one
vault password. An explicit --vars-file that is missing, a directory, or
encrypted without --vault-password-file is an error; the auto-detected default
that is encrypted without --vault-password-file is skipped with a note on
stderr, and the roster's password is used. The vars file is loaded whole, so
a freeipa_domain/freeipa_realm in it also sets the probe's realm (as in apply).`,
	Args: cobra.ExactArgs(1),
	RunE: runAccessHealthCmd,
}

func init() {
	accessHealthCmd.Flags().StringVar(&accessHealthFormat, "format", "table", "output format: table|json")
	accessHealthCmd.Flags().StringVarP(&accessHealthInventory, "inventory", "i", "inventory.yml", "inventory to probe live state against")
	accessHealthCmd.Flags().StringVar(&accessHealthTargetGroup, "target-group", "", "override the probe playbook's default host-targeting group")
	accessHealthCmd.Flags().StringVar(&accessHealthVaultPasswordFile, "vault-password-file", "", driftVaultPasswordFlagHelp)
	accessHealthCmd.Flags().StringVar(&accessHealthVarsFile, "vars-file", "", driftVarsFileFlagHelp)
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

	varsFile, err := resolveDriftVarsFile(cmd.ErrOrStderr(), accessHealthInventory, accessHealthVarsFile, accessHealthVaultPasswordFile)
	if err != nil {
		return err
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
			VarsFile:          varsFile,
			Now:               time.Now(),
		},
		StateDir: resolveStateDir(accessStateFiles...),
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
	if health.ProbeError != "" {
		fmt.Fprintf(out, "probe_error=%s\n", health.ProbeError)
	}
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
