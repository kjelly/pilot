// identity_hygiene_cli.go implements `pilot identity hygiene` — spec.md
// v3.2 §14's one-shot, read-only per-user compliance report. It never
// mutates the roster or FreeIPA (internal/accessgrants.EvaluateIdentityHygiene).
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
	identityHygieneFormat            string
	identityHygieneInventory         string
	identityHygieneTargetGroup       string
	identityHygieneVaultPasswordFile string
)

var identityHygieneCmd = &cobra.Command{
	Use:   "hygiene <roster-file>",
	Short: "One-shot identity hygiene report (read-only)",
	Long: `pilot identity hygiene reports, per user: whether they are
effectively privileged (security.privileged_identity), whether their
authentication.allowed meets the configured strong-auth baseline,
whether their SSH keys pass any covering credential_policy's hygiene
rules, and their credential review status. It also reports FreeIPA
capability support (when --inventory is given) and every underlying
finding.

Hygiene never mutates the roster or FreeIPA (spec.md v3.2 §14) — it runs
once and exits.`,
	Args: cobra.ExactArgs(1),
	RunE: runIdentityHygieneCmd,
}

func init() {
	identityHygieneCmd.Flags().StringVar(&identityHygieneFormat, "format", "table", "output format: table|json")
	identityHygieneCmd.Flags().StringVarP(&identityHygieneInventory, "inventory", "i", "", "inventory to probe FreeIPA capabilities against (omit to skip the live capability probe)")
	identityHygieneCmd.Flags().StringVar(&identityHygieneTargetGroup, "target-group", "", "override the probe playbook's default host-targeting group")
	identityHygieneCmd.Flags().StringVar(&identityHygieneVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")
	identityCmd.AddCommand(identityHygieneCmd)
}

func runIdentityHygieneCmd(cmd *cobra.Command, args []string) error {
	path := args[0]
	readPath, cleanup, err := resolveGrantsReadPath(path, identityHygieneVaultPasswordFile)
	if err != nil {
		return err
	}
	defer cleanup()

	if identityHygieneFormat != "table" && identityHygieneFormat != "json" {
		return fmt.Errorf("--format must be table or json, got %q", identityHygieneFormat)
	}

	violations, err := inventory.ValidateRosterFile(readPath)
	if err != nil {
		return err
	}
	if len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintln(cmd.OutOrStdout(), v.String())
		}
		return fmt.Errorf("%d roster issue(s) found; fix them before running hygiene", len(violations))
	}

	report, err := accessgrants.EvaluateIdentityHygiene(cmd.Context(), accessgrants.HygieneOptions{
		RosterFile:        readPath,
		Inventory:         identityHygieneInventory,
		TargetGroup:       identityHygieneTargetGroup,
		VaultPasswordFile: identityHygieneVaultPasswordFile,
		StateDir:          resolveDataDir(),
		Now:               time.Now(),
	})
	if err != nil {
		return err
	}
	return printHygieneReport(cmd.OutOrStdout(), report)
}

func printHygieneReport(out io.Writer, report accessgrants.HygieneReport) error {
	if identityHygieneFormat == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Fprintf(out, "evaluated_at\t%s\n", report.EvaluatedAt.Format(time.RFC3339))
	fmt.Fprintf(out, "stale_account_status\t%s\n", report.StaleAccountStatus)
	if report.CapabilityError != "" {
		fmt.Fprintf(out, "capability_probe_error\t%s\n", report.CapabilityError)
	}
	fmt.Fprintln(out, "user\tprivileged\tauth_compliance\tssh_key_compliance\tcredential_review")
	for _, u := range report.Users {
		fmt.Fprintf(out, "%s\t%t\t%s\t%s\t%s\n", u.Name, u.Privileged, u.AuthCompliance, u.SSHKeyCompliance, u.CredentialReview)
	}
	if len(report.SSHFindings) > 0 {
		fmt.Fprintln(out, "\nssh findings:")
		for _, f := range report.SSHFindings {
			fmt.Fprintf(out, "  policy=%s user=%s issue=%s detail=%s\n", f.PolicyName, f.User, f.Issue, f.Detail)
		}
	}
	if len(report.PrivilegedIdentityViolations) > 0 {
		fmt.Fprintln(out, "\nprivileged identity violations:")
		for _, v := range report.PrivilegedIdentityViolations {
			fmt.Fprintf(out, "  user=%s %s\n", v.User, v.Detail)
		}
	}
	return nil
}
