// access_breakglass_cli.go implements `pilot access breakglass
// activate/deactivate/status` (spec.md §14, Phase 3). Like
// `access_cli.go`'s status/reconcile, roster-file and --inventory are
// explicit positional/flag arguments here too — spec.md's own CLI
// examples for this area are illustrative shorthand, not complete
// signatures (its `pilot access reconcile --once` example likewise omits
// the roster-file argument access_cli.go's actual RunE requires).
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/accessgrants"
	"github.com/kjelly/pilot/internal/inventory"
)

var (
	accessBreakglassActivateInventory         string
	accessBreakglassActivateDuration          string
	accessBreakglassActivateReason            string
	accessBreakglassActivateTicket            string
	accessBreakglassActivatePlaybook          string
	accessBreakglassActivateVaultPasswordFile string

	accessBreakglassDeactivateInventory         string
	accessBreakglassDeactivatePlaybook          string
	accessBreakglassDeactivateVaultPasswordFile string

	accessBreakglassStatusFormat string
)

var accessBreakglassCmd = &cobra.Command{
	Use:   "breakglass",
	Short: "Activate, deactivate, and inspect break-glass grants",
}

var accessBreakglassActivateCmd = &cobra.Command{
	Use:   "activate <roster-file> <name>",
	Short: "Activate a kind: breakglass grant's definition for a bounded duration",
	Long: `pilot access breakglass activate creates a time-bounded managed
HBAC rule from a kind: breakglass grant's definition — the same compiler
and naming convention a temporary_grant uses (spec.md §9/§14) — and
records the activation (who/why/until-when) in local state. It never
rewrites the roster's grant definition and never creates an access-*
group.

--duration MUST NOT exceed the grant's own activation.max_duration;
--reason/--ticket are required unless the grant's activation explicitly
sets require_reason/require_ticket to false.`,
	Args: cobra.ExactArgs(2),
	RunE: runAccessBreakglassActivateCmd,
}

var accessBreakglassDeactivateCmd = &cobra.Command{
	Use:   "deactivate <roster-file> <name>",
	Short: "End a breakglass grant's active authorization early",
	Args:  cobra.ExactArgs(2),
	RunE:  runAccessBreakglassDeactivateCmd,
}

var accessBreakglassStatusCmd = &cobra.Command{
	Use:   "status [name]",
	Short: "Show breakglass activation history (most recent first)",
	Long:  "Without [name], shows every recorded activation across all breakglass grants.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runAccessBreakglassStatusCmd,
}

func init() {
	accessBreakglassActivateCmd.Flags().StringVarP(&accessBreakglassActivateInventory, "inventory", "i", "inventory.yml", "inventory to apply the activated rule against")
	accessBreakglassActivateCmd.Flags().StringVar(&accessBreakglassActivateDuration, "duration", "", "activation duration (e.g. 45m, 1h) — required, must not exceed the grant's activation.max_duration")
	accessBreakglassActivateCmd.Flags().StringVar(&accessBreakglassActivateReason, "reason", "", "reason for this activation")
	accessBreakglassActivateCmd.Flags().StringVar(&accessBreakglassActivateTicket, "ticket", "", "ticket reference for this activation")
	accessBreakglassActivateCmd.Flags().StringVar(&accessBreakglassActivatePlaybook, "playbook", accessgrants.DefaultPlaybook, "apply playbook to invoke")
	accessBreakglassActivateCmd.Flags().StringVar(&accessBreakglassActivateVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")

	accessBreakglassDeactivateCmd.Flags().StringVarP(&accessBreakglassDeactivateInventory, "inventory", "i", "inventory.yml", "inventory to apply the deactivation against")
	accessBreakglassDeactivateCmd.Flags().StringVar(&accessBreakglassDeactivatePlaybook, "playbook", accessgrants.DefaultPlaybook, "apply playbook to invoke")
	accessBreakglassDeactivateCmd.Flags().StringVar(&accessBreakglassDeactivateVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")

	accessBreakglassStatusCmd.Flags().StringVar(&accessBreakglassStatusFormat, "format", "table", "output format: table|json")

	accessBreakglassCmd.AddCommand(accessBreakglassActivateCmd)
	accessBreakglassCmd.AddCommand(accessBreakglassDeactivateCmd)
	accessBreakglassCmd.AddCommand(accessBreakglassStatusCmd)
	accessCmd.AddCommand(accessBreakglassCmd)
}

// activatedByCurrentUser stamps who ran the activation, for the audit
// trail Status reports — best-effort: an unresolvable username still
// activates the grant, just with an empty ActivatedBy.
func activatedByCurrentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return os.Getenv("USERNAME") // Windows fallback; harmless elsewhere
}

func runAccessBreakglassActivateCmd(cmd *cobra.Command, args []string) error {
	rosterPath, name := args[0], args[1]
	readPath, cleanup, err := resolveGrantsReadPath(rosterPath, accessBreakglassActivateVaultPasswordFile)
	if err != nil {
		return err
	}
	defer cleanup()

	violations, err := inventory.ValidateRosterFile(readPath)
	if err != nil {
		return err
	}
	if len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintln(cmd.OutOrStdout(), v.String())
		}
		return fmt.Errorf("%d roster issue(s) found; fix them before activating a breakglass grant", len(violations))
	}

	if accessBreakglassActivateDuration == "" {
		return fmt.Errorf("--duration is required")
	}
	duration, err := inventory.ParseAccessDuration(accessBreakglassActivateDuration)
	if err != nil {
		return err
	}

	activation, err := accessgrants.Activate(cmd.Context(), accessgrants.ActivateOptions{
		RosterFile:        readPath,
		Inventory:         accessBreakglassActivateInventory,
		StateDir:          resolveDataDir(),
		Name:              name,
		Duration:          duration,
		Reason:            accessBreakglassActivateReason,
		Ticket:            accessBreakglassActivateTicket,
		ActivatedBy:       activatedByCurrentUser(),
		Playbook:          accessBreakglassActivatePlaybook,
		VaultPasswordFile: accessBreakglassActivateVaultPasswordFile,
		Now:               time.Now(),
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "activated %q, expires at %s\n", name, activation.ExpiresAt.Format(time.RFC3339))
	return nil
}

func runAccessBreakglassDeactivateCmd(cmd *cobra.Command, args []string) error {
	rosterPath, name := args[0], args[1]
	readPath, cleanup, err := resolveGrantsReadPath(rosterPath, accessBreakglassDeactivateVaultPasswordFile)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := accessgrants.Deactivate(cmd.Context(), accessgrants.DeactivateOptions{
		RosterFile:        readPath,
		Inventory:         accessBreakglassDeactivateInventory,
		StateDir:          resolveDataDir(),
		Name:              name,
		Playbook:          accessBreakglassDeactivatePlaybook,
		VaultPasswordFile: accessBreakglassDeactivateVaultPasswordFile,
		Now:               time.Now(),
	}); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "deactivated %q\n", name)
	return nil
}

func runAccessBreakglassStatusCmd(cmd *cobra.Command, args []string) error {
	name := ""
	if len(args) == 1 {
		name = args[0]
	}
	activations, err := accessgrants.Status(resolveDataDir(), name)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if accessBreakglassStatusFormat == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(activations)
	}
	if accessBreakglassStatusFormat != "table" {
		return fmt.Errorf("--format must be table or json, got %q", accessBreakglassStatusFormat)
	}
	if len(activations) == 0 {
		fmt.Fprintln(out, "no activations recorded")
		return nil
	}
	now := time.Now()
	for _, a := range activations {
		state := "inactive"
		if a.IsActive(now) {
			state = "active"
		}
		fmt.Fprintf(out, "%s\tstate=%s\tactivated_at=%s\texpires_at=%s\tactivated_by=%s\treason=%q\tticket=%s\n",
			a.Name, state, a.ActivatedAt.Format(time.RFC3339), a.ExpiresAt.Format(time.RFC3339), a.ActivatedBy, a.Reason, a.Ticket)
	}
	return nil
}
