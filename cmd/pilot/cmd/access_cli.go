// access_cli.go implements the v3.0 Core Access Governance spec's Phase 1
// CLI surface (spec.md §9/§18 step 9): `pilot access status` is a
// pure, read-only report of every grant's current lifecycle state and
// next transition (internal/inventory's injected-clock evaluator, no
// ansible/FreeIPA call at all); `pilot access reconcile --once` compiles
// temporary_grant/sudo_grant entries into managed FreeIPA rules
// (internal/accessgrants) and applies them via one ansible-playbook run.
//
// Grant kind: breakglass is deliberately out of scope for both commands —
// it has no validity-driven lifecycle and never compiles through this
// path (spec.md §6.3/§14, Phase 3).
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
	accessStatusFormat            string
	accessStatusVaultPasswordFile string

	accessReconcileOnce              bool
	accessReconcileInventory         string
	accessReconcilePlaybook          string
	accessReconcileVaultPasswordFile string
)

var accessCmd = &cobra.Command{
	Use:   "access",
	Short: "Inspect and reconcile v3.0 access-governance grants",
}

var accessStatusCmd = &cobra.Command{
	Use:   "status <roster-file>",
	Short: "Show each grant's current lifecycle state and next transition",
	Long: `pilot access status evaluates every grants[] entry's lifecycle
(pending/active/expired/absent) against the real clock and reports it,
without touching FreeIPA at all. kind: breakglass entries are listed with
an empty lifecycle — a breakglass definition has no validity window; its
actual granting/not-granting state is separate runtime activation state
(spec.md §14), not something this command reports.`,
	Args: cobra.ExactArgs(1),
	RunE: runAccessStatusCmd,
}

var accessReconcileCmd = &cobra.Command{
	Use:   "reconcile <roster-file>",
	Short: "Compile temporary_grant/sudo_grant entries into managed FreeIPA rules and apply them",
	Long: `pilot access reconcile compiles every temporary_grant into a
managed HBAC rule and every sudo_grant into a managed sudo rule with
native sudoNotBefore/sudoNotAfter attributes (spec.md §9/§10), then
applies the result via one ansible-playbook run against
playbooks/apply/freeipa-identity-apply.yml.

--once is required: it is currently the only supported mode (a standing
reconcile daemon/loop is not part of this delivery) — passing it makes
that explicit rather than implying a continuous mode that doesn't exist.`,
	Args: cobra.ExactArgs(1),
	RunE: runAccessReconcileCmd,
}

func init() {
	accessStatusCmd.Flags().StringVar(&accessStatusFormat, "format", "table", "output format: table|json")
	accessStatusCmd.Flags().StringVar(&accessStatusVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")

	accessReconcileCmd.Flags().BoolVar(&accessReconcileOnce, "once", false, "run a single reconcile pass and exit (required — the only supported mode)")
	accessReconcileCmd.Flags().StringVarP(&accessReconcileInventory, "inventory", "i", "inventory.yml", "inventory to apply the compiled rules against")
	accessReconcileCmd.Flags().StringVar(&accessReconcilePlaybook, "playbook", accessgrants.DefaultPlaybook, "apply playbook to invoke")
	accessReconcileCmd.Flags().StringVar(&accessReconcileVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")

	accessCmd.AddCommand(accessStatusCmd)
	accessCmd.AddCommand(accessReconcileCmd)
	rootCmd.AddCommand(accessCmd)
}

func runAccessStatusCmd(cmd *cobra.Command, args []string) error {
	path := args[0]
	readPath, cleanup, err := resolveGrantsReadPath(path, accessStatusVaultPasswordFile)
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
		return fmt.Errorf("%d roster issue(s) found; fix them before checking grant status", len(violations))
	}

	statuses, err := inventory.EvaluateGrantStatusesFile(readPath, time.Now())
	if err != nil {
		return err
	}
	accountStatuses, err := inventory.EvaluateAccountPolicyStatusesFile(readPath, time.Now())
	if err != nil {
		return err
	}

	if accessStatusFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Grants          []inventory.GrantStatus         `json:"grants"`
			AccountPolicies []inventory.AccountPolicyStatus `json:"account_policies"`
		}{Grants: statuses, AccountPolicies: accountStatuses})
	}
	if accessStatusFormat != "table" {
		return fmt.Errorf("--format must be table or json, got %q", accessStatusFormat)
	}

	out := cmd.OutOrStdout()
	if len(statuses) == 0 {
		fmt.Fprintln(out, "no grants defined")
	}
	for _, s := range statuses {
		next := "n/a"
		if s.NextTransition != nil {
			next = s.NextTransition.Format(time.RFC3339)
		}
		lifecycle := string(s.Lifecycle)
		if lifecycle == "" {
			lifecycle = "n/a (breakglass has no validity-driven lifecycle)"
		}
		fmt.Fprintf(out, "%s\tkind=%s\tstate=%s\tlifecycle=%s\tnext_transition_at=%s", s.Name, s.Kind, s.State, lifecycle, next)
		if s.Kind == "sudo_grant" && s.State != "absent" {
			fmt.Fprintf(out, "\tnative_enforced=[%s,%s)", orNA(s.NativeSudoNotBefore), orNA(s.NativeSudoNotAfter))
		} else if s.Kind == "temporary_grant" && s.State != "absent" {
			fmt.Fprint(out, "\ttiming_enforcement=reconcile_required")
		}
		fmt.Fprintln(out)
	}
	for _, s := range accountStatuses {
		next := "n/a"
		if s.NextTransition != nil {
			next = s.NextTransition.Format(time.RFC3339)
		}
		nativeExpiration := s.NativeExpiration
		if nativeExpiration == "" {
			nativeExpiration = "n/a (cleared or no present entry)"
		}
		fmt.Fprintf(out, "%s\tuser=%s\tstate=%s\tlifecycle=%s\tnext_transition_at=%s\tnative_expiration=%s\n", s.Name, s.User, s.State, s.Lifecycle, next, nativeExpiration)
	}
	return nil
}

func runAccessReconcileCmd(cmd *cobra.Command, args []string) error {
	if !accessReconcileOnce {
		return fmt.Errorf("pilot access reconcile requires --once (the only supported mode)")
	}
	path := args[0]
	readPath, cleanup, err := resolveGrantsReadPath(path, accessReconcileVaultPasswordFile)
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
		return fmt.Errorf("%d roster issue(s) found; fix them before reconciling grants", len(violations))
	}

	// readPath (not the original, possibly-encrypted path) is what the
	// apply playbook's own include_vars reads — Go already holds the
	// decrypted content in hand, so there is no need for the playbook to
	// decrypt it again (same convention internal/freeipa's probes use).
	plan, result, err := accessgrants.ReconcileOnce(cmd.Context(), accessgrants.ReconcileOptions{
		RosterFile: readPath,
		Inventory:  accessReconcileInventory,
		Playbook:   accessReconcilePlaybook,
		StateDir:   resolveDataDir(),
		Now:        time.Now(),
	})
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "compiled %d hbac rule(s), %d sudo rule(s), %d account expiration(s)\n", len(plan.HBACRules), len(plan.SudoRules), len(plan.AccountExpirations))
	if result != nil {
		fmt.Fprint(out, result.Stdout)
	}
	return err
}

// orNA returns s, or "n/a" for an empty string — used for table-output
// fields that are legitimately unset (e.g. an omitted sudo not_before).
func orNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

// resolveGrantsReadPath returns a plaintext path to read grants from: path
// unchanged when it's already plaintext, otherwise a decrypted temp copy
// (caller MUST call the returned cleanup) — mirroring
// roster_remove_user.go's identical encrypted-roster handling
// (isRosterFileEncrypted, inventory.DecryptRosterToTempFile).
func resolveGrantsReadPath(path, vaultPasswordFile string) (readPath string, cleanup func(), err error) {
	encrypted, err := isRosterFileEncrypted(path)
	if err != nil {
		return "", func() {}, err
	}
	if !encrypted {
		return path, func() {}, nil
	}
	if vaultPasswordFile == "" {
		return "", func() {}, fmt.Errorf("%s is ansible-vault encrypted; pass --vault-password-file", path)
	}
	return inventory.DecryptRosterToTempFile(path, vaultPasswordFile)
}
