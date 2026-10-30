// identity_drift_cli.go implements `pilot identity drift` — spec.md v3.2
// §15's one-shot drift inspection/repair entry point. It is a thin
// wrapper around the same internal/accessgrants.DriftOnce/RepairManaged
// machinery `pilot access drift` already uses (drift.go's ComputeDrift
// now covers v3.2's password_policy/user_auth_type axes alongside v3.0/
// v3.1's grants/auth_policies/account_policies ones) — spec.md's own
// "reuse one canonical ... mechanism where possible" posture, not a
// second drift engine.
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
	identityDriftFormat            string
	identityDriftInventory         string
	identityDriftTargetGroup       string
	identityDriftVaultPasswordFile string
	identityDriftVarsFile          string
	identityDriftRepairManaged     bool
	identityDriftIncludeObjects    bool
	identityDriftExitCode          bool
)

var identityDriftCmd = &cobra.Command{
	Use:   "drift <roster-file>",
	Short: "Compare desired vs live FreeIPA identity-hardening state",
	Long: `pilot identity drift probes live FreeIPA state and compares it
against the roster's desired compiled state for every axis this delivery
covers: HBAC/sudo grants, auth_policies indicators, account_policies
expiration, password_policies, and per-user authentication types. It runs
once and exits — no recurring loop (spec.md v3.2 §1).

--include-users-groups enables the staged object observer using apply's shared
normalization: create/delete, enabled state, attributes, SSH key counts and direct
group memberships. Extra members of additive groups and objects outside the
roster are report-only. The JSON schema is version 1, with sorted items and
explicit covered/uncovered lists. Coverage remains partial while rule attachments,
host objects and password actions are pending; an empty report is not full parity.
--exit-code returns 2 for actionable drift, 3 for partial coverage or report-only
differences, and 1 on failure. Zero is reserved for fully covered clean state.

--repair-managed additionally reconciles any drift found via the same
apply path 'pilot access reconcile' uses — it only ever touches
Pilot-owned managed constructs (spec.md §13.1's ownership boundary),
never a hand-authored roster entry it doesn't compile itself. The repair step
itself still reads the admin password from the roster only.

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
	RunE: runIdentityDriftCmd,
}

func init() {
	identityDriftCmd.Flags().StringVar(&identityDriftFormat, "format", "table", "output format: table|json")
	identityDriftCmd.Flags().StringVarP(&identityDriftInventory, "inventory", "i", "inventory.yml", "inventory to probe live state against")
	identityDriftCmd.Flags().StringVar(&identityDriftTargetGroup, "target-group", "", "override the probe playbook's default host-targeting group")
	identityDriftCmd.Flags().StringVar(&identityDriftVaultPasswordFile, "vault-password-file", "", driftVaultPasswordFlagHelp)
	identityDriftCmd.Flags().StringVar(&identityDriftVarsFile, "vars-file", "", driftVarsFileFlagHelp)
	identityDriftCmd.Flags().BoolVar(&identityDriftRepairManaged, "repair-managed", false, "explicitly repair any drift found (Pilot-owned managed constructs only)")
	identityDriftCmd.Flags().BoolVar(&identityDriftIncludeObjects, "include-users-groups", false, "include staged users/groups observer (requires FreeIPA Python client on target)")
	identityDriftCmd.Flags().BoolVar(&identityDriftExitCode, "exit-code", false, "CI status: 0 fully clean, 1 error, 2 actionable drift, 3 partial coverage/report-only")
	identityCmd.AddCommand(identityDriftCmd)
}

func runIdentityDriftCmd(cmd *cobra.Command, args []string) error {
	if identityDriftRepairManaged && (identityDriftIncludeObjects || identityDriftExitCode || identityDriftFormat == "json") {
		return fmt.Errorf("--repair-managed cannot be combined with --include-users-groups, --exit-code or --format json; inspect and apply separately")
	}
	path := args[0]
	readPath, cleanup, err := resolveGrantsReadPath(path, identityDriftVaultPasswordFile)
	if err != nil {
		return err
	}
	defer cleanup()

	if identityDriftFormat != "table" && identityDriftFormat != "json" {
		return fmt.Errorf("--format must be table or json, got %q", identityDriftFormat)
	}

	varsFile, err := resolveDriftVarsFile(cmd.ErrOrStderr(), identityDriftInventory, identityDriftVarsFile, identityDriftVaultPasswordFile)
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
		return fmt.Errorf("%d roster issue(s) found; fix them before checking drift", len(violations))
	}

	driftOpts := accessgrants.DriftProbeOptions{
		IncludeIdentityObjects: identityDriftIncludeObjects,
		RosterFile:             readPath,
		Inventory:              identityDriftInventory,
		TargetGroup:            identityDriftTargetGroup,
		VaultPasswordFile:      identityDriftVaultPasswordFile,
		VarsFile:               varsFile,
		StateDir:               resolveStateDir(accessStateFiles...),
		Now:                    time.Now(),
	}

	out := cmd.OutOrStdout()

	if !identityDriftRepairManaged {
		report, err := accessgrants.DriftOnce(cmd.Context(), driftOpts)
		if err != nil {
			return err
		}
		if err := printIdentityDriftReport(out, report); err != nil {
			return err
		}
		if identityDriftExitCode {
			return identityDriftStatus(report)
		}
		return nil
	}

	before, plan, result, err := accessgrants.RepairManaged(cmd.Context(), driftOpts, accessgrants.ReconcileOptions{
		RosterFile: readPath,
		Inventory:  identityDriftInventory,
		StateDir:   resolveStateDir(accessStateFiles...),
		Now:        time.Now(),
	})
	if perr := printIdentityDriftReport(out, before); perr != nil {
		return perr
	}
	if before.Empty() {
		fmt.Fprintln(out, "no drift found; nothing to repair")
		return nil
	}
	fmt.Fprintf(out, "repaired via reconcile: %d hbac rule(s), %d sudo rule(s), %d account expiration(s), %d password polic(y/ies), %d user auth type(s)\n",
		len(plan.HBACRules), len(plan.SudoRules), len(plan.AccountExpirations), len(plan.PasswordPolicies), len(plan.UserAuthTypes))
	if result != nil {
		fmt.Fprintf(out, "apply exit code: %d\n", result.ExitCode)
	}
	return err
}

func printIdentityDriftReport(out io.Writer, report accessgrants.DriftReport) error {
	view := identityDriftJSON(report, identityDriftIncludeObjects)
	if identityDriftFormat == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(view)
	}
	fmt.Fprintf(out, "partial coverage; not inspected: %v\n", view.Uncovered)
	if report.Empty() {
		fmt.Fprintln(out, "no drift found within inspected scope")
		return nil
	}
	for _, item := range view.Items {
		fmt.Fprintf(out, "%s\tname=%s\taction=%s\tdetail=%s\n", item.Category, item.Name, item.Action, item.Detail)
	}
	return nil
}
