package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/inventory"
)

var rosterCmd = &cobra.Command{
	Use:   "roster",
	Short: "Validate a canonical freeipa-identity roster file",
}

var rosterLintUpgrade bool

var rosterLintCmd = &cobra.Command{
	Use:   "lint <roster-file>",
	Short: "Check a roster against the same rules freeipa-identity-apply.yml enforces at real-apply time",
	Long: `pilot roster lint mirrors freeipa-identity-apply.yml's "Gate: canonical
..." assert chain in Go — user/group/host field validation, group category
name-prefix rules, HBAC/sudo subject and target referential integrity, and
the sudo command denylist — so a mistake (a dangling group reference, an
unsafe sudo command, a missing name prefix) is caught by reading the file
directly, without needing an inventory or running ansible-playbook at all.

A roster that passes this should also pass those Ansible gates; this does
not replace running a real --check apply, since it only checks the
roster's own structure, not the rest of the inventory.

A structurally valid roster below the current schema version passes with a
notice pointing at ` + "`pilot roster migrate`" + `; pass --upgrade to have
lint perform that upgrade itself (via the same migration engine, not a
second one) before reporting.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		violations, err := inventory.ValidateRosterFile(path)
		if err != nil {
			if errors.Is(err, inventory.ErrRosterEncrypted) {
				return fmt.Errorf("%s is ansible-vault encrypted; decrypt it first (e.g. ansible-vault view %s) to lint it", path, path)
			}
			return err
		}
		if len(violations) > 0 {
			for _, v := range violations {
				fmt.Fprintln(cmd.OutOrStdout(), v.String())
			}
			return fmt.Errorf("%d issue(s) found", len(violations))
		}

		// Deprecation warnings never affect exit status or violate lint
		// (spec.md §8) — printWarnings runs after every "ok:"/notice line
		// below, exactly like the freeipa-identity.md example output.
		// --upgrade remains purely about schema migration; it does not
		// touch or remove deprecated-category groups, so the warning
		// still applies just as much after upgrading.
		warnings, err := inventory.RosterDeprecationWarningsFile(path)
		if err != nil {
			return err
		}
		printWarnings := func() {
			for _, w := range warnings {
				fmt.Fprintf(cmd.OutOrStdout(), "warning: %s\n", w.Detail)
			}
		}

		// No structural violations: report which schema version passed
		// and, for v1, nudge toward `pilot roster migrate`. This re-reads
		// the file only to detect its declared version for display — it
		// is not a second validation pass; ValidateRosterFile above
		// already did the only one.
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		version, err := inventory.DetectRosterSchemaVersion(data)
		if err != nil {
			// Violations were already empty, so this shouldn't happen in
			// practice; fall back rather than fail oddly on a race.
			fmt.Fprintln(cmd.OutOrStdout(), "ok: no issues found")
			printWarnings()
			return nil
		}

		if rosterLintUpgrade && version != inventory.CurrentRosterSchemaVersion {
			result, err := inventory.MigrateRosterFile(path, inventory.RosterMigrationOptions{})
			if err != nil {
				return err
			}
			printRosterMigrationResult(cmd.OutOrStdout(), path, result, false)
			printWarnings()
			return nil
		}

		switch {
		case version == inventory.CurrentRosterSchemaVersion:
			fmt.Fprintf(cmd.OutOrStdout(), "ok: schema v%d; no issues found\n", version)
		case version < inventory.CurrentRosterSchemaVersion:
			fmt.Fprintf(cmd.OutOrStdout(), "ok: schema v%d is valid\n", version)
			fmt.Fprintf(cmd.OutOrStdout(), "notice: current schema is v%d; run `pilot roster migrate %s`\n", inventory.CurrentRosterSchemaVersion, path)
		default:
			fmt.Fprintf(cmd.OutOrStdout(), "ok: schema v%d is valid\n", version)
		}
		printWarnings()
		return nil
	},
}

func init() {
	rosterLintCmd.Flags().BoolVar(&rosterLintUpgrade, "upgrade", false, "if the roster isn't the current schema version, upgrade it via the same engine as `pilot roster migrate` before reporting")
	rosterCmd.AddCommand(rosterLintCmd)
	rootCmd.AddCommand(rosterCmd)
}
