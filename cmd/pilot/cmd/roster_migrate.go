package cmd

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/inventory"
)

var (
	rosterMigrateTargetVersion int
	rosterMigrateDryRun        bool
	rosterMigrateVaultPassword string
)

var rosterMigrateCmd = &cobra.Command{
	Use:   "migrate <roster-file>",
	Short: "Upgrade a canonical roster to the current schema version",
	Long: `pilot roster migrate upgrades a schema-v1 roster to schema v2 in place.

It validates the original as v1, builds the v2 candidate entirely in
memory, checks that HBAC/sudo effective access and rendered NFS client
selectors come out exactly unchanged, writes a persistent backup of the
exact original bytes, then atomically replaces the roster. A roster
already at the target schema is left untouched: nothing is written, no
backup is created, and the command still exits 0.

The backup is never deleted automatically — it is the only place the
pre-migration roster is recoverable from, so its path is always printed
on success. Nothing this command prints ever includes a password, a
vault secret, or the roster's own content.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		result, err := inventory.MigrateRosterFile(path, inventory.RosterMigrationOptions{
			TargetVersion:     rosterMigrateTargetVersion,
			DryRun:            rosterMigrateDryRun,
			VaultPasswordFile: rosterMigrateVaultPassword,
		})
		if err != nil {
			if errors.Is(err, inventory.ErrRosterEncrypted) {
				// MigrateRosterFile only ever returns this when
				// VaultPasswordFile is empty — with one set, it attempts
				// the encrypted flow instead (see migrateEncryptedRosterFile),
				// so reaching here always means the flag was omitted.
				return fmt.Errorf("roster schema upgrade requires a vault credential; rerun with --vault-password-file <path>")
			}
			return err
		}
		printRosterMigrationResult(cmd.OutOrStdout(), path, result, rosterMigrateDryRun)
		return nil
	},
}

func init() {
	rosterMigrateCmd.Flags().IntVar(&rosterMigrateTargetVersion, "to", int(inventory.CurrentRosterSchemaVersion), "target schema version")
	rosterMigrateCmd.Flags().BoolVar(&rosterMigrateDryRun, "dry-run", false, "report what would change without writing anything")
	rosterMigrateCmd.Flags().StringVar(&rosterMigrateVaultPassword, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")
	rosterCmd.AddCommand(rosterMigrateCmd)
}

// printRosterMigrationResult renders result in the one shared format both
// `pilot roster migrate` and `pilot roster lint --upgrade` use. There is
// exactly one migration engine (inventory.MigrateRosterFile) and exactly
// one report format for what it did — never a second implementation of
// either, per the roster-schema-v2 migration spec's "MUST NOT be a second
// migration implementation inside lint".
func printRosterMigrationResult(w io.Writer, path string, result inventory.RosterMigrationResult, dryRun bool) {
	if !result.Changed {
		fmt.Fprintf(w, "roster %s is already schema v%d; nothing to do\n", path, result.ToVersion)
		return
	}

	if dryRun {
		fmt.Fprintln(w, "Roster would be migrated (dry run — nothing written)")
	} else {
		fmt.Fprintln(w, "Roster migrated successfully")
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "schema:\n  %d -> %d\n", result.FromVersion, result.ToVersion)
	fmt.Fprintln(w)
	if result.BackupPath != "" {
		fmt.Fprintf(w, "backup:\n  %s\n", result.BackupPath)
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "original_sha256:\n  %s\n", result.OriginalSHA256)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "new_sha256:\n  %s\n", result.NewSHA256)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "authorization changes:")
	fmt.Fprintln(w, "  none")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "HBAC effective access:")
	fmt.Fprintln(w, "  unchanged")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "sudo effective access:")
	fmt.Fprintln(w, "  unchanged")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "NFS rendered client selectors:")
	fmt.Fprintln(w, "  unchanged")
}
