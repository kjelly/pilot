package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/inventory"
)

var rosterCmd = &cobra.Command{
	Use:   "roster",
	Short: "Validate a canonical freeipa-identity roster file",
}

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
roster's own structure, not the rest of the inventory.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		violations, err := inventory.ValidateRosterFile(args[0])
		if err != nil {
			if errors.Is(err, inventory.ErrRosterEncrypted) {
				return fmt.Errorf("%s is ansible-vault encrypted; decrypt it first (e.g. ansible-vault view %s) to lint it", args[0], args[0])
			}
			return err
		}
		if len(violations) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "ok: no issues found")
			return nil
		}
		for _, v := range violations {
			fmt.Fprintln(cmd.OutOrStdout(), v.String())
		}
		return fmt.Errorf("%d issue(s) found", len(violations))
	},
}

func init() {
	rosterCmd.AddCommand(rosterLintCmd)
	rootCmd.AddCommand(rosterCmd)
}
