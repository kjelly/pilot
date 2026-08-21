package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/inventory"
)

var (
	rosterRemoveUserInventory         string
	rosterRemoveUserVaultPasswordFile string
	rosterRemoveUserDryRun            bool
	rosterRemoveUserCascade           bool
)

var rosterRemoveUserCmd = &cobra.Command{
	Use:   "remove-user <roster-file> <username>",
	Short: "Undo a never-applied local roster user definition",
	Long: `pilot roster remove-user hard-removes a roster user entry that has
never been applied to FreeIPA — the safe undo for an accidentally-added
local edit.

This is NOT a FreeIPA deprovisioning command. A user that FreeIPA reports
as active or preserved can never be removed by this command, and neither
can a roster entry already in state: absent — use state: disabled or
state: absent (reconciled through freeipa-identity-apply.yml) instead.

There is no --force flag: the FreeIPA historical guard and the
state: absent tombstone rule cannot be bypassed.`,
	Args: cobra.ExactArgs(2),
	RunE: runRosterRemoveUser,
}

func init() {
	rosterRemoveUserCmd.Flags().StringVarP(&rosterRemoveUserInventory, "inventory", "i", "inventory.yml", "inventory used to resolve/contact the FreeIPA server")
	rosterRemoveUserCmd.Flags().StringVar(&rosterRemoveUserVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")
	rosterRemoveUserCmd.Flags().BoolVar(&rosterRemoveUserDryRun, "dry-run", false, "perform every read/probe/validation step but do not mutate the roster")
	rosterRemoveUserCmd.Flags().BoolVar(&rosterRemoveUserCascade, "cascade-references", false, "also remove local inbound references to this user")
	rosterCmd.AddCommand(rosterRemoveUserCmd)
}

func runRosterRemoveUser(cmd *cobra.Command, args []string) error {
	rosterPath, username := args[0], args[1]
	out := cmd.OutOrStdout()
	ctx := cmd.Context()

	encrypted, err := resolveRosterRemoveInputs(rosterPath, rosterRemoveUserInventory, rosterRemoveUserVaultPasswordFile)
	if err != nil {
		return err
	}

	readPath := rosterPath
	if encrypted {
		tmp, cleanup, err := inventory.DecryptRosterToTempFile(rosterPath, rosterRemoveUserVaultPasswordFile)
		if err != nil {
			return err
		}
		defer cleanup()
		readPath = tmp
	}

	opts := inventory.RemoveRosterUserOptions{CascadeReferences: rosterRemoveUserCascade}

	// Phase A — local read-only checks.
	sim, err := inventory.SimulateRemoveRosterUser(readPath, username, opts)
	if err != nil {
		return err
	}
	if !sim.Found {
		return fmt.Errorf("roster %s: no user entry named %q", rosterPath, username)
	}
	if len(sim.References) > 0 && !rosterRemoveUserCascade {
		fmt.Fprintf(out, "cannot remove roster user %q: resource is still referenced\n\n", username)
		printRosterReferences(out, sim.References)
		fmt.Fprintln(out, "\nrerun with --cascade-references to remove these local references")
		return fmt.Errorf("roster user %q is still referenced (%d reference(s))", username, len(sim.References))
	}

	// Phase B — authoritative FreeIPA historical probe.
	probe, err := probeUserHistory(ctx, rosterRemoveUserInventory, readPath, username)
	if err != nil {
		fmt.Fprintf(out, "refusing to remove roster user %q:\nunable to prove that the user has never been applied to FreeIPA.\n\nFreeIPA probe failed: %v\nNo roster bytes were changed.\n", username, err)
		return fmt.Errorf("FreeIPA history for roster user %q is unknown", username)
	}
	if probe.EverApplied {
		fmt.Fprintf(out, "refusing to remove roster user %q:\nFreeIPA reports an active or preserved user with this name.\n\nThis user has entered the FreeIPA lifecycle and must remain represented\nin the roster. Use state: disabled or state: absent instead.\n", username)
		return fmt.Errorf("roster user %q: %w", username, ErrRosterUserAlreadyApplied)
	}

	// Phase C — candidate validation (computed by Phase A's simulation).
	if len(sim.Violations) != 0 {
		fmt.Fprintf(out, "cannot remove roster user %q: the candidate roster would be invalid\n\n", username)
		for _, v := range sim.Violations {
			fmt.Fprintln(out, " ", v.String())
		}
		return fmt.Errorf("roster user %q: candidate roster is invalid", username)
	}

	if rosterRemoveUserDryRun {
		fmt.Fprintf(out, "Would remove roster-only user %q.\nFreeIPA history check: not found.\nReferences removed: %d.\n", username, len(sim.RemovedReferences))
		return nil
	}

	// Phase D — mutation, with a second FreeIPA probe immediately before
	// writing (TOCTOU mitigation — spec.md §16) against whatever fresh
	// plaintext copy is about to actually be written.
	mutate := func(plainPath string) error {
		probe2, err := probeUserHistory(ctx, rosterRemoveUserInventory, plainPath, username)
		if err != nil {
			return fmt.Errorf("refusing to remove roster user %q: FreeIPA probe failed on the pre-write recheck: %w", username, err)
		}
		if probe2.EverApplied {
			return fmt.Errorf("refusing to remove roster user %q: %w (detected on the pre-write recheck)", username, ErrRosterUserAlreadyApplied)
		}
		return inventory.RemoveRosterUser(plainPath, username, opts)
	}
	if encrypted {
		err = inventory.MutateEncryptedRosterFile(rosterPath, rosterRemoveUserVaultPasswordFile, mutate)
	} else {
		err = mutate(rosterPath)
	}
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "Removed roster-only user %q.\nFreeIPA history check: not found.\nReferences removed: %d.\n", username, len(sim.RemovedReferences))
	return nil
}
