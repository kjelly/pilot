package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/inventory"
)

var (
	rosterRemoveGroupInventory         string
	rosterRemoveGroupVaultPasswordFile string
	rosterRemoveGroupDryRun            bool
	rosterRemoveGroupCascade           bool
)

var rosterRemoveGroupCmd = &cobra.Command{
	Use:   "remove-group <roster-file> <groupname>",
	Short: "Undo a never-applied local roster group definition",
	Long: `pilot roster remove-group hard-removes a roster group entry that has
never been applied to FreeIPA — the safe undo for an accidentally-added
local edit.

This is NOT a FreeIPA group deletion command. FreeIPA has no
preserved-group lifecycle equivalent to preserved users, so "ever
applied" is proven by a durable, deterministic history marker
(pilot-internal-history-g-<sha256(name)>) that freeipa-identity-apply.yml
creates for every group that reaches state: present and never deletes —
an active group OR a valid marker permanently blocks this command. Use
state: absent (reconciled through freeipa-identity-apply.yml) for
declarative FreeIPA group deletion instead; the roster tombstone remains.

A required scalar reference (e.g. an NFS share's ownership.group) always
blocks removal, even with --cascade-references — reassign it explicitly
first. There is no --force flag.`,
	Args: cobra.ExactArgs(2),
	RunE: runRosterRemoveGroup,
}

func init() {
	rosterRemoveGroupCmd.Flags().StringVarP(&rosterRemoveGroupInventory, "inventory", "i", "inventory.yml", "inventory used to resolve/contact the FreeIPA server")
	rosterRemoveGroupCmd.Flags().StringVar(&rosterRemoveGroupVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")
	rosterRemoveGroupCmd.Flags().BoolVar(&rosterRemoveGroupDryRun, "dry-run", false, "perform every read/probe/validation step but do not mutate the roster")
	rosterRemoveGroupCmd.Flags().BoolVar(&rosterRemoveGroupCascade, "cascade-references", false, "also remove local inbound references to this group (never a blocked reference)")
	rosterCmd.AddCommand(rosterRemoveGroupCmd)
}

func runRosterRemoveGroup(cmd *cobra.Command, args []string) error {
	rosterPath, groupname := args[0], args[1]
	out := cmd.OutOrStdout()
	ctx := cmd.Context()

	encrypted, err := resolveRosterRemoveInputs(rosterPath, rosterRemoveGroupInventory, rosterRemoveGroupVaultPasswordFile)
	if err != nil {
		return err
	}

	readPath := rosterPath
	if encrypted {
		tmp, cleanup, err := inventory.DecryptRosterToTempFile(rosterPath, rosterRemoveGroupVaultPasswordFile)
		if err != nil {
			return err
		}
		defer cleanup()
		readPath = tmp
	}

	opts := inventory.RemoveRosterGroupOptions{CascadeReferences: rosterRemoveGroupCascade}

	// Phase A — local read-only checks.
	sim, err := inventory.SimulateRemoveRosterGroup(readPath, groupname, opts)
	if err != nil {
		return err
	}
	if !sim.Found {
		return fmt.Errorf("roster %s: no group entry named %q", rosterPath, groupname)
	}

	var blocked []inventory.RosterReference
	for _, ref := range sim.References {
		if ref.Cascade == inventory.RosterReferenceCascadeBlocked {
			blocked = append(blocked, ref)
		}
	}
	if len(blocked) > 0 {
		fmt.Fprintf(out, "cannot remove roster group %q: the group is required by a non-cascadeable reference\n\n", groupname)
		printRosterReferences(out, blocked)
		fmt.Fprintln(out, "\nChange the owning group explicitly before removing this roster group.")
		return fmt.Errorf("roster group %q is required by a non-cascadeable reference", groupname)
	}
	if len(sim.References) > 0 && !rosterRemoveGroupCascade {
		fmt.Fprintf(out, "cannot remove roster group %q: resource is still referenced\n\n", groupname)
		printRosterReferences(out, sim.References)
		fmt.Fprintln(out, "\nrerun with --cascade-references to remove these local references")
		return fmt.Errorf("roster group %q is still referenced (%d reference(s))", groupname, len(sim.References))
	}

	// Phase B — authoritative FreeIPA historical probe.
	probe, err := probeGroupHistory(ctx, rosterRemoveGroupInventory, readPath, groupname)
	if err != nil {
		fmt.Fprintf(out, "refusing to remove roster group %q:\nunable to prove that the group has never been applied to FreeIPA.\n\nFreeIPA probe failed: %v\nNo roster bytes were changed.\n", groupname, err)
		return fmt.Errorf("FreeIPA history for roster group %q is unknown", groupname)
	}
	if probe.EverApplied {
		fmt.Fprintf(out, "refusing to remove roster group %q:\nFreeIPA history marker proves this group has entered the managed lifecycle.\n\nmarker:\n  %s\n\nUse state: absent for declarative FreeIPA deletion.\nThe roster tombstone must remain.\n", groupname, probe.HistoryMarker)
		return fmt.Errorf("roster group %q: %w", groupname, ErrRosterGroupAlreadyApplied)
	}

	// Phase C — candidate validation (computed by Phase A's simulation).
	if len(sim.Violations) != 0 {
		fmt.Fprintf(out, "cannot remove roster group %q: the candidate roster would be invalid\n\n", groupname)
		for _, v := range sim.Violations {
			fmt.Fprintln(out, " ", v.String())
		}
		return fmt.Errorf("roster group %q: candidate roster is invalid", groupname)
	}

	if rosterRemoveGroupDryRun {
		fmt.Fprintf(out, "Would remove roster-only group %q.\nFreeIPA history check: not found.\nReferences removed: %d.\n", groupname, len(sim.RemovedReferences))
		return nil
	}

	// Phase D — mutation, with a second FreeIPA probe immediately before
	// writing (TOCTOU mitigation — spec.md §16).
	mutate := func(plainPath string) error {
		probe2, err := probeGroupHistory(ctx, rosterRemoveGroupInventory, plainPath, groupname)
		if err != nil {
			return fmt.Errorf("refusing to remove roster group %q: FreeIPA probe failed on the pre-write recheck: %w", groupname, err)
		}
		if probe2.EverApplied {
			return fmt.Errorf("refusing to remove roster group %q: %w (detected on the pre-write recheck)", groupname, ErrRosterGroupAlreadyApplied)
		}
		return inventory.RemoveRosterGroup(plainPath, groupname, opts)
	}
	if encrypted {
		err = inventory.MutateEncryptedRosterFile(rosterPath, rosterRemoveGroupVaultPasswordFile, mutate)
	} else {
		err = mutate(rosterPath)
	}
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "Removed roster-only group %q.\nFreeIPA history check: not found.\nReferences removed: %d.\n", groupname, len(sim.RemovedReferences))
	return nil
}
