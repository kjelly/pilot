package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/freeipa"
	"github.com/kjelly/pilot/internal/inventory"
)

// ErrRosterUserAlreadyApplied/ErrRosterGroupAlreadyApplied are returned
// (wrapped) when the FreeIPA historical probe (internal/freeipa) proves
// ever_applied=true — the resource has entered the managed lifecycle and
// must remain represented in the roster forever (spec.md §2.1, §21).
var (
	ErrRosterUserAlreadyApplied  = errors.New("roster user has entered the FreeIPA lifecycle")
	ErrRosterGroupAlreadyApplied = errors.New("roster group has entered the FreeIPA lifecycle")
)

// isRosterFileEncrypted mirrors the exact ansible-vault-prefix detection
// every internal/inventory roster reader already does internally — this
// call only exists so the CLI layer can decide, before invoking any
// mutation, whether --vault-password-file is required and whether reads
// need to go through a decrypted temp copy.
func isRosterFileEncrypted(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT"), nil
}

// resolveRosterRemoveInputs validates the roster-file/inventory paths
// common to remove-user and remove-group, and reports whether the
// roster is encrypted (requiring --vault-password-file).
func resolveRosterRemoveInputs(rosterPath, inventoryPath, vaultPasswordFile string) (encrypted bool, err error) {
	if _, err := os.Stat(inventoryPath); err != nil {
		return false, fmt.Errorf("inventory %s: %w", inventoryPath, err)
	}
	if _, err := os.Stat(rosterPath); err != nil {
		return false, fmt.Errorf("roster %s: %w", rosterPath, err)
	}
	encrypted, err = isRosterFileEncrypted(rosterPath)
	if err != nil {
		return false, fmt.Errorf("roster %s: %w", rosterPath, err)
	}
	if encrypted && vaultPasswordFile == "" {
		return false, fmt.Errorf("roster %s is ansible-vault encrypted; rerun with --vault-password-file", rosterPath)
	}
	return encrypted, nil
}

// printRosterReferences renders a reference list in the shape spec.md
// §7.4/§7.6 shows: one path per line, sorted (RosterUserReferences/
// RosterGroupReferences already sort deterministically).
func printRosterReferences(w io.Writer, refs []inventory.RosterReference) {
	fmt.Fprintln(w, "references:")
	for _, ref := range refs {
		fmt.Fprintf(w, "  %s\n", ref.Path)
	}
}

// rosterRemoveTestProbeRunner overrides the ansible runner
// probeUserHistory/probeGroupHistory use. nil (the default, always true
// in production) selects internal/freeipa's own production
// ansible.NewRunner(); tests that have no real FreeIPA server to talk to
// set this to a fake before calling a remove-user/remove-group RunE
// directly.
var rosterRemoveTestProbeRunner interface {
	Run(ctx context.Context, args ...string) (*ansible.Result, error)
}

func probeUserHistory(ctx context.Context, inventoryPath, rosterPlaintextPath, username string) (freeipa.UserHistoryProbe, error) {
	return freeipa.ProbeUserHistory(ctx, username, freeipa.ProbeOptions{
		Inventory:  inventoryPath,
		RosterFile: rosterPlaintextPath,
		Runner:     rosterRemoveTestProbeRunner,
	})
}

func probeGroupHistory(ctx context.Context, inventoryPath, rosterPlaintextPath, groupname string) (freeipa.GroupHistoryProbe, error) {
	return freeipa.ProbeGroupHistory(ctx, groupname, freeipa.ProbeOptions{
		Inventory:  inventoryPath,
		RosterFile: rosterPlaintextPath,
		Runner:     rosterRemoveTestProbeRunner,
	})
}
