// edit_workspace_backup.go is apply's rollback mechanism — see the
// spec's "如果 scenario 已成功儲存 hosts.yml，但後續 group_vars action
// 失敗... 從 journal 還原本 session 已修改的 managed files" requirement.
// There's no separate on-disk journal format: the "journal" is simply
// managedFileEntries(dir) (Phase 2), snapshotted in memory right
// before a scenario runs. Because computeWorkspaceRevision is a pure
// function of that same entry set, restoring it byte-for-byte makes
// "revision after rollback == revision before apply" a structural
// guarantee rather than something a caller must separately verify to
// trust.
package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/secretpath"
	"github.com/kjelly/pilot/internal/vaultfile"
)

// restoreManagedFiles rewrites dir's managed files to exactly match
// snapshot: every snapshot entry is written back verbatim, and any
// managed file present in dir now but absent from snapshot (created by
// the scenario that's being rolled back) is removed.
//
// A roster under .vault/ is the exception (rosterEntry): `pilot roster`,
// `pilot access` and decommission write rosters without this session's
// workspace lock, so one of them may have read the roster this session
// wrote and saved on top of it. A roster is put back only under its roster
// lock and only while it still holds what the session left there —
// written, the session's writes as noteSessionWrites recorded them
// (inventory.RestoreRosterFile). One that changed since, or is held, is
// left as it is and returned in left (relative paths) for the operator to
// check by hand. A roster the session never wrote is never touched and is
// no rollback failure: whoever changed it meant to. Each file is restored
// once, however many managed names it has (a .vault/ symlink and its
// target), and one already back to its pre-session bytes counts as done.
//
// kept lists the rosters left as another writer changed them (not this
// session's), so the caller can tell their change from a failed restore.
func restoreManagedFiles(dir string, snapshot []managedFileEntry, written map[string][]byte) (left, kept []string, err error) {
	wanted := make(map[string]managedFileEntry, len(snapshot))
	for _, e := range snapshot {
		wanted[e.RelPath] = e
	}
	current, err := managedFileEntries(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("rollback: scan managed files: %w", err)
	}
	now := make(map[string]managedFileEntry, len(current))
	for _, e := range current {
		now[e.RelPath] = e
	}
	restored := map[string]bool{}
	// restoreRoster reports whether rel was a roster, handled here.
	restoreRoster := func(rel string, before, after *managedFileEntry) (bool, error) {
		if !rosterEntry(before) && !rosterEntry(after) {
			return false, nil
		}
		if before != nil && after != nil && bytes.Equal(before.Content, after.Content) {
			return true, nil
		}
		expected, wrote := written[rel]
		if !wrote {
			// Changed by someone else, not this session: theirs to keep.
			kept = append(kept, rel)
			return true, nil
		}
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if file, err := secretpath.Canonical(full); err == nil {
			if restored[file] {
				return true, nil
			}
			restored[file] = true
		}
		var restoreErr error
		switch {
		case after == nil:
			// This session wrote it and someone has removed it since.
			restoreErr = inventory.ErrRosterChanged
		case before == nil:
			restoreErr = mutateRosterSource(dir, full, func() error { return inventory.RemoveRosterFile(full, expected) })
		default:
			restoreErr = mutateRosterSource(dir, full, func() error { return inventory.RestoreRosterFile(full, expected, before.Content) })
		}
		switch {
		case restoreErr == nil:
		case errors.Is(restoreErr, inventory.ErrRosterChanged), errors.Is(restoreErr, inventory.ErrMutationLocked), errors.Is(restoreErr, inventory.ErrRosterLockFile):
			left = append(left, rel)
		default:
			return true, fmt.Errorf("rollback: restore %s: %w", rel, restoreErr)
		}
		return true, nil
	}

	for _, e := range snapshot {
		after, ok := now[e.RelPath]
		var afterPtr *managedFileEntry
		if ok {
			afterPtr = &after
		}
		if handled, err := restoreRoster(e.RelPath, &e, afterPtr); err != nil {
			return nil, nil, err
		} else if handled {
			continue
		}
		full := filepath.Join(dir, filepath.FromSlash(e.RelPath))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return nil, nil, fmt.Errorf("rollback: mkdir for %s: %w", e.RelPath, err)
		}
		if err := os.WriteFile(full, e.Content, 0o644); err != nil {
			return nil, nil, fmt.Errorf("rollback: restore %s: %w", e.RelPath, err)
		}
	}

	for _, e := range current {
		if _, ok := wanted[e.RelPath]; ok {
			continue
		}
		if handled, err := restoreRoster(e.RelPath, nil, &e); err != nil {
			return nil, nil, err
		} else if handled {
			continue
		}
		full := filepath.Join(dir, filepath.FromSlash(e.RelPath))
		if err := os.Remove(full); err != nil {
			return nil, nil, fmt.Errorf("rollback: remove %s (created by the failed scenario): %w", e.RelPath, err)
		}
	}
	return left, kept, nil
}

// rosterEntry reports whether e, a managed file, is a roster under .vault/
// by its content: roster-shaped top-level keys (looksLikeRoster), or
// ansible-vault encrypted, which a session's automation never writes. nil
// (the file is absent on that side) is not.
func rosterEntry(e *managedFileEntry) bool {
	if e == nil || !e.IsSecret {
		return false
	}
	if isAnsibleVaultEncrypted(e.Content) {
		return true
	}
	doc, err := vaultfile.Parse(e.Content)
	return err == nil && looksLikeRoster(doc)
}

// secretFileContents is every managed .vault/ file's bytes, by RelPath.
func secretFileContents(dir string) map[string][]byte {
	out := map[string][]byte{}
	entries, err := managedFileEntries(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsSecret {
			out[e.RelPath] = e.Content
		}
	}
	return out
}

// noteSessionWrites records in written every managed .vault/ file whose
// bytes differ from last (secretFileContents as the step began), with its
// new bytes: what a session wrote, as a rollback must find it to undo it
// (restoreManagedFiles). Called after each scenario step; a roster another
// process saves while that same step runs counts as the session's, one it
// saves between steps does not.
func noteSessionWrites(dir string, last, written map[string][]byte) {
	entries, err := managedFileEntries(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsSecret {
			continue
		}
		if before, ok := last[e.RelPath]; !ok || !bytes.Equal(before, e.Content) {
			written[e.RelPath] = e.Content
			last[e.RelPath] = e.Content
		}
	}
}
