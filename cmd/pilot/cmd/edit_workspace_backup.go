// edit_workspace_backup.go is apply's rollback mechanism — see the
// spec's "如果 scenario 已成功儲存 hosts.yml，但後續 group_vars action
// 失敗... 從 journal 還原本 session 已修改的 managed files" requirement.
// There's no separate on-disk journal format: the "journal" is simply
// managedFileEntries(dir) (Phase 2), snapshotted in memory right
// before a scenario runs. Because computeWorkspaceRevision is a pure
// function of that same entry set, restoring it byte-for-byte makes
// "revision after rollback == revision before apply" a structural
// guarantee rather than something a caller must separately verify to
// trust. Rosters under .vault/ are the exception: they have writers
// outside the workspace lock, so the rollback undoes only what the
// session's own writes replaced, as the apply's inventory.RosterJournal
// recorded them where each was written (restoreManagedFiles).
package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/vaultfile"
)

// sessionRosterWrites is what an apply knows about its own writes to its
// .vault/ files: every roster write writeLockedRoster recorded while the
// session ran (inventory.RosterJournal.Writes, by canonical path), and the
// files whose bytes changed while a step ran (noteSessionWrites, by
// RelPath) — by the session or by anyone else.
type sessionRosterWrites struct {
	writes  map[string][]inventory.RosterWrite
	touched map[string]bool
}

// rollbackReport is what restoreManagedFiles did not simply put back.
type rollbackReport struct {
	// left are rosters left as they are for a hand check, as
	// "<RelPath> (<why>)".
	left []string
	// kept are the RelPaths of rosters another writer changed during the
	// apply whose change the rollback kept: revisionWith takes them as
	// they are now.
	kept []string
	// notes say, one line per kept roster file, what was kept.
	notes []string
}

// restoreManagedFiles rewrites dir's managed files to exactly match
// snapshot: every snapshot entry is written back verbatim, and any
// managed file present in dir now but absent from snapshot (created by
// the scenario that's being rolled back) is removed.
//
// A roster under .vault/ is the exception (rosterEntry): `pilot roster`,
// `pilot access` and decommission write rosters without this session's
// workspace lock, so a roster may hold another process's change made at
// any point of the apply. The rollback undoes only what the session's own
// writes replaced, as session.writes recorded them at the write site, one
// file at a time however many managed names it has (a .vault/ symlink and
// its target, or hard links of one file):
//
//   - Back to its pre-apply bytes, or never changed: nothing to do.
//   - No write of the session's and not changed while a step ran: another
//     writer's change, kept as it is (kept).
//   - No write of the session's, but changed while a step ran: pilot
//     cannot tell whose change it is, so it is left as it is (left) and
//     never restored.
//   - The session's writes do not form one chain — one began from other
//     bytes than the previous one left, or one failed part-way — so
//     another writer changed it between them, or its bytes are unknown:
//     left.
//   - Otherwise it gets back what the session's first write replaced
//     (inventory.RestoreRosterFile; a roster the session created is
//     removed, inventory.RemoveRosterFile) — under its roster lock and only
//     while it still holds what the session's last write left. One changed
//     since, removed, held, or whose lock file cannot be used is left. When
//     what the first write replaced was already another writer's change
//     (not the pre-apply bytes), the restored roster is kept too, every
//     name of it.
//
// left is for the operator to check by hand; kept and its notes are no
// failure: whoever changed those rosters meant to.
func restoreManagedFiles(dir string, snapshot []managedFileEntry, session *sessionRosterWrites) (rollbackReport, error) {
	if session == nil {
		session = &sessionRosterWrites{}
	}
	var report rollbackReport
	wanted := make(map[string]managedFileEntry, len(snapshot))
	for _, e := range snapshot {
		wanted[e.RelPath] = e
	}
	current, err := managedFileEntries(dir)
	if err != nil {
		return report, fmt.Errorf("rollback: scan managed files: %w", err)
	}
	now := make(map[string]managedFileEntry, len(current))
	for _, e := range current {
		now[e.RelPath] = e
	}
	entry := func(m map[string]managedFileEntry, rel string) *managedFileEntry {
		if e, ok := m[rel]; ok {
			return &e
		}
		return nil
	}

	// Rosters, a file at a time: their names grouped by the file they
	// name (inventory.RosterFileKey: one file however many symlinks or hard
	// links name it, the key the journal records its writes under), in
	// RelPath order.
	var rels []string
	for _, e := range snapshot {
		rels = append(rels, e.RelPath)
	}
	for _, e := range current {
		if _, ok := wanted[e.RelPath]; !ok {
			rels = append(rels, e.RelPath)
		}
	}
	sort.Strings(rels)
	files := map[string][]string{}
	var order []string
	roster := map[string]bool{}
	for _, rel := range rels {
		if !rosterEntry(entry(wanted, rel)) && !rosterEntry(entry(now, rel)) {
			continue
		}
		roster[rel] = true
		file, err := inventory.RosterFileKey(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			file = "unresolved:" + rel // a dangling link: a file of its own
		}
		if _, seen := files[file]; !seen {
			order = append(order, file)
		}
		files[file] = append(files[file], rel)
	}
	for _, file := range order {
		if err := restoreRosterFile(dir, file, files[file], wanted, now, session, &report); err != nil {
			return report, err
		}
	}

	for _, e := range snapshot {
		if roster[e.RelPath] {
			continue
		}
		full := filepath.Join(dir, filepath.FromSlash(e.RelPath))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return report, fmt.Errorf("rollback: mkdir for %s: %w", e.RelPath, err)
		}
		if err := os.WriteFile(full, e.Content, 0o644); err != nil {
			return report, fmt.Errorf("rollback: restore %s: %w", e.RelPath, err)
		}
	}
	for _, e := range current {
		if _, ok := wanted[e.RelPath]; ok || roster[e.RelPath] {
			continue
		}
		full := filepath.Join(dir, filepath.FromSlash(e.RelPath))
		if err := os.Remove(full); err != nil {
			return report, fmt.Errorf("rollback: remove %s (created by the failed scenario): %w", e.RelPath, err)
		}
	}
	return report, nil
}

// restoreRosterFile rolls back one roster file, file (canonical), whose
// managed names are rels, by restoreManagedFiles' rules, adding what it
// did not restore to report.
func restoreRosterFile(dir, file string, rels []string, wanted, now map[string]managedFileEntry, session *sessionRosterWrites, report *rollbackReport) error {
	// The file's name in messages: its own name rather than a link's.
	shown := rels[0]
	var before, after *managedFileEntry
	for _, rel := range rels {
		if e, ok := wanted[rel]; ok && before == nil {
			before = &e
		}
		if e, ok := now[rel]; ok && after == nil {
			after = &e
		}
		if e, ok := wanted[rel]; ok && !e.IsSymlink {
			shown = rel
		}
		if e, ok := now[rel]; ok && !e.IsSymlink {
			shown = rel
		}
	}
	if (before == nil) == (after == nil) && (before == nil || bytes.Equal(before.Content, after.Content)) {
		return nil
	}
	leave := func(why string) {
		report.left = append(report.left, shown+" ("+why+")")
	}
	keep := func(note string) {
		report.kept = append(report.kept, rels...)
		report.notes = append(report.notes, strings.Join(rels, ", ")+": "+note)
	}
	writes := session.writes[file]
	touched := false
	for _, rel := range rels {
		touched = touched || session.touched[rel]
	}
	switch {
	case len(writes) == 0 && !touched:
		keep("another pilot process changed it during this apply, which never wrote it; the rollback kept that change")
		return nil
	case len(writes) == 0:
		leave("it changed while a step ran, but this apply recorded no write to it; pilot cannot tell whose change it is, so it was not rolled back")
		return nil
	}
	for i, w := range writes {
		switch {
		case w.Failed:
			leave("a write of this apply to it failed part-way, so what it holds is unknown")
			return nil
		case i > 0 && (!w.Existed || !bytes.Equal(w.Before, writes[i-1].After)):
			leave("another pilot process changed it between this apply's writes to it, so undoing them would undo that change too")
			return nil
		}
	}
	first, last := writes[0], writes[len(writes)-1]
	if after == nil {
		leave("it was removed after this apply wrote it")
		return nil
	}
	full := filepath.Join(dir, filepath.FromSlash(shown))
	var err error
	if first.Existed {
		err = mutateRosterSource(editWriteScope{dir: dir}, full, func(full string) error { return inventory.RestoreRosterFile(full, last.After, first.Before) })
	} else {
		err = mutateRosterSource(editWriteScope{dir: dir}, full, func(full string) error { return inventory.RemoveRosterFile(full, last.After) })
	}
	switch {
	case errors.Is(err, inventory.ErrRosterChanged):
		leave("another pilot process changed it after this apply wrote it")
		return nil
	case errors.Is(err, inventory.ErrMutationLocked):
		leave("another pilot process holds its lock")
		return nil
	case errors.Is(err, inventory.ErrRosterLockFile):
		leave("its lock file cannot be used")
		return nil
	case err != nil:
		return fmt.Errorf("rollback: restore %s: %w", shown, err)
	}
	if first.Existed != (before != nil) || (before != nil && !bytes.Equal(first.Before, before.Content)) {
		keep("another pilot process changed it during this apply before this apply wrote it; the rollback undid only this apply's writes and kept that change")
	}
	return nil
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

// noteSessionWrites marks in touched every managed .vault/ file whose
// bytes differ from last (secretFileContents as the step began), or that
// is gone since: changed while a step ran, by the session or by anyone
// else. Called after each scenario step. Who wrote a roster is not
// decided here — the apply's RosterJournal records the session's own
// writes — but a roster changed while a step ran with no write recorded is
// one the rollback cannot attribute (restoreManagedFiles).
func noteSessionWrites(dir string, last map[string][]byte, touched map[string]bool) {
	entries, err := managedFileEntries(dir)
	if err != nil {
		return
	}
	present := map[string]bool{}
	for _, e := range entries {
		if !e.IsSecret {
			continue
		}
		present[e.RelPath] = true
		if before, ok := last[e.RelPath]; !ok || !bytes.Equal(before, e.Content) {
			touched[e.RelPath] = true
		}
	}
	for rel := range last {
		if !present[rel] {
			touched[rel] = true
		}
	}
}
