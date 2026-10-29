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

	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/vaultfile"
)

// sessionRosterWrites is what an apply knows about its .vault/ files: the
// ones that were rosters before it ran (rosters), every roster write
// writeLockedRoster recorded while the session ran
// (inventory.RosterJournal.Writes, by roster key), and the files whose bytes
// changed while a step ran (noteSessionWrites, by RelPath) — by the session
// or by anyone else.
type sessionRosterWrites struct {
	writes  map[string][]inventory.RosterWrite
	touched map[string]bool
	// rosters are the RelPaths of the snapshot's .vault/ files that were
	// rosters before the apply ran (rosterNamesBeforeApply).
	rosters map[string]bool
}

// rollbackReport is what restoreManagedFiles did not simply put back.
type rollbackReport struct {
	// left are rosters left as they are for a hand check, as
	// "<RelPath> (<why>)".
	left []string
	// leftPlaintext is whether one of them is a plaintext roster, whose
	// freeipa.admin.password the operator must check against the vault; an
	// encrypted file is no roster pilot reads.
	leftPlaintext bool
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
// A roster under .vault/ is the exception (rosterFile): `pilot roster`,
// `pilot access` and decommission write rosters without this session's
// workspace lock, so a roster may hold another process's change made at
// any point of the apply. The rollback undoes only what the session's own
// writes replaced, as session.writes recorded them at the write site, one
// file at a time however many managed names it has (a .vault/ symlink and
// its target, or hard links of one file):
//
//   - A .vault/ file the apply's snapshot does not have, with no write of
//     the session's, is another writer's roster when it looks like one now
//     (foreignNewRosters): it goes through the cases below, so it is kept
//     (or left, when it appeared while a step ran) rather than removed.
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
	// RelPath order. A file is a roster by what the apply knew before it ran,
	// what its journal recorded, and — for a file the snapshot does not
	// have — whether it is another writer's roster now (rosterFile).
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
	for _, rel := range rels {
		if !secretEntry(entry(wanted, rel), entry(now, rel)) {
			continue
		}
		file, err := inventory.RosterFileKey(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			file = "unresolved:" + rel // a dangling link: a file of its own
		}
		if _, seen := files[file]; !seen {
			order = append(order, file)
		}
		files[file] = append(files[file], rel)
	}
	// A file the apply's snapshot does not have may still be another
	// process's roster, created while the apply ran (foreignNewRosters).
	var created []managedFileEntry
	for _, e := range current {
		if _, ok := wanted[e.RelPath]; !ok {
			created = append(created, e)
		}
	}
	known := foreignNewRosters(dir, created)
	for rel := range session.rosters {
		known[rel] = true
	}
	roster := map[string]bool{}
	var rosterOrder []string
	for _, file := range order {
		if rosterFile(files[file], session.writes[file], known) {
			rosterOrder = append(rosterOrder, file)
			for _, rel := range files[file] {
				roster[rel] = true
			}
		}
	}
	order = rosterOrder
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
		report.leftPlaintext = report.leftPlaintext || !rosterEncrypted(before, after)
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

// secretEntry reports whether either side of a managed file — as the
// snapshot had it, as it is now; nil when absent on that side — is a .vault/
// file: only those can be rosters.
func secretEntry(wanted, now *managedFileEntry) bool {
	return wanted != nil && wanted.IsSecret || now != nil && now.IsSecret
}

// rosterFile reports whether the .vault/ file the names rels reach is a
// roster for the rollback: one the apply's journal recorded a write to
// (writes), or one in known — a file that was a roster before the apply ran
// (rosterNamesBeforeApply), or a new file that is another writer's roster
// (foreignNewRosters). It is never decided from the bytes a file holds
// because of what the session made of it (a vault edit can make any file
// look like one). A file the session created, never wrote through a roster
// writer and that is no other writer's roster is a plain one, and is
// removed.
func rosterFile(rels []string, writes []inventory.RosterWrite, known map[string]bool) bool {
	if len(writes) > 0 {
		return true
	}
	for _, rel := range rels {
		if known[rel] {
			return true
		}
	}
	return false
}

// rosterNamesBeforeApply returns the RelPaths of the snapshot's .vault/ files
// that are rosters before an apply on dir runs (rosterLike).
func rosterNamesBeforeApply(dir string, snapshot []managedFileEntry) map[string]bool {
	return rosterLike(dir, snapshot)
}

// foreignNewRosters returns the RelPaths of the .vault/ files in created —
// the files the apply's snapshot does not have — that belong to another
// writer rather than to the session, decided from what they hold now
// (rosterLike), since no snapshot says what they were: a roster that
// `pilot roster`, `pilot access` or decommission created in .vault/ while
// the apply ran must not be removed with the files the session created.
// The only .vault/ file the session can create without a journaled roster
// write is a plain one the vault editor wrote, with scalar values; so a new
// file that is encrypted, holds a roster-shaped mapping or list, or is a
// roster the workspace names now is kept. A file the vault editor created
// under the default roster name .vault/ipa-identity.yaml, with only scalars,
// is kept too: pilot cannot tell it from a roster another process created
// there, and keeping a file is the safe error.
func foreignNewRosters(dir string, created []managedFileEntry) map[string]bool {
	return rosterLike(dir, created)
}

// rosterLike returns the RelPaths of entries' .vault/ files that look like
// rosters: those that are ansible-vault encrypted (a session's automation
// never writes one), those with a roster-shaped top-level key holding a
// mapping or a list rather than a scalar (the vault editor writes only
// scalars, so a plain vault file does not look like that), and those the
// workspace names as its roster — the editor's default
// .vault/ipa-identity.yaml or a freeipa_roster_file, as it is now — which
// may hold only scalars. Every name of a file that is one is listed.
func rosterLike(dir string, entries []managedFileEntry) map[string]bool {
	referenced := map[string]bool{}
	for _, path := range rosterCandidates(dir, "", referencedRosterFiles(dir, "")) {
		if key, err := inventory.RosterFileKey(path); err == nil {
			referenced[key] = true
		}
	}
	out := map[string]bool{}
	for _, e := range entries {
		if !e.IsSecret {
			continue
		}
		key, err := inventory.RosterFileKey(filepath.Join(dir, filepath.FromSlash(e.RelPath)))
		if isAnsibleVaultEncrypted(e.Content) || rosterShapedStructure(e.Content) || err == nil && referenced[key] {
			out[e.RelPath] = true
		}
	}
	return out
}

// rosterShapedStructure reports whether content has a top-level key unique
// to the roster schema (rosterShapedKeys) holding a mapping, a list or an
// alias — what the vault editor never writes — rather than a scalar.
func rosterShapedStructure(content []byte) bool {
	doc, err := vaultfile.Parse(content)
	if err != nil {
		return false
	}
	for _, e := range doc.Entries() {
		if rosterShapedKeys[e.Key] && e.Value.Kind != yaml.ScalarNode {
			return true
		}
	}
	return false
}

// rosterEncrypted reports whether a roster file's snapshot or current entry
// (either may be nil) is ansible-vault encrypted.
func rosterEncrypted(wanted, now *managedFileEntry) bool {
	for _, e := range []*managedFileEntry{wanted, now} {
		if e != nil && isAnsibleVaultEncrypted(e.Content) {
			return true
		}
	}
	return false
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
