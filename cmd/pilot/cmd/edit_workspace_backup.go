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
	"fmt"
	"os"
	"path/filepath"
)

// restoreManagedFiles rewrites dir's managed files to exactly match
// snapshot: every snapshot entry is written back verbatim, and any
// managed file present in dir now but absent from snapshot (created by
// the scenario that's being rolled back) is removed.
func restoreManagedFiles(dir string, snapshot []managedFileEntry) error {
	wanted := make(map[string]managedFileEntry, len(snapshot))
	for _, e := range snapshot {
		wanted[e.RelPath] = e
	}

	for _, e := range snapshot {
		full := filepath.Join(dir, filepath.FromSlash(e.RelPath))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return fmt.Errorf("rollback: mkdir for %s: %w", e.RelPath, err)
		}
		if err := os.WriteFile(full, e.Content, 0o644); err != nil {
			return fmt.Errorf("rollback: restore %s: %w", e.RelPath, err)
		}
	}

	current, err := managedFileEntries(dir)
	if err != nil {
		return fmt.Errorf("rollback: re-scan managed files: %w", err)
	}
	for _, e := range current {
		if _, ok := wanted[e.RelPath]; ok {
			continue
		}
		full := filepath.Join(dir, filepath.FromSlash(e.RelPath))
		if err := os.Remove(full); err != nil {
			return fmt.Errorf("rollback: remove %s (created by the failed scenario): %w", e.RelPath, err)
		}
	}
	return nil
}
