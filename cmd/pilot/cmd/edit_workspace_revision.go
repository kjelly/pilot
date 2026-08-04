// edit_workspace_revision.go computes a deterministic fingerprint of a
// workspace's managed files — see the spec's "Workspace revision"
// section. Plan and apply compare this before/after to detect a
// workspace changed out from under them (workspace_changed) instead of
// silently overwriting a concurrent edit.
package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// computeWorkspaceRevision hashes managedFileEntries(dir) — relative
// path, file mode (which carries the symlink bit), and content hash,
// in sorted order — using the same "ordered fields, null-byte
// separated, one running sha256" idiom internal/store's evidenceHash
// already uses. Deterministic for a given file set/content, sensitive
// to any managed file changing (including a plain file being replaced
// by a symlink to identical content), and blind to anything outside
// the managed-file set.
func computeWorkspaceRevision(dir string) (string, error) {
	entries, err := managedFileEntries(dir)
	if err != nil {
		return "", fmt.Errorf("compute workspace revision: %w", err)
	}
	h := sha256.New()
	for _, e := range entries {
		contentHash := sha256.Sum256(e.Content)
		for _, field := range []string{e.RelPath, e.Mode.String(), fmt.Sprint(e.IsSymlink), hex.EncodeToString(contentHash[:])} {
			_, _ = h.Write([]byte(field))
			_, _ = h.Write([]byte{0})
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
