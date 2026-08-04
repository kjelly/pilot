// edit_workspace_copy.go creates an inert, disposable copy of a
// workspace's managed files for a plan run to operate on — see the
// spec's "Plan 不得修改真實 workspace" invariant.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
)

// copyManagedFilesToTemp copies managedFileEntries(dir) into a fresh
// OS-temp-dir location (never nested inside dir — mirrors
// docker_target.go's os.MkdirTemp("", "pilot-img-build-*") pattern for
// "disposable, outside the tracked tree"). Every entry is materialized
// as a plain regular file holding its already-resolved Content, even if
// the source was a symlink: recreating a symlink in the copy would let
// editAgentSession's save path follow it and mutate whatever it points
// at (possibly the original workspace, or something outside it) — an
// inert copy can never do that.
//
// The returned cleanup func removes the temp dir; callers should defer
// it immediately.
func copyManagedFilesToTemp(dir string) (tempDir string, cleanup func(), err error) {
	tempDir, err = os.MkdirTemp("", "pilot-edit-plan-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp workspace: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(tempDir) }

	entries, err := managedFileEntries(dir)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	for _, e := range entries {
		dst := filepath.Join(tempDir, filepath.FromSlash(e.RelPath))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("mkdir for %s: %w", e.RelPath, err)
		}
		if err := os.WriteFile(dst, e.Content, 0o644); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("write temp copy of %s: %w", e.RelPath, err)
		}
	}
	return tempDir, cleanup, nil
}
