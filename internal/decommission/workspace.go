// workspace.go gives Finalize (finalizer.go) its own small, self-contained
// workspace-mutation-lock and snapshot/restore primitives. cmd/pilot/cmd
// already has equivalent machinery (edit_workspace_lock.go,
// edit_workspace_backup.go) built for `pilot edit`'s apply flow, but it is
// unexported in a package that imports internal/decommission — importing
// it back here would be a cycle. This file re-implements the same narrow
// flock idiom on the SAME lock file path (<dir>/.pilot/edit.lock), so a
// concurrent `pilot edit` session and a decommission finalize mutually
// exclude each other (spec.md §23 step 1 / §29), and a snapshot/restore
// pair scoped to exactly the files Finalize can mutate in this phase:
// hosts.yml, inventory.yml, host_vars/<host>.yml (spec.md §24's explicit
// file list, minus the manifests no Phase 2 provider touches yet).
package decommission

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// decommissionLock is a held advisory flock on the workspace's shared
// edit/decommission lock file. Released by closing the fd — a crashed
// process can never wedge it (the kernel drops the lock).
type decommissionLock struct {
	file *os.File
}

// acquireDecommissionLock takes a non-blocking exclusive flock on
// <dir>/.pilot/edit.lock — the same path `pilot edit`'s apply flow uses,
// so the two mutually exclude each other.
func acquireDecommissionLock(dir string) (*decommissionLock, error) {
	lockDir := filepath.Join(dir, ".pilot")
	if err := os.MkdirAll(lockDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", lockDir, err)
	}
	path := filepath.Join(lockDir, "edit.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, newError(ErrFinalizationFailed, "workspace %s is locked by another session (pilot edit or another decommission finalize) — try again once it finishes", dir)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return &decommissionLock{file: f}, nil
}

func (l *decommissionLock) release() error { return l.file.Close() }

// finalizeFileEntry is one snapshotted workspace file's before-state,
// including whether it existed at all (so restore can remove a file the
// failed finalize attempt created).
type finalizeFileEntry struct {
	RelPath string
	Existed bool
	Content []byte
	Mode    os.FileMode
}

// finalizeManagedRelPaths returns the workspace-relative paths Finalize
// may mutate for hostName in this phase.
func finalizeManagedRelPaths(hostName string) []string {
	return []string{"hosts.yml", "inventory.yml", filepath.Join("host_vars", hostName+".yml")}
}

// snapshotWorkspaceFiles reads the current on-disk state of every file
// Finalize might mutate for hostName, so a failure partway can restore
// dir to exactly this state (spec.md §23 "If final workspace generation
// fails ... restore the finalization file set").
func snapshotWorkspaceFiles(dir, hostName string) ([]finalizeFileEntry, error) {
	var out []finalizeFileEntry
	for _, rel := range finalizeManagedRelPaths(hostName) {
		full := filepath.Join(dir, rel)
		data, err := os.ReadFile(full)
		if errors.Is(err, os.ErrNotExist) {
			out = append(out, finalizeFileEntry{RelPath: rel, Existed: false})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", rel, err)
		}
		mode := os.FileMode(0o644)
		if info, statErr := os.Stat(full); statErr == nil {
			mode = info.Mode()
		}
		out = append(out, finalizeFileEntry{RelPath: rel, Existed: true, Content: data, Mode: mode})
	}
	return out, nil
}

// restoreWorkspaceFiles rewrites every snapshotted file back to exactly
// its pre-finalize state, removing any that did not exist before.
func restoreWorkspaceFiles(dir string, snapshot []finalizeFileEntry) error {
	for _, e := range snapshot {
		full := filepath.Join(dir, e.RelPath)
		if !e.Existed {
			if err := os.Remove(full); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("rollback: remove %s: %w", e.RelPath, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return fmt.Errorf("rollback: mkdir for %s: %w", e.RelPath, err)
		}
		if err := os.WriteFile(full, e.Content, e.Mode); err != nil {
			return fmt.Errorf("rollback: restore %s: %w", e.RelPath, err)
		}
	}
	return nil
}
