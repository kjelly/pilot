// edit_workspace_lock.go is pilot_edit_apply's mutation gate — see the
// spec's "Mutation Lock and Rollback" section: "同一 workspace 同時間只
// 允許一個 apply session". It mirrors internal/statefile's existing
// flock idiom (advisory syscall.Flock on a sidecar file, released by
// closing the fd — the kernel drops the lock if the holding process
// dies, so a crash can never wedge it) but with LOCK_NB: apply must
// fail fast rather than queue behind a concurrent session.
package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// errWorkspaceLocked is returned by acquireWorkspaceLock when another
// session already holds dir's lock. The MCP apply handler maps this to
// the workspace_locked error code.
var errWorkspaceLocked = errors.New("workspace is locked by another apply session")

// workspaceLockInfo is written into the lock file for human
// introspection only — the actual mutual exclusion is the flock
// syscall, not this content (spec: "不因單純存在舊 lock file 就永久阻
// 擋；須檢查 owner process 或採 OS file lock").
type workspaceLockInfo struct {
	PID       int       `json:"pid"`
	Start     time.Time `json:"start"`
	SessionID string    `json:"session_id"`
}

type workspaceLock struct {
	file *os.File
}

// acquireWorkspaceLock takes a non-blocking exclusive flock on
// <dir>/.pilot/edit.lock. Returns errWorkspaceLocked (wrapped) if
// another live process already holds it.
func acquireWorkspaceLock(dir, sessionID string) (*workspaceLock, error) {
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
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errWorkspaceLocked
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}

	info := workspaceLockInfo{PID: os.Getpid(), Start: time.Now(), SessionID: sessionID}
	data, _ := json.MarshalIndent(info, "", "  ")
	_ = f.Truncate(0)
	_, _ = f.WriteAt(data, 0)

	return &workspaceLock{file: f}, nil
}

// release closes the lock file, dropping the flock. Safe to call
// exactly once; the caller should defer it immediately after a
// successful acquireWorkspaceLock.
func (l *workspaceLock) release() error {
	return l.file.Close()
}
