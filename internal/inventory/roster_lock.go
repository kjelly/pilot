package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// ErrMutationLocked is returned by acquireMutationLock when another live
// process already holds the lock at path. A migration that hits this must
// fail fast rather than queue: see MigrateRosterFile, which must not
// create a backup or touch the roster once this happens.
var ErrMutationLocked = errors.New("inventory: already locked by another process")

// mutationLockInfo is written into the lock file for human introspection
// only — the actual mutual exclusion is the flock syscall below, not this
// content, so a stale lock file left behind by a crashed process (whose
// flock the kernel already dropped) can never block a fresh acquisition on
// its own. Mirrors cmd/edit_workspace_lock.go's workspaceLockInfo.
type mutationLockInfo struct {
	PID   int       `json:"pid"`
	Start time.Time `json:"start"`
}

type mutationLock struct {
	file *os.File
}

// acquireMutationLock takes a non-blocking exclusive flock on path,
// creating it if necessary. This is the same advisory-flock-on-a-sidecar-
// file idiom cmd/edit_workspace_lock.go uses for the whole-workspace apply
// lock, extracted here so roster migration doesn't duplicate it — and so
// any other future internal/inventory mutation that needs cross-process
// exclusivity on a single file has somewhere to get it without
// reinventing the syscall handling.
func acquireMutationLock(path string) (*mutationLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrMutationLocked
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}

	info := mutationLockInfo{PID: os.Getpid(), Start: time.Now()}
	data, _ := json.MarshalIndent(info, "", "  ")
	_ = f.Truncate(0)
	_, _ = f.WriteAt(data, 0)

	return &mutationLock{file: f}, nil
}

// release closes the lock file, dropping the flock. Safe to call exactly
// once; callers should defer it immediately after a successful
// acquireMutationLock.
func (l *mutationLock) release() error {
	return l.file.Close()
}
