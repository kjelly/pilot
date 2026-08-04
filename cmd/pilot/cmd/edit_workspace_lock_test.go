package cmd

import (
	"errors"
	"testing"
)

func TestAcquireWorkspaceLock_SecondAcquireFailsWhileFirstHeld(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireWorkspaceLock(dir, "session-a")
	if err != nil {
		t.Fatalf("first acquireWorkspaceLock() error = %v", err)
	}
	defer first.release()

	_, err = acquireWorkspaceLock(dir, "session-b")
	if !errors.Is(err, errWorkspaceLocked) {
		t.Fatalf("second acquireWorkspaceLock() error = %v, want errWorkspaceLocked", err)
	}
}

func TestAcquireWorkspaceLock_ReleasedLockCanBeReacquired(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireWorkspaceLock(dir, "session-a")
	if err != nil {
		t.Fatalf("first acquireWorkspaceLock() error = %v", err)
	}
	if err := first.release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}

	second, err := acquireWorkspaceLock(dir, "session-b")
	if err != nil {
		t.Fatalf("acquireWorkspaceLock() after release error = %v", err)
	}
	defer second.release()
}
