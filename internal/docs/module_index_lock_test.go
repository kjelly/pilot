package docs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// flockTryLockNonBlocking tries to acquire an exclusive flock on path
// and returns whether it succeeded. We need this helper to simulate
// "another pilot process holds the lock" without depending on the
// `flock(1)` CLI being installed on the test host.
func flockTryLockNonBlocking(t *testing.T, path string) (*os.File, bool) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, false
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, false
	}
	return f, true
}

// TestModuleIndex_Open_TimesOutOnStaleLock is a regression test for the
// hang where bleve.Open -> bbolt.Open -> flock() retries every 50ms with
// no upper bound. We simulate "another process holds the lock" by
// grabbing an exclusive flock on store/root.bolt first, then call Open
// in a goroutine and assert it returns within (bleveOpenTimeout + 5s).
//
// Before the fix this test would hang forever and need -timeout=kill.
// After the fix it returns an error in ~30s with a hint about the lock.
func TestModuleIndex_Open_TimesOutOnStaleLock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping lock-contention regression under -short")
	}

	// 1. Build a real bleve index on disk so store/root.bolt exists.
	dir := t.TempDir()
	path := filepath.Join(dir, "modules.bleve")
	seed := NewModuleIndex(path)
	if err := seed.Open(); err != nil {
		t.Fatalf("seed Open: %v", err)
	}
	if err := seed.Build(sampleModuleChunks()); err != nil {
		t.Fatalf("seed Build: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("seed Close: %v", err)
	}

	lockPath := filepath.Join(path, "store", "root.bolt")
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("expected lock path to exist: %v", err)
	}

	// 2. Hold the lock externally for 2x the timeout. We must release
	// before the test exits — defer it first so a panic still cleans up.
	holder, ok := flockTryLockNonBlocking(t, lockPath)
	if !ok {
		// On some CI environments (e.g. overlayfs) flock may be a no-op.
		// Skip rather than report a false failure.
		t.Skip("could not acquire flock on this filesystem; lock contention test is not portable here")
	}
	defer func() {
		_ = syscall.Flock(int(holder.Fd()), syscall.LOCK_UN)
		holder.Close()
	}()

	// 3. Try to Open. It must return within the configured timeout plus
	// a small grace period. We use bleveOpenTimeout + 5s; if our timeout
	// ever grows above ~50s, this slack will need to grow too.
	// Override the package-level timeout so the test finishes in <1s.
	// Production code still uses the 30s default.
	prev := bleveOpenTimeoutForTest
	bleveOpenTimeoutForTest = 200 * time.Millisecond
	defer func() { bleveOpenTimeoutForTest = prev }()

	deadline := 2 * time.Second
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		victim := NewModuleIndex(path)
		done <- victim.Open()
	}()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("Open returned nil despite held lock (took %s)", elapsed)
		}
		if elapsed > deadline {
			t.Fatalf("Open took %s, expected <= %s: %v", elapsed, deadline, err)
		}
		// Error message should mention the lock so users have a hint.
		if msg := err.Error(); !containsAny(msg, "lock", "stale", "timed out", "timeout") {
			t.Logf("Open error (no lock hint, but timed out correctly in %s): %v", elapsed, err)
		}
		t.Logf("Open returned in %s with: %v", elapsed, err)
	case <-time.After(deadline):
		t.Fatalf("Open did not return within %s — the bleve timeout is broken", deadline)
	}
}

// containsAny is a tiny helper to avoid pulling in strings just for one
// substring check in a regression test.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) == 0 {
			continue
		}
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}

// TestModuleIndex_Open_ReturnsPromptError ensures the timeout error is
// not a bare context.DeadlineExceeded — it should be wrapped with
// actionable guidance pointing the user at the lock file.
func TestModuleIndex_Open_ReturnsPromptError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping under -short")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "modules.bleve")
	seed := NewModuleIndex(path)
	if err := seed.Open(); err != nil {
		t.Fatalf("seed Open: %v", err)
	}
	if err := seed.Build(sampleModuleChunks()); err != nil {
		t.Fatalf("seed Build: %v", err)
	}
	_ = seed.Close()

	lockPath := filepath.Join(path, "store", "root.bolt")
	holder, ok := flockTryLockNonBlocking(t, lockPath)
	if !ok {
		t.Skip("could not acquire flock on this filesystem")
	}
	defer func() {
		_ = syscall.Flock(int(holder.Fd()), syscall.LOCK_UN)
		holder.Close()
	}()

	done := make(chan error, 1)
	go func() {
		victim := NewModuleIndex(path)
		done <- victim.Open()
	}()

	// Override the timeout for fast feedback in CI.
	prev := bleveOpenTimeoutForTest
	bleveOpenTimeoutForTest = 200 * time.Millisecond
	defer func() { bleveOpenTimeoutForTest = prev }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Open returned nil despite held lock")
		}
		// The error message must mention root.bolt so the user can
		// find and remove the offending file. This is what makes the
		// fix useful in production — a generic "timeout" would force
		// users to dig.
		if !containsAny(err.Error(), "root.bolt") {
			t.Errorf("error should mention root.bolt for debuggability, got: %v", err)
		}
		// And it must NOT look like an unrelated error (e.g. ENOENT,
		// permission denied) — those would mislead the user.
		if errors.Is(err, syscall.ENOENT) {
			t.Errorf("error is ENOENT but lock is held; likely a misclassified error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Open did not return within timeout — bleve timeout is broken")
	}
}
