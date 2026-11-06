package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identitylock/identitylocktest"
)

// fakeIdentityLock replaces newIdentityLock for the length of a test: the
// funnels of the identity lock gate refuse to run without one, a test of a
// funnel has no FreeIPA server to take /etc/ipa on, and the production
// builder resolves a server from the inventory and runs ssh. It records what
// each funnel asked for (the inventory, the hosts, how long it waits) and
// takes an in-memory lock that tests can lose, make busy and order against
// what the funnel runs.
//
// Tests that are about something else than the lock install it with
// useFakeIdentityLock and ignore it; the tests of the gate itself assert on
// it. Only the lock is faked: host resolution, the target derivation and ssh
// are exercised by identity_lock_test.go with the real builder.
type fakeIdentityLock struct {
	*identitylocktest.Fake
	mu       sync.Mutex
	requests []identityLockRequest
}

func useFakeIdentityLock(t *testing.T) *fakeIdentityLock {
	t.Helper()
	f := &fakeIdentityLock{Fake: &identitylocktest.Fake{Host: "ipa-1"}}
	prev := newIdentityLock
	t.Cleanup(func() { newIdentityLock = prev })
	newIdentityLock = func(req identityLockRequest) identitylock.Acquirer {
		f.mu.Lock()
		f.requests = append(f.requests, req)
		f.mu.Unlock()
		return f.Acquirer()
	}
	return f
}

// Requests are the identityLockRequests the funnels built, in order.
func (f *fakeIdentityLock) Requests() []identityLockRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]identityLockRequest(nil), f.requests...)
}

// onlyRequest is the one lock request a command built: a funnel asks for its
// lock once per run.
func onlyRequest(t *testing.T, f *fakeIdentityLock) identityLockRequest {
	t.Helper()
	reqs := f.Requests()
	if len(reqs) != 1 {
		t.Fatalf("the command built %d lock requests, want 1", len(reqs))
	}
	return reqs[0]
}

// appendEvent adds a line to a log file shared with a fake executable, so
// that what the fake lock saw and what the fake ansible-playbook saw are in
// one order.
func appendEvent(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Error(err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Error(err)
	}
}

func readEvents(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

// writeScript writes an executable into a fresh directory and returns its path.
func writeScript(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
