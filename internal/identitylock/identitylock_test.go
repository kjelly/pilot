package identitylock

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/sshdial"
)

// fakeRemote mimics *sshdial.Lock: its Lost closes when the session ends for
// any reason, Release included. That is the property Held exists to correct:
// a Held that forwarded it would call a clean Release a loss.
type fakeRemote struct {
	lost    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	order   *[]string
	release int
}

func newFakeRemote() *fakeRemote { return &fakeRemote{lost: make(chan struct{})} }

func (r *fakeRemote) Lost() <-chan struct{} { return r.lost }

func (r *fakeRemote) drop() { r.once.Do(func() { close(r.lost) }) }

func (r *fakeRemote) Release() error {
	r.mu.Lock()
	r.release++
	if r.order != nil {
		*r.order = append(*r.order, "release")
	}
	r.mu.Unlock()
	r.drop()
	return nil
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// waitClosed fails unless ch closes soon: the watcher goroutine is
// asynchronous, Active is not.
func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not close", what)
	}
}

func TestHeldActiveUntilReleased(t *testing.T) {
	r := newFakeRemote()
	h := New("ipa-1", r)
	if !h.Active() || closed(h.Lost()) || h.Check() != nil {
		t.Fatal("a freshly taken lock is not active")
	}
	if h.Host != "ipa-1" {
		t.Fatalf("Host = %q", h.Host)
	}
	if err := h.Release(); err != nil {
		t.Fatal(err)
	}
	if h.Active() {
		t.Fatal("Active after Release")
	}
	// The discriminating case: the remote's Lost IS closed here (the real one
	// closes on Release too), and Held.Lost must still not be, or a gate that
	// reads it would call a clean end of the run a loss.
	if !closed(r.Lost()) {
		t.Fatal("the fake remote's Lost did not close on Release: the test would prove nothing")
	}
	time.Sleep(50 * time.Millisecond) // let the watcher see the remote's Lost
	if closed(h.Lost()) {
		t.Fatal("Held.Lost closed after Release: it must close only when the lock is lost")
	}
	// Check is for a command that ran under the lock; after Release none does.
	// It is an error, and not a loss: nothing was interleaved.
	if err := h.Check(); err == nil || errors.Is(err, ErrLockLost) {
		t.Fatalf("Check after Release = %v, want an error that is not ErrLockLost", err)
	}
}

func TestHeldLostWhenTheSessionEndsWithoutRelease(t *testing.T) {
	r := newFakeRemote()
	h := New("ipa-1", r)
	r.drop()
	// Active reads the session itself, so it is false at once, before the
	// watcher has had a chance to run.
	if h.Active() {
		t.Fatal("Active after the session ended")
	}
	waitClosed(t, h.Lost(), "Held.Lost")
	err := h.Check()
	if !errors.Is(err, ErrLockLost) {
		t.Fatalf("Check = %v, want ErrLockLost", err)
	}
	if want := "ipa-1: lock lost; FreeIPA may be partially reconciled; rerun"; err.Error() != want {
		t.Fatalf("Check message = %q, want %q", err, want)
	}
	// Releasing a lost lock is allowed and still ends the Dialer.
	closedDialer := 0
	h2 := New("ipa-1", newFakeRemote(), func() { closedDialer++ })
	h2.remote.(*fakeRemote).drop()
	_ = h2.Release()
	if closedDialer != 1 {
		t.Fatalf("closers ran %d times after a lost lock was released", closedDialer)
	}
}

func TestHeldReleaseIsIdempotentAndRunsClosersAfterTheRemote(t *testing.T) {
	r := newFakeRemote()
	var order []string
	r.order = &order
	h := New("ipa-1", r,
		func() { order = append(order, "close-1") },
		func() { order = append(order, "close-2") })
	for i := 0; i < 3; i++ {
		if err := h.Release(); err != nil {
			t.Fatal(err)
		}
	}
	if want := []string{"release", "close-1", "close-2"}; !slices.Equal(order, want) {
		t.Fatalf("order = %v, want %v (once, remote first)", order, want)
	}
}

func TestBindCancelsOnLossWithTheCauseAndAttachNever(t *testing.T) {
	r := newFakeRemote()
	h := New("ipa-1", r)
	attached := h.Attach(context.Background())
	bound, cancel := h.Bind(context.Background())
	defer cancel()
	if HeldFrom(attached) != h || HeldFrom(bound) != h || HeldFrom(context.Background()) != nil {
		t.Fatal("HeldFrom does not return the token Attach and Bind carry")
	}
	if bound.Err() != nil || attached.Err() != nil {
		t.Fatal("a context from a lock that is held is already cancelled")
	}
	r.drop()
	waitClosed(t, bound.Done(), "the bound context")
	if cause := context.Cause(bound); !errors.Is(cause, ErrLockLost) {
		t.Fatalf("cause = %v, want ErrLockLost", cause)
	}
	if attached.Err() != nil {
		t.Fatal("the attached context was cancelled by the loss: the evidence writes that use it would fail")
	}
	// What the lock's loss must never do to a context that Attach made, it must
	// not do to its children either (the step evidence context derives from it).
	child, cancelChild := context.WithTimeout(attached, time.Minute)
	defer cancelChild()
	time.Sleep(20 * time.Millisecond)
	if child.Err() != nil {
		t.Fatalf("a child of the attached context: %v", child.Err())
	}
}

func TestBindIsNotCancelledByRelease(t *testing.T) {
	r := newFakeRemote()
	h := New("ipa-1", r)
	bound, cancel := h.Bind(context.Background())
	defer cancel()
	if err := h.Release(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := bound.Err(); err != nil {
		t.Fatalf("a clean Release cancelled the bound context: %v", err)
	}
	cancel()
	if err := bound.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("the CancelFunc did not cancel: %v", err)
	}
	if cause := context.Cause(bound); errors.Is(cause, ErrLockLost) {
		t.Fatalf("a deliberate cancel reads as a lost lock: %v", cause)
	}
}

func TestBindOfALostLockIsAlreadyCancelled(t *testing.T) {
	r := newFakeRemote()
	h := New("ipa-1", r)
	r.drop()
	bound, cancel := h.Bind(context.Background())
	defer cancel()
	if bound.Err() == nil || !errors.Is(context.Cause(bound), ErrLockLost) {
		t.Fatalf("err = %v, cause = %v: a command bound to a lock that is gone must not start", bound.Err(), context.Cause(bound))
	}
}

// Require is how a step inside a run whose owner took the lock gets it: the
// token Attach or Bind carried, refused when there is none and when the lock is
// no longer usable. Each refusal is a different one (ErrNoLock, ErrLockLost, the
// released lock), and the usable lock is the very *Held the owner holds, not a
// copy: a second session on the same server would be a second lock.
func TestRequireReturnsTheRunsLockAndRefusesWhatIsNotUsable(t *testing.T) {
	r := newFakeRemote()
	h := New("ipa-1", r)
	bound, cancel := h.Bind(context.Background())
	defer cancel()
	for name, ctx := range map[string]context.Context{"Attach": h.Attach(context.Background()), "Bind": bound} {
		got, err := Require(ctx)
		if err != nil || got != h {
			t.Fatalf("%s: Require = %v, %v, want the owner's lock", name, got, err)
		}
	}

	if got, err := Require(context.Background()); !errors.Is(err, ErrNoLock) || got != nil {
		t.Fatalf("no lock in the context: Require = %v, %v, want ErrNoLock", got, err)
	}

	lost := New("ipa-2", newFakeRemote())
	lostCtx := lost.Attach(context.Background())
	lost.remote.(*fakeRemote).drop()
	if got, err := Require(lostCtx); !errors.Is(err, ErrLockLost) || got != nil {
		t.Fatalf("a lost lock: Require = %v, %v, want ErrLockLost", got, err)
	}

	released := New("ipa-3", newFakeRemote())
	releasedCtx := released.Attach(context.Background())
	if err := released.Release(); err != nil {
		t.Fatal(err)
	}
	got, err := Require(releasedCtx)
	if err == nil || got != nil || errors.Is(err, ErrNoLock) || errors.Is(err, ErrLockLost) {
		t.Fatalf("a released lock: Require = %v, %v, want the 'already released' refusal, which is neither a missing nor a lost lock", got, err)
	}
}

// Held over the real sshdial.Lock (the fake ssh runs the remote command
// locally, flock and all): a clean Release is not a loss and frees the lock;
// Dialer.Close, which ends the session the way a dropped connection does, is.
func TestHeldOverARealSSHLock(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock not installed")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "ssh")
	script := "#!/bin/bash\nwhile [ \"$#\" -gt 0 ] && [ \"$1\" != \"--\" ]; do shift; done\nshift 2\nexec sh -c \"$*\"\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	lockPath := t.TempDir()
	ctx := context.Background()
	take := func(wait time.Duration) (*Held, *sshdial.Dialer, error) {
		d := &sshdial.Dialer{Target: sshdial.Target{Host: "ipa1.example.test"}, SSH: fake}
		l, err := d.AcquireLock(ctx, sshdial.LockOptions{Path: lockPath, Wait: wait})
		if err != nil {
			d.Close()
			return nil, nil, err
		}
		return New("ipa-1", l, d.Close), d, nil
	}

	held, _, err := take(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := take(0); !errors.Is(err, sshdial.ErrLockBusy) {
		t.Fatalf("second take = %v, want ErrLockBusy while held", err)
	}
	if !held.Active() {
		t.Fatal("not Active while the real lock is held")
	}
	if err := held.Release(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if held.Active() || closed(held.Lost()) {
		t.Fatalf("after a clean Release: Active = %v, Lost closed = %v", held.Active(), closed(held.Lost()))
	}

	again, d, err := take(0)
	if err != nil {
		t.Fatalf("take after Release: %v", err)
	}
	bound, cancel := again.Bind(ctx)
	defer cancel()
	d.Close() // the session ends without Release: a dropped connection
	waitClosed(t, again.Lost(), "Held.Lost after the session was ended")
	waitClosed(t, bound.Done(), "the bound context")
	if !errors.Is(context.Cause(bound), ErrLockLost) || again.Active() {
		t.Fatalf("cause = %v, Active = %v", context.Cause(bound), again.Active())
	}
	// The lock really is free again, so another run can have it: that is why
	// nothing may be written once Active is false.
	third, _, err := take(0)
	if err != nil {
		t.Fatalf("take after the session ended: %v", err)
	}
	_ = third.Release()
}

func TestIsApplyPlaybook(t *testing.T) {
	for p, want := range map[string]bool{
		"playbooks/apply/freeipa-identity-apply.yml":        true,
		"/work/playbooks/apply/freeipa-identity-apply.yml":  true,
		"freeipa-identity-apply.yml":                        true,
		"./playbooks/apply/freeipa-identity-apply.yml":      true,
		"playbooks/apply/freeipa-server-apply.yml":          false,
		"playbooks/apply/freeipa-identity-auth-cache.yml":   false,
		"playbooks/apply/freeipa-identity-apply.yml.bak":    false,
		"playbooks/apply/not-freeipa-identity-apply.yml":    false,
		"playbooks/site.yml":                                false,
		"":                                                  false,
		"playbooks/apply/freeipa-identity-apply.yml/other":  false,
		"playbooks/test/fixtures/freeipa-identity-fixtures": false,
	} {
		if got := IsApplyPlaybook(p); got != want {
			t.Errorf("IsApplyPlaybook(%q) = %v, want %v", p, got, want)
		}
	}
}
