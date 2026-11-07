// Package identitylocktest is a fake FreeIPA identity lock for the tests of
// the funnels (accessgrants, the decommission provider, cmd/pilot/cmd): a test
// of a funnel has no FreeIPA server to take /etc/ipa on, and a funnel that is
// handed no lock refuses to run (identitylock.ErrNoLock), so the tests hand
// it this one. Like internal/gateledger it is imported by tests only:
// cmd/pilot/cmd/identity_lock_funnel_test.go fails when non-test code imports
// it, so the production requirement stays as it is and "run without the lock"
// is not something a test fake can be turned into.
package identitylocktest

import (
	"context"
	"fmt"
	"sync"

	"github.com/kjelly/pilot/internal/identitylock"
)

// Fake takes a lock that exists only in memory. The zero value is usable
// (host "fake-ipa").
type Fake struct {
	// Host is the inventory name the lock reports.
	Host string
	// Err, when not nil, is what the Acquirer returns instead of a lock (a busy
	// server, an inventory it cannot derive an ssh Target from).
	Err error
	// Events, when not nil, receives "lock <host>" when the lock is taken and
	// "release <host>" when it is given back, so that a test can put them in
	// order with what the funnel's runner records.
	Events func(string)
	// OnAcquire, when not nil, runs inside the Acquirer after Events and
	// before the lock is returned: a test that needs to know what the funnel
	// had and had not done by then (an extra-vars file written, a prompt
	// answered) looks at it here.
	OnAcquire func(ctx context.Context)

	mu       sync.Mutex
	acquired int
	released int
	current  *remote
	held     *identitylock.Held
}

func (f *Fake) host() string {
	if f.Host == "" {
		return "fake-ipa"
	}
	return f.Host
}

// remote mimics *sshdial.Lock: Lost closes when the session ends, whatever
// ended it, Release included, so a Held that confused the two would show.
type remote struct {
	fake *Fake
	lost chan struct{}
	once sync.Once
}

func (r *remote) Lost() <-chan struct{} { return r.lost }

func (r *remote) end() { r.once.Do(func() { close(r.lost) }) }

func (r *remote) Release() error {
	r.end()
	r.fake.mu.Lock()
	r.fake.released++
	r.fake.mu.Unlock()
	if r.fake.Events != nil {
		r.fake.Events("release " + r.fake.host())
	}
	return nil
}

// Acquirer returns the identitylock.Acquirer a funnel is handed.
func (f *Fake) Acquirer() identitylock.Acquirer {
	return func(ctx context.Context) (*identitylock.Held, error) {
		if f.Err != nil {
			return nil, f.Err
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("identitylocktest: %w", err)
		}
		r := &remote{fake: f, lost: make(chan struct{})}
		held := identitylock.New(f.host(), r)
		f.mu.Lock()
		f.acquired++
		f.current = r
		f.held = held
		f.mu.Unlock()
		if f.Events != nil {
			f.Events("lock " + f.host())
		}
		if f.OnAcquire != nil {
			f.OnAcquire(ctx)
		}
		return held, nil
	}
}

// Acquired is how many times the lock was taken.
func (f *Fake) Acquired() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.acquired
}

// Released is how many times a lock taken from the Fake was given back.
func (f *Fake) Released() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.released
}

// Held is the lock most recently taken, or nil.
func (f *Fake) Held() *identitylock.Held {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held
}

// Lose ends the session of the lock most recently taken without Release, as a
// dropped network does: Held.Lost fires and Held.Active turns false.
func (f *Fake) Lose() {
	f.mu.Lock()
	r := f.current
	f.mu.Unlock()
	if r != nil {
		r.end()
	}
}
