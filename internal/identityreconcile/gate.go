package identityreconcile

import (
	"context"
	"fmt"
	"sync"

	"github.com/kjelly/pilot/internal/identitylock"
)

// Gate is the engine's WriteGate (freeiparpc.Config.WriteGate): a write may leave
// only while the run still holds the FreeIPA server's lock and has observed the
// result of the authorization cache entry on that locked host (spec §7.1, §2 I2).
// The lock is asked with Held.Active, through Held.Check, never with Lost: Lost
// stays open after Release, and a gate that only looked at it would let a write
// through after the lock was given back.
//
// It is made by whoever builds the client and handed to Execute, which opens it
// when the entry has been observed and checks it itself before every write too, so
// that a client built with another gate does not take the requirement away.
type Gate struct {
	mu       sync.Mutex
	observed string // inventory host whose entry result was observed; "" before
}

// NewGate returns a gate that refuses every write until the entry's result for
// the run's locked host has been observed.
func NewGate() *Gate { return &Gate{} }

// Check is the freeiparpc.Config.WriteGate function.
func (g *Gate) Check(ctx context.Context, method string) error {
	held := identitylock.HeldFrom(ctx)
	if held == nil {
		return fmt.Errorf("%s: no lock in the context: a write runs under the run's lock only: %w", method, identitylock.ErrNoLock)
	}
	if err := held.Check(); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	g.mu.Lock()
	observed := g.observed
	g.mu.Unlock()
	if observed == "" {
		return fmt.Errorf("%s: the authorization cache entry has not been observed on %s: no write before the obligation is recorded", method, held.Host)
	}
	if observed != held.Host {
		return fmt.Errorf("%s: the entry was observed on %s, the lock is held on %s", method, observed, held.Host)
	}
	return nil
}

// open records that the entry's result for held's host was observed.
func (g *Gate) open(held *identitylock.Held) {
	g.mu.Lock()
	g.observed = held.Host
	g.mu.Unlock()
}

// close makes the gate refuse again: a new run starts with it shut.
func (g *Gate) close() {
	g.mu.Lock()
	g.observed = ""
	g.mu.Unlock()
}
