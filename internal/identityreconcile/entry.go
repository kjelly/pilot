package identityreconcile

import (
	"context"
	"errors"
	"fmt"

	"github.com/kjelly/pilot/internal/identitylock"
)

// Entry is the authorization cache entry the executor depends on: before the first
// write it records the obligation (Prepare), and an idle run reads it (Probe), both
// through the entry playbook (spec §5, §7.2). It is an interface because running
// that playbook is the command layer's work (P2-6); AuthCacheEntry is the one
// implementation, over AuthCacheOutput.Run, which resets the result file itself.
type Entry interface {
	// Prepare runs the entry in prepare mode and returns its verified result: the
	// obligation is recorded on the locked host when it returns without an error.
	Prepare(ctx context.Context) (AuthCacheResult, error)
	// Probe runs the entry in probe mode, which changes nothing, and returns
	// whether an obligation is owed.
	Probe(ctx context.Context) (AuthCacheResult, error)
}

// AuthCacheEntry is an Entry over the result file of one run's locked host.
type AuthCacheEntry struct {
	out  *AuthCacheOutput
	host string
	fqdn string
	run  AuthCacheCommand
}

// NewAuthCacheEntry makes the Entry for the host held's lock is on. fqdn is what
// the lock's own ssh reports for it (sshdial.Dialer.FQDN): the result's fqdn must
// be that one. run is the command layer's one run of the entry playbook, with the
// extra variables it is handed; it takes the lock's Bind context for ansible-playbook,
// as every code that runs a playbook under the lock does.
func NewAuthCacheEntry(out *AuthCacheOutput, held *identitylock.Held, fqdn string, run AuthCacheCommand) (*AuthCacheEntry, error) {
	switch {
	case out == nil || run == nil:
		return nil, errors.New("an authorization cache entry needs its result file and the command that runs the playbook")
	case held == nil || held.Host == "":
		return nil, identitylock.ErrNoLock
	case fqdn == "":
		return nil, errors.New("an authorization cache entry needs the FQDN of the locked host")
	}
	return &AuthCacheEntry{out: out, host: held.Host, fqdn: fqdn, run: run}, nil
}

func (e *AuthCacheEntry) do(ctx context.Context, action AuthCacheAction) (AuthCacheResult, error) {
	res, err := e.out.Run(ctx, AuthCacheWant{Action: action, Host: e.host, FQDN: e.fqdn}, e.run)
	if err != nil {
		return AuthCacheResult{}, fmt.Errorf("authorization cache entry (%s) on %s: %w", action, e.host, err)
	}
	return res, nil
}

// Prepare implements Entry.
func (e *AuthCacheEntry) Prepare(ctx context.Context) (AuthCacheResult, error) {
	return e.do(ctx, AuthCachePrepare)
}

// Probe implements Entry.
func (e *AuthCacheEntry) Probe(ctx context.Context) (AuthCacheResult, error) {
	return e.do(ctx, AuthCacheProbe)
}
