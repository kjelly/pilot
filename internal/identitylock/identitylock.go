// Package identitylock is the token every pilot path that runs the FreeIPA
// identity apply playbook (and, later, the Go writer) holds for the length of
// the run: the exclusive /etc/ipa lock of the FreeIPA server
// (sshdial.Dialer.AcquireLock), kept by one ssh session for as long as the
// run lasts.
//
// Why a lock at all: the playbook's authorization cache journal
// (auth_pending) is read-modify-written by whichever run happens last. Two
// runs interleaved on one server can clear or overwrite an obligation the
// other one still owes, and the client authorization cache is then never
// refreshed after an access revocation
// (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md §4,
// the two interleavings are reproduced by
// cmd/pilot/cmd/identity_lock_interleaving_test.go).
//
// The package holds no policy about which paths must lock; that is the lint
// of cmd/pilot/cmd/identity_lock_funnel_test.go. It holds what a locked run
// needs from the lock:
//
//   - Active: the one question "may I still change FreeIPA?" (held, not
//     released, not lost). Gates ask this, never Lost directly: Lost stays
//     open after Release, so a gate that only looks at it would let a write
//     through after the lock was given back.
//   - Lost: closed only when the session ended without Release.
//   - Attach and Bind: how the token travels in a context. Bind is for the
//     context of a command (ansible-playbook) and cancels it when the lock is
//     lost; Attach is for everything else and never cancels, because the
//     writes that record what a run did (journal, step evidence, the
//     terminal result) fail on a cancelled context and would hide the real
//     outcome behind "evidence failed".
package identitylock

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sync"
)

// ErrLockLost is what a run ends with when the lock's session ended without
// Release: a concurrent run may have interleaved, so whatever the run did to
// FreeIPA cannot be called a clean reconcile. It is the cause of a context
// derived by Bind.
var ErrLockLost = errors.New("lock lost; FreeIPA may be partially reconciled; rerun")

// ErrNoLock is returned by a funnel that was handed no Acquirer. A funnel
// that runs the identity apply playbook refuses before running anything
// rather than run without the lock.
var ErrNoLock = errors.New("identitylock: no lock acquirer: a run of the FreeIPA identity apply playbook must hold the /etc/ipa lock")

// ApplyPlaybook is the identity apply playbook, the one every funnel the lint
// of cmd/pilot/cmd/identity_lock_funnel_test.go knows runs under the lock.
const ApplyPlaybook = "playbooks/apply/freeipa-identity-apply.yml"

// AuthCachePlaybook is the entry playbook that writes and reads the
// authorization cache obligation for the Go writer (Phase 2, P2-3). It is
// named here so the lint treats a reference to it like one to ApplyPlaybook.
const AuthCachePlaybook = "playbooks/apply/freeipa-identity-auth-cache.yml"

// IsApplyPlaybook reports whether p names the identity apply playbook, by its
// file name: playbook paths reach pilot relative to the repository, absolute,
// or with a directory in front.
func IsApplyPlaybook(p string) bool {
	return path.Base(p) == path.Base(ApplyPlaybook)
}

// Acquirer takes the lock, for the funnel that owns the run. It is built by
// the caller of the funnel (cmd resolves the server from the inventory, which
// the packages with funnels cannot do), so that a funnel whose Acquirer is nil
// cannot run: a new caller does not get to forget the lock.
type Acquirer func(ctx context.Context) (*Held, error)

// Remote is what Held needs from the held lock; *sshdial.Lock is one.
type Remote interface {
	// Lost is closed when the session that holds the lock has ended, for any
	// reason (including Release).
	Lost() <-chan struct{}
	// Release gives the lock back and waits for the session to end.
	Release() error
}

// Held is a lock the run holds. The zero value is not usable; New makes one.
// It is safe for concurrent use.
type Held struct {
	// Host is the inventory name of the FreeIPA server the lock is held on
	// (the host's identity, not the address ssh connects to: AGENTS.md §5.13).
	Host string

	remote  Remote
	closers []func()

	mu       sync.Mutex
	released bool
	lost     bool
	lostCh   chan struct{}
	stop     chan struct{}
	relErr   error
}

// New wraps a lock that is already held on host. closers run after Release,
// in order (the Dialer that owns the session, for one).
func New(host string, remote Remote, closers ...func()) *Held {
	h := &Held{Host: host, remote: remote, closers: closers, lostCh: make(chan struct{}), stop: make(chan struct{})}
	go h.watch()
	return h
}

// watch turns the session's end into a loss unless Release ended it.
func (h *Held) watch() {
	select {
	case <-h.remote.Lost():
		h.settle()
	case <-h.stop:
	}
}

// settle decides, once, whether the session's end is a loss. The decision is
// made under the lock Release takes before it gives the lock back, so a
// session that ended because of Release can never be counted as lost, and one
// that ended first is lost whatever Release does after.
func (h *Held) settle() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.released || h.lost {
		return
	}
	h.lost = true
	close(h.lostCh)
}

// Active reports whether the lock is still held: not released and not lost.
// It looks at the session itself, not only at what the watcher has noticed so
// far, so it is false from the moment the session ends.
func (h *Held) Active() bool {
	select {
	case <-h.remote.Lost():
		h.settle()
	default:
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.released && !h.lost
}

// Lost is closed when the lock's session ended without Release. It is not
// closed by Release: use Active to ask whether writing is still allowed.
func (h *Held) Lost() <-chan struct{} { return h.lostCh }

// Check returns nil while the lock is Active, an error wrapping ErrLockLost
// once it was lost, and another error once it was released. A step that ran a
// command under the lock calls it when the command returns: a command that
// exited 0 after the lock was lost did not run under it.
func (h *Held) Check() error {
	if h.Active() {
		return nil
	}
	h.mu.Lock()
	released := h.released
	h.mu.Unlock()
	if released {
		return fmt.Errorf("%s: the lock was already released", h.Host)
	}
	return fmt.Errorf("%s: %w", h.Host, ErrLockLost)
}

// Release gives the lock back, and ends the session's Dialer. It is safe to
// call more than once; later calls return the first one's result.
func (h *Held) Release() error {
	h.mu.Lock()
	if h.released {
		err := h.relErr
		h.mu.Unlock()
		return err
	}
	h.released = true
	close(h.stop)
	h.mu.Unlock()
	err := h.remote.Release()
	for _, closeFn := range h.closers {
		closeFn()
	}
	h.mu.Lock()
	h.relErr = err
	h.mu.Unlock()
	return err
}

type heldKey struct{}

// Attach returns ctx carrying the token (HeldFrom reads it). The returned
// context is never cancelled because the lock was lost: it is for the code
// that must go on recording what the run did after the loss, and for the
// writer, which asks Active before every write instead.
func (h *Held) Attach(ctx context.Context) context.Context {
	return context.WithValue(ctx, heldKey{}, h)
}

// Bind returns ctx carrying the token that is cancelled, with ErrLockLost as
// its cause, when the lock is lost. Use it only for the context of a command
// that must not outlive the lock (ansible-playbook): its result must never
// reach the code that records the run's outcome, whose context stays
// attached, not bound. The CancelFunc must be called when the command is
// done. A lock that is already lost gives a context that is already
// cancelled, so the command is never started.
func (h *Held) Bind(ctx context.Context) (context.Context, context.CancelFunc) {
	bound, cancel := context.WithCancelCause(ctx)
	go func() {
		select {
		case <-h.lostCh:
			cancel(ErrLockLost)
		case <-bound.Done():
		}
	}()
	// Active first: a lock that ended a moment ago and that the watcher has
	// not noticed yet must not hand out a context that is still live.
	if !h.Active() {
		cancel(ErrLockLost)
	}
	return context.WithValue(bound, heldKey{}, h), func() { cancel(context.Canceled) }
}

// HeldFrom returns the token Attach or Bind put in ctx, or nil.
func HeldFrom(ctx context.Context) *Held {
	h, _ := ctx.Value(heldKey{}).(*Held)
	return h
}
