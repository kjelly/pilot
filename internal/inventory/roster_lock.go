package inventory

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kjelly/pilot/internal/secretpath"
)

// ErrMutationLocked is returned by acquireMutationLock when another live
// process already holds the lock at path. A migration that hits this must
// fail fast rather than queue: see MigrateRosterFile, which must not
// create a backup or touch the roster once this happens.
var ErrMutationLocked = errors.New("inventory: already locked by another process")

// ErrRosterLockFile wraps every reason a roster's lock file cannot be used
// at all — its directory refuses a new one, an existing one cannot be
// opened, or it is a symlink — as opposed to being held (ErrMutationLocked).
// Either way nothing was read or written; the message says what to fix.
var ErrRosterLockFile = errors.New("inventory: roster lock file unusable")

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
// lock. Roster writers never call it directly: lockRosterFile takes every
// roster sidecar lock on the file a write will actually change.
//
// The lock file sits in a directory its owner controls while pilot may run
// as root (pilot-cli under `docker run`), so it is never followed through a
// symlink and must be a regular file with no other names: otherwise the pid
// written below would truncate whatever file the link points at. flock
// needs no write access, so an existing lock file this user may only read —
// one a root-run pilot left, say — still locks; it just gets no pid.
func acquireMutationLock(path string) (*mutationLock, error) {
	// O_NONBLOCK: a FIFO planted as the lock file must not hang the open;
	// the fstat below refuses it.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0o600)
	writable := err == nil
	if errors.Is(err, fs.ErrPermission) {
		if _, statErr := os.Lstat(path); errors.Is(statErr, fs.ErrNotExist) {
			return nil, fmt.Errorf("cannot create lock file %s; its directory must be writable by this user: %w: %w", path, ErrRosterLockFile, err)
		}
		f, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
		if errors.Is(err, fs.ErrPermission) {
			return nil, fmt.Errorf("lock file %s exists but this user cannot open it (left by another user, e.g. a root-run pilot); remove it or give it to this user: %w: %w", path, ErrRosterLockFile, err)
		}
	}
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("lock file %s is a symlink; refusing to follow it (remove it): %w", path, ErrRosterLockFile)
	}
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		return nil, fmt.Errorf("stat lock file %s: %w", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("lock file %s is not a plain file of its own (a device, FIFO or hard link); remove it: %w", path, ErrRosterLockFile)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrMutationLocked
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}

	if writable {
		stampLockFile(f)
	}

	return &mutationLock{file: f}, nil
}

// release closes the lock file, dropping the flock. Safe to call exactly
// once; callers should defer it immediately after a successful
// acquireMutationLock.
func (l *mutationLock) release() error {
	return l.file.Close()
}

// rosterLockSuffixes are the sidecar locks every roster writer takes, in
// this order. Both names predate lockRosterFile — roster migration used
// the first and removal the second — and are kept so an older pilot
// binary working on the same file still conflicts with this one.
var rosterLockSuffixes = []string{".pilot-migrate.lock", ".pilot-remove.lock"}

// rosterLock is what lockRosterFile returns: both roster sidecar locks,
// held on target, the canonical file the caller's path named.
type rosterLock struct {
	// path is the caller's spelling, for messages.
	path string
	// target is the file every read, decision and write under this lock
	// must use: a symlinked roster is written where it points, so the link
	// stays a link and every spelling of the file shares one lock.
	target string
	locks  []*mutationLock
}

// afterRosterLockHook runs between taking a roster's locks and checking
// that its path still names the locked file. Tests use it to retarget a
// link in exactly that window; it is nil otherwise.
var afterRosterLockHook func()

// lockRosterFile takes both roster sidecar locks (rosterLockSuffixes) on
// the canonical file path names (secretpath.Canonical), beside that file,
// so every writer of one roster excludes every other however each spells
// its path — through a symlink, a relative link, a chain, or a symlinked
// directory. A dangling link fails closed. A lock already held by another
// process returns ErrMutationLocked, as does a path that resolves to a
// different file once the locks are held (retry: the link moved). The
// lock files get the roster's owner — its directory's for a roster about
// to be created — so a root-run pilot does not lock the owner out.
//
// It is not reentrant: a second lockRosterFile on the same roster from
// the same process fails with ErrMutationLocked, so a writer holding a
// rosterLock must pass it on (the *Locked helpers) rather than call
// another exported writer. Every roster writer in this package goes
// through it (TestRegression_RosterWritersLockCanonicalTarget).
func lockRosterFile(path string) (*rosterLock, error) {
	if err := validateSecretSourceFile(path); err != nil {
		return nil, err
	}
	target, err := secretpath.Canonical(path)
	if err != nil {
		return nil, fmt.Errorf("resolve roster %s: %w", path, err)
	}
	owner, err := os.Stat(target)
	if errors.Is(err, fs.ErrNotExist) {
		owner, err = os.Stat(filepath.Dir(target))
	}
	if err != nil {
		return nil, fmt.Errorf("roster %s: %w", path, err)
	}
	lk := &rosterLock{path: path, target: target}
	for _, suffix := range rosterLockSuffixes {
		lock, err := acquireMutationLock(target + suffix)
		if err != nil {
			lk.release() //nolint:errcheck
			return nil, fmt.Errorf("roster %s: %w", path, err)
		}
		lk.locks = append(lk.locks, lock)
		keepOwner(lock.file, owner)
	}
	// Temp files a killed pilot left beside the roster: the lock is held,
	// so no write of ours is in progress.
	sweepRosterTemps(target)
	if afterRosterLockHook != nil {
		afterRosterLockHook()
	}
	if again, err := secretpath.Canonical(path); err != nil || again != target {
		lk.release() //nolint:errcheck
		return nil, fmt.Errorf("roster %s no longer resolves to %s; retry: %w", path, target, ErrMutationLocked)
	}
	return lk, nil
}

// release drops both locks. Safe to call once, on a partly built lock too.
func (lk *rosterLock) release() error {
	var errs []error
	for i := len(lk.locks) - 1; i >= 0; i-- {
		errs = append(errs, lk.locks[i].release())
	}
	lk.locks = nil
	return errors.Join(errs...)
}

// keepOwner gives the open file f the owner recorded in info after this
// process created or replaced it: under `docker run` as root, a rename or
// a new lock file would otherwise lock the host user out of their own
// roster. It changes f itself, never a path, so a name swapped for a
// symlink meanwhile cannot redirect it. Only root can give a file away,
// and only root needs to; failing that, the group alone is kept where
// possible.
func keepOwner(f *os.File, info os.FileInfo) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	if f.Chown(int(st.Uid), int(st.Gid)) != nil {
		_ = f.Chown(-1, int(st.Gid))
	}
}
