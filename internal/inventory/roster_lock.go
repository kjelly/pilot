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
// opened, it is a symlink, or opening or flocking it fails for any other
// reason (a read-only file system, no space, no lock support) — as opposed
// to being held (ErrMutationLocked). Either way nothing was read or
// written; the message says what to fix.
var ErrRosterLockFile = errors.New("inventory: roster lock file unusable")

// fileFault, when set, makes the lock-file and roster opens, the flock
// and resolving a roster's path below fail with the error it returns for
// an operation ("open", "flock", "resolve") on a path: how tests produce
// errors a real file system gives rarely (EROFS, EIO, ENOSPC). It is the
// one fault seam for these operations, inside this package and out
// (InjectFileFault). Nil in production.
var fileFault func(op, path string) error

// InjectFileFault makes the roster lock-file and roster opens and flocks
// fail as fault says, until restore is called — for tests outside this
// package that must see how pilot handles EROFS, EIO and the like. fault
// returns nil to let an operation run. Never call it outside a test.
func InjectFileFault(fault func(op, path string) error) (restore func()) {
	old := fileFault
	fileFault = fault
	return func() { fileFault = old }
}

// resolveRoster is secretpath.Canonical(path), which fileFault can make
// fail ("resolve") with an error no sentinel classifies: how tests check
// that a caller refuses on an error it does not recognise.
func resolveRoster(path string) (string, error) {
	if fileFault != nil {
		if fault := fileFault("resolve", path); fault != nil {
			return "", fault
		}
	}
	return secretpath.Canonical(path)
}

// faultAfterOpen applies fileFault to an open of path that returned f,
// err: an injected error closes f and replaces err.
func faultAfterOpen(path string, f *os.File, err error) (*os.File, error) {
	if fileFault == nil {
		return f, err
	}
	if fault := fileFault("open", path); fault != nil {
		if f != nil {
			f.Close()
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: fault}
	}
	return f, err
}

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
	// created is true when this acquisition created the lock file.
	created bool
}

// openLockFile is every open of a roster's lock file — its callers pass
// lockFileOpenFlags — and applies fileFault, so a test can make any of
// them fail with a chosen error.
func openLockFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flag, perm)
	return faultAfterOpen(path, f, err)
}

// lockFileOpenFlags are added to every open of a lock file. O_NONBLOCK: a
// FIFO planted as the lock file must not hang the open; checkLockFileOpen
// refuses it.
const lockFileOpenFlags = syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK

// acquireMutationLock takes a non-blocking exclusive flock on path,
// creating it if necessary. This is the same advisory-flock-on-a-sidecar-
// file idiom cmd/edit_workspace_lock.go uses for the whole-workspace apply
// lock. Roster writers never call it directly: lockRosterFile takes every
// roster sidecar lock on the file a write will actually change.
//
// The lock file sits in a directory its owner controls while pilot may run
// as root (pilot-cli under `docker run`), so it is never followed through a
// symlink and must be a regular file with no other names: otherwise the pid
// written below would truncate whatever file the link points at. It is
// created with O_EXCL, so created says whether this call made it
// (lockRosterFile then sets its mode, shareLockFile). flock needs no write
// access, so an existing lock file this user may only read — one a
// root-run pilot left, say, or one on a read-only file system — still
// locks; it just gets no pid.
func acquireMutationLock(path string) (*mutationLock, error) {
	f, err := openLockFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|lockFileOpenFlags, 0o600)
	created := err == nil
	if err != nil && !errors.Is(err, fs.ErrExist) {
		if _, statErr := os.Lstat(path); errors.Is(statErr, fs.ErrNotExist) {
			return nil, errLockFileNotCreatable(path, err)
		}
	}
	writable := created
	if !created {
		f, err = openLockFile(path, os.O_RDWR|lockFileOpenFlags, 0)
		writable = err == nil
		// No write access — permission, or a read-only file system: an
		// existing lock file still locks read-only.
		if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS) {
			f, err = openLockFile(path, os.O_RDONLY|lockFileOpenFlags, 0)
			if errors.Is(err, fs.ErrPermission) {
				return nil, errLockFileNotOpenable(path, err)
			}
		}
	}
	if err := checkLockFileOpen(path, f, err); err != nil {
		return nil, err
	}
	if err := flockMutationLock(path, f, syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}

	if writable {
		stampLockFile(f)
	}

	return &mutationLock{file: f, created: created}, nil
}

func errLockFileNotCreatable(path string, err error) error {
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS) {
		return fmt.Errorf("cannot create lock file %s; its directory must be writable by this user: %w: %w", path, ErrRosterLockFile, err)
	}
	return fmt.Errorf("cannot create lock file %s: %w: %w", path, ErrRosterLockFile, err)
}

func errLockFileNotOpenable(path string, err error) error {
	return fmt.Errorf("lock file %s exists but this user cannot open it (left by another user, e.g. a root-run pilot); remove it or give it to this user: %w: %w", path, ErrRosterLockFile, err)
}

// checkLockFileOpen vets the result of opening the lock file path: f must
// be a plain file of its own. It closes f when it refuses it. Every
// refusal is ErrRosterLockFile, whatever the cause (a directory, EIO,
// ENOSPC, …), so no caller mistakes an unusable lock file for something
// it may carry on past (PR #148 round 6, P2-1).
func checkLockFileOpen(path string, f *os.File, err error) error {
	if errors.Is(err, syscall.ELOOP) {
		return fmt.Errorf("lock file %s is a symlink; refusing to follow it (remove it): %w", path, ErrRosterLockFile)
	}
	if err != nil {
		return fmt.Errorf("cannot open lock file %s: %w: %w", path, ErrRosterLockFile, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		return fmt.Errorf("cannot stat lock file %s: %w: %w", path, ErrRosterLockFile, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 {
		f.Close()
		return fmt.Errorf("lock file %s is not a plain file of its own (a device, FIFO or hard link); remove it: %w", path, ErrRosterLockFile)
	}
	return nil
}

// lockContentionWait is how long flockMutationLock keeps trying a lock
// another process holds before reporting ErrMutationLocked. It covers the
// instant ProbeRosterWrite holds a lock file shared, so a plan's probe never
// fails a writer, and stays short enough that a busy roster is still
// reported at once rather than queued behind (PR #148 round 5, P3-a).
// A variable only so tests about refusal, not timing, can shorten it
// (shortLockContentionWait).
var lockContentionWait = 250 * time.Millisecond

// flockMutationLock takes how (LOCK_EX or LOCK_SH) on the open lock file
// f without blocking, trying again for up to lockContentionWait while
// another process holds it: ErrMutationLocked if it still does. Any other
// flock failure (no lock support, say) is ErrRosterLockFile.
func flockMutationLock(path string, f *os.File, how int) error {
	deadline := time.Now().Add(lockContentionWait)
	for delay := 5 * time.Millisecond; ; delay *= 2 {
		err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if fileFault != nil {
			if fault := fileFault("flock", path); fault != nil {
				err = fault
			}
		}
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("cannot lock %s: %w: %w", path, ErrRosterLockFile, err)
		}
		left := time.Until(deadline)
		if left <= 0 {
			return ErrMutationLocked
		}
		time.Sleep(min(delay, left))
	}
}

// ProbeRosterWrite reports whether a write to the roster at path would be
// refused now, without writing anything, creating a lock file or holding
// one past the call, checking what lockRosterFile checks in the order it
// does: ErrRosterNotWritable when the roster itself would be refused
// (openRosterForWrite: the probe opens it for writing without truncating,
// so a file watcher may see an open and a close), then ErrMutationLocked
// when another process holds a lock file — or, for a roster with another
// hard link, the roster's own inode — and ErrRosterLockFile when one could
// not be used; nil otherwise. A plan probes the real roster its
// scratch copy stands in for, so it fails where the apply would. The probe
// takes each existing lock file's flock shared for an instant; a writer
// whose attempt lands in that instant keeps trying (flockMutationLock), so
// the probe never fails it. Like the writer, the probe waits up to
// lockContentionWait for a holder to let go.
func ProbeRosterWrite(path string) error {
	target, err := resolveRoster(path)
	if err != nil {
		return fmt.Errorf("resolve roster %s: %w", path, err)
	}
	f, st, err := openRosterForWrite(target, path)
	if err != nil {
		return err
	}
	if f != nil {
		defer f.Close() // drops the shared inode flock below
	}
	for _, suffix := range rosterLockSuffixes {
		if err := probeMutationLock(target + suffix); err != nil {
			return fmt.Errorf("roster %s: %w", path, err)
		}
	}
	// A roster with another name is locked through its inode too
	// (lockRosterFile): a writer through that name would not meet the
	// sidecars above.
	if f != nil && st.Nlink > 1 {
		if err := flockMutationLock(target, f, syscall.LOCK_SH); err != nil {
			return fmt.Errorf("roster %s: it has other hard links, so its inode is locked too: %w", path, err)
		}
	}
	return nil
}

func probeMutationLock(path string) error {
	f, err := openLockFile(path, os.O_RDONLY|lockFileOpenFlags, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// acquireMutationLock would create it.
		if err := syscall.Access(filepath.Dir(path), 2 /* W_OK */); err != nil {
			return errLockFileNotCreatable(path, err)
		}
		return nil
	case errors.Is(err, fs.ErrPermission):
		return errLockFileNotOpenable(path, err)
	}
	if err := checkLockFileOpen(path, f, err); err != nil {
		return err
	}
	defer f.Close() // drops the shared flock
	return flockMutationLock(path, f, syscall.LOCK_SH)
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
// held on target, the canonical file the caller's path named — and, when
// that file has other hard links, its inode.
type rosterLock struct {
	// path is the caller's spelling, for messages.
	path string
	// target is the file every read, decision and write under this lock
	// must use: a symlinked roster is written where it points, so the link
	// stays a link and every spelling of the file shares one lock.
	target string
	// key is the roster's identity (RosterFileKey): target for a file with
	// one name, an inode key once it has hard links — the one key every
	// name of it records its writes under (roster_journal.go).
	key   string
	locks []*mutationLock
	// identity is the roster itself, opened for writing and flocked
	// exclusively, held only when it had other hard links as it was locked:
	// the sidecar locks are named by path, so two names of one inode hold
	// different ones, and only a lock on the inode excludes both. Nil for a
	// roster with one name, whose name is its identity (a rename changes the
	// inode).
	identity *os.File
}

// afterRosterLockHook runs between taking a roster's locks and checking
// that its path still names the locked file. Tests use it to retarget a
// link in exactly that window; it is nil otherwise.
var afterRosterLockHook func()

// lockRosterFile takes both roster sidecar locks (rosterLockSuffixes) on
// the canonical file path names (secretpath.Canonical), beside that file,
// so every writer of one roster excludes every other however each spells
// its path — through a symlink, a relative link, a chain, or a symlinked
// directory. A roster with other hard links is also locked through its own
// inode (lockRosterInode): a hard link is another name for the file, with
// sidecar lock files of its own, so two names would otherwise write it at
// once. A dangling link fails closed. A lock already held by another
// process returns ErrMutationLocked, as does a path that resolves to a
// different file once the locks are held (retry: the link moved).
//
// A roster writeLockedRoster would refuse (checkRosterWritable:
// ErrRosterNotWritable — not writable by this user, not a regular file) is
// refused before any lock file is created: only someone who may write the
// roster creates a lock file, so one left behind never locks a writer out
// (PR #148 review, P2-1). writeLockedRoster decides again under the lock.
// The lock files get the roster's owner — its directory's for a roster
// about to be created — so a root-run pilot does not lock the owner out,
// and a mode that lets everyone who may write the roster open them
// (shareLockFile). A lock file is never removed after a failure: removing
// one another process holds flocked would let a third lock a new file of
// the same name while the second still holds the old one.
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
	target, err := resolveRoster(path)
	if err != nil {
		return nil, fmt.Errorf("resolve roster %s: %w", path, err)
	}
	ownerPath, exists := target, true
	owner, err := os.Stat(target)
	if errors.Is(err, fs.ErrNotExist) {
		ownerPath, exists = filepath.Dir(target), false
		owner, err = os.Stat(ownerPath)
	}
	if err != nil {
		return nil, fmt.Errorf("roster %s: %w", path, err)
	}
	if _, err := checkRosterWritable(target, path); err != nil {
		return nil, err
	}
	share := lockFileShare(owner, exists, hasPOSIXACL(ownerPath))
	lk := &rosterLock{path: path, target: target, key: target}
	for _, suffix := range rosterLockSuffixes {
		lock, err := acquireMutationLock(target + suffix)
		if err != nil {
			lk.release() //nolint:errcheck
			return nil, fmt.Errorf("roster %s: %w", path, err)
		}
		lk.locks = append(lk.locks, lock)
		keepOwner(lock.file, owner)
		shareLockFile(lock, owner, share)
	}
	if err := lk.lockRosterInode(); err != nil {
		lk.release() //nolint:errcheck
		return nil, fmt.Errorf("roster %s: %w", path, err)
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

// lockRosterInode takes the exclusive flock on the roster's own inode when
// the roster exists and has other hard links, and records its identity key
// (RosterFileKey). It is taken after the sidecars, always in that order, and
// never for a roster with one name: its name is its identity, a rename
// changes the inode, and a file system that cannot flock a roster must keep
// working through its sidecars. Held, ErrMutationLocked; any other failure
// to take it, ErrRosterLockFile — fail closed.
func (lk *rosterLock) lockRosterInode() error {
	f, st, err := openRosterForWrite(lk.target, lk.path)
	if err != nil {
		if errors.Is(err, ErrRosterNotWritable) {
			return err
		}
		return fmt.Errorf("cannot open it to lock its inode: %w: %w", ErrRosterLockFile, err)
	}
	if f == nil {
		return nil
	}
	if st.Nlink <= 1 {
		f.Close()
		return nil
	}
	if err := flockMutationLock(lk.target, f, syscall.LOCK_EX); err != nil {
		f.Close()
		if errors.Is(err, ErrMutationLocked) {
			return fmt.Errorf("it has other hard links, and another process holds it through one of them: %w", err)
		}
		return fmt.Errorf("it has other hard links, so its inode is locked too: %w", err)
	}
	lk.identity, lk.key = f, inodeKey(st)
	return nil
}

// checkNoNewHardLink refuses a write to a roster that gained a hard link
// since it was locked: st is its fstat now. The roster was locked as a file
// with one name, so another name's holder is not excluded, and a write in
// place would change what that holder sees. The caller retries, which then
// locks the inode.
func (lk *rosterLock) checkNoNewHardLink(st *syscall.Stat_t) error {
	if st.Nlink > 1 && lk.identity == nil {
		return fmt.Errorf("roster %s gained a hard link while it was locked, so its other name is not excluded; retry: %w", lk.path, ErrMutationLocked)
	}
	return nil
}

// RosterFileKey is the one identity of the roster file path names, for
// anything that must tell whether two names are one file: the journal that
// records a session's writes and the rollback that groups them. It is the
// canonical path (secretpath.Canonical) of a file with one name or not yet
// created, and "inode:<device>:<inode>" for a regular file with other hard
// links, shared by every name of it. A file's key changes when it gains or
// loses a name; callers treat a key that no longer matches as a file they
// cannot attribute.
func RosterFileKey(path string) (string, error) {
	canonical, err := secretpath.Canonical(path)
	if err != nil {
		return "", err
	}
	var st syscall.Stat_t
	if err := syscall.Stat(canonical, &st); err == nil && st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Nlink > 1 {
		return inodeKey(&st), nil
	}
	return canonical, nil
}

func inodeKey(st *syscall.Stat_t) string {
	return fmt.Sprintf("inode:%d:%d", uint64(st.Dev), uint64(st.Ino)) //nolint:unconvert // Dev is not uint64 on every platform
}

// release drops every lock. Safe to call once, on a partly built lock too.
func (lk *rosterLock) release() error {
	var errs []error
	if lk.identity != nil {
		errs = append(errs, lk.identity.Close())
		lk.identity = nil
	}
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

// lockFileShare is who besides its owner must be able to open a roster's
// lock files: everyone who may write the roster — for a roster not created
// yet, everyone who may create it in its directory — described by info.
// Read is enough: a lock file holds only a pid, and flock needs no write
// access (acquireMutationLock opens a read-only lock file). It returns
// group read when the group class may read or write the roster (write the
// directory), and other read when the other class may, or when it carries
// an access ACL, which may name any user or group.
func lockFileShare(info os.FileInfo, exists, acl bool) os.FileMode {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	groupBits, otherBits := uint32(0o060), uint32(0o006)
	if !exists {
		groupBits, otherBits = 0o020, 0o002
	}
	var share os.FileMode
	if st.Mode&groupBits != 0 {
		share |= 0o040
	}
	if st.Mode&otherBits != 0 || acl {
		share |= 0o004
	}
	return share
}

// shareLockFile lets everyone who may write the roster, described by info,
// open its lock file: share (lockFileShare), and other read as well when
// the lock file is not owned by the roster's owner — keepOwner could not
// give it away, and that owner may be in neither its user nor its group. A
// lock file this call created gets exactly 0600 plus those bits. An
// existing one this user owns (or any, run as root) gets the read bits it
// lacks, so a 0600 lock file an earlier pilot left no longer locks the
// roster's other writers out; nothing else about it changes, and anyone
// else's is left alone.
func shareLockFile(lock *mutationLock, info os.FileInfo, share os.FileMode) {
	roster, ok := info.Sys().(*syscall.Stat_t)
	var st syscall.Stat_t
	if !ok || syscall.Fstat(int(lock.file.Fd()), &st) != nil {
		return
	}
	euid := uint32(os.Geteuid())
	if !lock.created && st.Uid != euid && euid != 0 {
		return
	}
	if st.Uid != roster.Uid {
		share |= 0o004
	}
	current := os.FileMode(st.Mode) & os.ModePerm
	mode := current | share
	if lock.created {
		mode = 0o600 | share
	}
	if mode != current {
		_ = lock.file.Chmod(mode)
	}
}
