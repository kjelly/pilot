// roster_write.go is the one way this package puts bytes into a roster
// file: writeLockedRoster, called with the roster's lock held. Every other
// write primitive — the temp files, renames, in-place writes and the
// lock-file stamp — lives here too, so the write policy has one home
// (TestRegression_RosterWritersLockCanonicalTarget enforces it).
package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// rosterTempInfix names the temp files writeLockedRoster and the encrypted
// migration create beside a roster: ".<roster>.pilot-tmp-*". Files an older
// pilot left as ".<roster>.migrate-*" are swept the same way.
const rosterTempInfix = ".pilot-tmp-"

// staleRosterTempAge is how old a temp file beside a roster must be before
// sweepRosterTemps removes it: older than any write still in progress.
const staleRosterTempAge = 2 * time.Minute

// createRosterTemp creates the temp files beside a roster. A variable so a
// test can make it fail with a chosen error.
var createRosterTemp = os.CreateTemp

// fchownRosterTemp gives the replacement temp file the roster's owner and
// group. A variable so a test can make it fail as it does for a non-root
// writer of another user's roster.
var fchownRosterTemp = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }

// writeLockedRoster writes data to the roster lk holds, and is the only
// way this package does. It keeps what a write must not change about the
// file, choosing between two ways of writing:
//
//   - It opens the roster for writing first, without truncating. A roster
//     this user may not write is refused (as an in-place write always was;
//     root still writes a 0400 roster), and anything but a regular file is
//     refused.
//   - Replace: a temp file in the same directory with the roster's mode and
//     owner, renamed over it, so a reader that takes no lock sees the old
//     roster or the new one, never a truncated file.
//   - In place, through the open file, when replacing would change the
//     file's identity: it has other hard links, it carries a POSIX ACL,
//     this user may not create a temp file in its directory (EACCES/EPERM),
//     or the temp file cannot be given the roster's owner and group (a
//     non-root writer of another user's roster). Any other failure to
//     create the temp file (a full disk or quota, no file descriptors)
//     fails the write with the roster unchanged: written in place, it
//     could fail half-way too, leaving a roster neither old nor new.
//
// A roster not created yet is written through a temp file renamed into
// place, mode 0600, and — run as root — owned like its directory, as the
// lock files are.
func writeLockedRoster(lk *rosterLock, data []byte) error {
	path := lk.target
	if err := validateSecretSourceFile(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return createLockedRoster(lk, data)
	case errors.Is(err, fs.ErrPermission), errors.Is(err, syscall.EROFS):
		return fmt.Errorf("roster %s is not writable by this user: %w", lk.path, err)
	case errors.Is(err, syscall.ELOOP):
		return fmt.Errorf("roster %s became a symlink while locked; retry: %w", lk.path, err)
	case err != nil:
		return fmt.Errorf("open roster %s: %w", lk.path, err)
	}
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return fmt.Errorf("stat roster %s: %w", lk.path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return fmt.Errorf("roster %s is not a regular file", lk.path)
	}
	if st.Nlink > 1 || hasPOSIXACL(path) {
		return writeRosterInPlace(f, data)
	}
	tmp, err := createRosterTemp(filepath.Dir(path), "."+filepath.Base(path)+rosterTempInfix+"*")
	switch {
	case errors.Is(err, fs.ErrPermission):
		return writeRosterInPlace(f, data)
	case err != nil:
		return fmt.Errorf("write roster %s: cannot create its temp file, so it was left unchanged: %w", lk.path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // a no-op once renamed
	if err := writeRosterTemp(tmp, data, os.FileMode(st.Mode)&os.ModePerm, int(st.Uid), int(st.Gid)); err != nil {
		tmp.Close()
		if errors.Is(err, errRosterOwnerNotKept) {
			return writeRosterInPlace(f, data)
		}
		return fmt.Errorf("write roster %s: %w", lk.path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write roster %s: %w", lk.path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("write roster %s: %w", lk.path, err)
	}
	syncDir(filepath.Dir(path))
	return nil
}

// errRosterOwnerNotKept is writeRosterTemp's refusal when the temp file
// cannot be given the roster's owner; the caller writes in place instead.
var errRosterOwnerNotKept = errors.New("cannot give the replacement the roster's owner")

func writeRosterTemp(tmp *os.File, data []byte, mode os.FileMode, uid, gid int) error {
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if err := fchownRosterTemp(tmp, uid, gid); err != nil {
		return fmt.Errorf("%w: %w", errRosterOwnerNotKept, err)
	}
	return tmp.Sync()
}

// writeRosterInPlace overwrites the open roster f with data: the file
// keeps its inode, owner, mode, links and ACL, at the cost of a moment in
// which a reader without the lock may see it half-written.
func writeRosterInPlace(f *os.File, data []byte) error {
	if _, err := f.WriteAt(data, 0); err != nil {
		return fmt.Errorf("write roster %s: %w", f.Name(), err)
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return fmt.Errorf("write roster %s: %w", f.Name(), err)
	}
	return f.Sync()
}

// createLockedRoster writes the new roster lk holds: mode 0600, owned —
// when run as root — like its directory.
func createLockedRoster(lk *rosterLock, data []byte) error {
	path := lk.target
	dir := filepath.Dir(path)
	parent, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("create roster %s: %w", path, err)
	}
	tmp, err := createRosterTemp(dir, "."+filepath.Base(path)+rosterTempInfix+"*")
	if err != nil {
		return fmt.Errorf("create roster %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("create roster %s: %w", path, err)
	}
	keepOwner(tmp, parent)
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("create roster %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("create roster %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("create roster %s: %w", path, err)
	}
	syncDir(dir)
	return nil
}

// hasPOSIXACL reports whether path carries an access ACL, which a rename
// would drop.
func hasPOSIXACL(path string) bool {
	n, err := syscall.Getxattr(path, "system.posix_acl_access", nil)
	return err == nil && n > 0
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// rosterScratchFile is a new, empty, mode-0600 temp file beside the roster
// lk holds, named so sweepRosterTemps removes it if pilot dies before its
// caller does. The encrypted migration encrypts its candidate in it.
func rosterScratchFile(lk *rosterLock) (*os.File, error) {
	return createRosterTemp(filepath.Dir(lk.target), "."+filepath.Base(lk.target)+rosterTempInfix+"*")
}

// sweepRosterTemps removes temp files a killed pilot left beside target —
// regular files only, never followed, and only once older than
// staleRosterTempAge, so a write still in progress keeps its own. Called
// with the roster's lock held (lockRosterFile).
func sweepRosterTemps(target string) {
	dir, base := filepath.Dir(target), filepath.Base(target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "."+base+rosterTempInfix) && !strings.HasPrefix(name, "."+base+".migrate-") {
			continue
		}
		full := filepath.Join(dir, name)
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() || time.Since(info.ModTime()) < staleRosterTempAge {
			continue
		}
		_ = os.Remove(full)
	}
}

// decryptedScratchFile writes plaintext — a decrypted roster — to a new
// mode-0600 temp file in the system temp directory and returns its path and
// a cleanup that removes it, along with any roster lock files a writer
// left beside it (nothing else can know their names).
func decryptedScratchFile(plaintext []byte) (string, func(), error) {
	tmp, err := os.CreateTemp("", ".pilot-roster-decrypt-*.yaml")
	if err != nil {
		return "", func() {}, err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		os.Remove(tmpPath)
		for _, suffix := range rosterLockSuffixes {
			os.Remove(tmpPath + suffix)
		}
	}
	if _, err := tmp.Write(plaintext); err != nil {
		tmp.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return tmpPath, cleanup, nil
}

// stampLockFile writes this process's pid into a lock file it holds, for
// people reading it; the flock alone does the locking.
func stampLockFile(f *os.File) {
	info := mutationLockInfo{PID: os.Getpid(), Start: time.Now()}
	data, _ := json.MarshalIndent(info, "", "  ")
	_ = f.Truncate(0)
	_, _ = f.WriteAt(data, 0)
}
