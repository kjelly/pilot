// roster_write.go is the one way this package puts bytes into a roster
// file: writeLockedRoster, called with the roster's lock held. Every other
// write primitive — the temp files, renames, in-place writes and the
// lock-file stamp — lives here too, so the write policy has one home
// (TestRegression_RosterWritersLockCanonicalTarget enforces it).
package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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

// renameRosterTemp renames writeLockedRoster's temp file over the roster,
// and fallocateRoster reserves room before a write in place grows it:
// variables so a test can make them fail with a chosen error.
var (
	renameRosterTemp = os.Rename
	fallocateRoster  = unix.Fallocate
)

// writeLockedRoster writes data to the roster lk holds, and is the only
// way this package does: every byte written to a roster — replaced, in
// place, or created — is written here. It keeps what a write must not
// change about the file, choosing between two ways of writing:
//
//   - It opens the roster for writing first, without truncating. A roster
//     this user may not write is refused (as an in-place write always was;
//     root still writes a 0400 roster), and anything but a regular file is
//     refused.
//   - Replace: a temp file in the same directory with the roster's mode and
//     owner, renamed over it, so a reader that takes no lock sees the old
//     roster or the new one, never a truncated file. The temp file gets
//     its owner and mode, and its extended attributes are compared with
//     the roster's, before any data goes into it (writeRosterTemp).
//   - In place, through the open file, when replacing would change the
//     file's identity: it has other hard links, it carries a POSIX ACL,
//     this user may not create a temp file in its directory (EACCES/EPERM),
//     the temp file cannot be given the roster's owner and group (a
//     non-root writer of another user's roster), or its extended
//     attributes would differ from the roster's — an ACL inherited from
//     the directory's default ACL, which would widen who may read the
//     roster, or a SELinux label or user.* attribute the roster carries
//     that a new file would not. Any other failure to create or write the
//     temp file (a full disk or quota, no file descriptors) fails the
//     write with the roster unchanged: written in place, it could fail
//     half-way too, leaving a roster neither old nor new.
//   - In place too when the rename itself is refused with EBUSY, EXDEV,
//     EPERM or EACCES: a roster that is a single-file bind mount (pilot-cli
//     under `docker run -v roster:roster`) cannot be renamed over, nor can
//     one in a sticky directory owned by someone else. Any other rename
//     failure fails the write with the roster unchanged.
//
// A write in place that grows the file first reserves the room
// (fallocate, keeping the size), so a full disk or quota fails it before
// any byte changes; a file system without fallocate just writes.
//
// A roster not created yet is written through a temp file renamed into
// place, mode 0600, and — run as root — owned like its directory, as the
// lock files are.
func writeLockedRoster(lk *rosterLock, data []byte) error {
	path := lk.target
	f, st, err := openRosterForWrite(path, lk.path)
	if err != nil {
		return err
	}
	if f == nil {
		return createLockedRoster(lk, data)
	}
	defer f.Close()
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
	if err := writeRosterTemp(tmp, f, data, os.FileMode(st.Mode)&os.ModePerm, int(st.Uid), int(st.Gid)); err != nil {
		tmp.Close()
		if errors.Is(err, errRosterOwnerNotKept) || errors.Is(err, errRosterAttrsDiffer) {
			return writeRosterInPlace(f, data)
		}
		return fmt.Errorf("write roster %s: cannot write its temp file, so it was left unchanged: %w", lk.path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write roster %s: cannot write its temp file, so it was left unchanged: %w", lk.path, err)
	}
	if err := renameRosterTemp(tmpName, path); err != nil {
		if renameRefusedForThisFile(err) {
			return writeRosterInPlace(f, data)
		}
		return fmt.Errorf("write roster %s: cannot replace it, so it was left unchanged: %w", lk.path, err)
	}
	syncDir(filepath.Dir(path))
	return nil
}

// renameRefusedForThisFile reports whether a rename over the roster
// failed because of where the roster is — a mount point (EBUSY), another
// file system (EXDEV), a sticky or otherwise protected directory
// (EPERM/EACCES) — rather than because the write cannot happen at all, so
// writing it in place is the way to keep it.
func renameRefusedForThisFile(err error) bool {
	for _, errno := range []syscall.Errno{syscall.EBUSY, syscall.EXDEV, syscall.EPERM, syscall.EACCES} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

// ErrRosterNotWritable is a roster write refused before anything is
// written: the roster is not writable by this user (a 0400 file, a
// read-only file system), not a regular file, became a symlink, or is a
// path the workspace may not use. PrepareRosterAdminSync and
// ProbeRosterWrite report it before a caller commits to writing anything.
var ErrRosterNotWritable = errors.New("roster cannot be written")

// openRosterForWrite opens the roster at target (shown in messages as
// shown) for writing, without truncating it, and is the one place that
// decides what writeLockedRoster refuses (ErrRosterNotWritable): a path
// the workspace may not use, a roster this user cannot open for writing
// (root still opens a 0400 one), a symlink, and anything but a regular
// file. A roster that does not exist returns a nil file and no error: the
// writer creates it.
func openRosterForWrite(target, shown string) (*os.File, *syscall.Stat_t, error) {
	if err := validateSecretSourceFile(target); err != nil {
		return nil, nil, fmt.Errorf("roster %s: %w: %w", shown, ErrRosterNotWritable, err)
	}
	f, err := os.OpenFile(target, os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil, nil
	case errors.Is(err, fs.ErrPermission), errors.Is(err, syscall.EROFS):
		return nil, nil, fmt.Errorf("roster %s is not writable by this user: %w: %w", shown, ErrRosterNotWritable, err)
	case errors.Is(err, syscall.ELOOP):
		return nil, nil, fmt.Errorf("roster %s became a symlink since it was resolved; retry: %w: %w", shown, ErrRosterNotWritable, err)
	case err != nil:
		return nil, nil, fmt.Errorf("open roster %s: %w: %w", shown, ErrRosterNotWritable, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("stat roster %s: %w", shown, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		f.Close()
		return nil, nil, fmt.Errorf("roster %s is not a regular file: %w", shown, ErrRosterNotWritable)
	}
	return f, &st, nil
}

// checkRosterWritable is what writeLockedRoster would refuse about the
// roster at target (shown in messages as shown), decided by the same
// openRosterForWrite: lockRosterFile and ProbeRosterWrite ask it before
// any lock file exists. A roster not created yet passes.
func checkRosterWritable(target, shown string) error {
	f, _, err := openRosterForWrite(target, shown)
	if f != nil {
		f.Close()
	}
	return err
}

// errRosterOwnerNotKept is writeRosterTemp's refusal when the temp file
// cannot be given the roster's owner, and errRosterAttrsDiffer when its
// extended attributes would not be the roster's; the caller writes in
// place instead.
var (
	errRosterOwnerNotKept = errors.New("cannot give the replacement the roster's owner")
	errRosterAttrsDiffer  = errors.New("the replacement's extended attributes would differ from the roster's")
)

// writeRosterTemp makes tmp the replacement for the open roster: the
// roster's owner and group, then its mode, then — with the mode set, so an
// ACL's mask is final — the same extended attributes as the roster
// (sameXattrs), and only then data. A temp file that inherited a default
// ACL from the directory is refused before it holds anything, so the
// roster's content is never readable by whoever that ACL names, not even
// for the moment before the rename.
func writeRosterTemp(tmp, roster *os.File, data []byte, mode os.FileMode, uid, gid int) error {
	if err := fchownRosterTemp(tmp, uid, gid); err != nil {
		return fmt.Errorf("%w: %w", errRosterOwnerNotKept, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if !sameXattrs(tmp, roster) {
		return errRosterAttrsDiffer
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	return tmp.Sync()
}

// ignoredXattrs are the extended attributes sameXattrs does not compare:
// the kernel's integrity measurement and its signature, which follow the
// file's content rather than anything set on the file.
var ignoredXattrs = map[string]bool{"security.ima": true, "security.evm": true}

// sameXattrs reports whether the open files a and b carry the same
// extended attributes, by name and value — POSIX ACLs (system.posix_acl_*),
// SELinux labels, user.* attributes — apart from ignoredXattrs. A file
// system without extended attributes gives both none. Failing to read
// either side counts as different, so the caller keeps the roster's inode.
func sameXattrs(a, b *os.File) bool {
	ax, err := fileXattrs(a)
	if err != nil {
		return false
	}
	bx, err := fileXattrs(b)
	if err != nil || len(ax) != len(bx) {
		return false
	}
	for name, value := range ax {
		if other, ok := bx[name]; !ok || !bytes.Equal(value, other) {
			return false
		}
	}
	return true
}

// fileXattrs returns the extended attributes of the open file f this
// process may read, but ignoredXattrs.
func fileXattrs(f *os.File) (map[string][]byte, error) {
	fd := int(f.Fd())
	list, err := readXattr(func(buf []byte) (int, error) { return unix.Flistxattr(fd, buf) })
	if errors.Is(err, unix.ENOTSUP) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, name := range strings.Split(string(list), "\x00") {
		if name == "" || ignoredXattrs[name] {
			continue
		}
		value, err := readXattr(func(buf []byte) (int, error) { return unix.Fgetxattr(fd, name, buf) })
		if errors.Is(err, unix.ENODATA) {
			continue // removed since it was listed
		}
		if err != nil {
			return nil, err
		}
		out[name] = value
	}
	return out, nil
}

// readXattr calls read, a listxattr or getxattr, first for the size and
// then into a buffer of that size, again if it grew in between (ERANGE).
func readXattr(read func(buf []byte) (int, error)) ([]byte, error) {
	for {
		n, err := read(nil)
		if err != nil || n == 0 {
			return nil, err
		}
		buf := make([]byte, n)
		n, err = read(buf)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
}

// writeRosterInPlace overwrites the open roster f with data: the file
// keeps its inode, owner, mode, links, ACL and other attributes, at the
// cost of a moment in which a reader without the lock may see it
// half-written. Growing the file, it reserves the room first, keeping the
// size, so ENOSPC or EDQUOT leaves the roster unchanged; where fallocate is
// not supported (EOPNOTSUPP, ENOSYS) it writes regardless. A write that
// fails after that may have left the roster partly written, and says so.
func writeRosterInPlace(f *os.File, data []byte) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return fmt.Errorf("write roster %s: %w; it was left unchanged", f.Name(), err)
	}
	if size := int64(len(data)); size > st.Size {
		err := fallocateRoster(int(f.Fd()), unix.FALLOC_FL_KEEP_SIZE, 0, size)
		if err != nil && !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.ENOSYS) {
			return fmt.Errorf("write roster %s: cannot reserve room for it, so it was left unchanged: %w", f.Name(), err)
		}
	}
	if _, err := f.WriteAt(data, 0); err != nil {
		return fmt.Errorf("write roster %s in place: %w; it may now be partly written, check it by hand", f.Name(), err)
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return fmt.Errorf("write roster %s in place: %w; it may now be partly written, check it by hand", f.Name(), err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("write roster %s in place: written, but not synced to disk: %w", f.Name(), err)
	}
	return nil
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
// mode-0600 file in a new private (0700) directory under the system temp
// directory, and returns its path and a cleanup that removes that
// directory with everything in it: the plaintext, and the lock files and
// temp files a roster writer working on it left there. No name in it is
// predictable to other users, none is shared with anything else, and a
// writer's sweep for stale temp files (sweepRosterTemps) reads only that
// directory, not all of $TMPDIR.
func decryptedScratchFile(plaintext []byte) (string, func(), error) {
	dir, err := os.MkdirTemp("", "pilot-roster-decrypt-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	tmp, err := os.CreateTemp(dir, "roster-*.yaml")
	if err != nil {
		cleanup()
		return "", func() {}, err
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
	return tmp.Name(), cleanup, nil
}

// stampLockFile writes this process's pid into a lock file it holds, for
// people reading it; the flock alone does the locking.
func stampLockFile(f *os.File) {
	info := mutationLockInfo{PID: os.Getpid(), Start: time.Now()}
	data, _ := json.MarshalIndent(info, "", "  ")
	_ = f.Truncate(0)
	_, _ = f.WriteAt(data, 0)
}
