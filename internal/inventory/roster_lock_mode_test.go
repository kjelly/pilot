package inventory

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// withUmask runs the rest of t under umask mask, so a lock file's mode is
// what pilot chose, not what the umask happened to leave. This package's
// tests do not run in parallel.
func withUmask(t *testing.T, mask int) {
	t.Helper()
	old := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(old) })
}

// lockFileModes returns the permission bits of target's lock files.
func lockFileModes(t *testing.T, target string) []os.FileMode {
	t.Helper()
	var out []os.FileMode
	for _, suffix := range rosterLockSuffixes {
		info, err := os.Lstat(target + suffix)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, info.Mode().Perm())
	}
	return out
}

// POSIX ACL xattr encoding (linux/posix_acl_xattr.h), for tests that give a
// file or directory an ACL without setfacl.
const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclMask     = 0x10
	aclOther    = 0x20
	aclNoID     = 0xffffffff
)

type aclEntry struct {
	tag, perm uint16
	id        uint32
}

// setPOSIXACL sets name (system.posix_acl_access or _default) on path to
// entries, which must be in the kernel's order (by tag, then id); it skips
// t where the file system has no ACLs.
func setPOSIXACL(t *testing.T, path, name string, entries ...aclEntry) {
	t.Helper()
	value := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range entries {
		value = binary.LittleEndian.AppendUint16(value, e.tag)
		value = binary.LittleEndian.AppendUint16(value, e.perm)
		value = binary.LittleEndian.AppendUint32(value, e.id)
	}
	if err := unix.Setxattr(path, name, value, 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("no POSIX ACLs on %s: %v", filepath.Dir(path), err)
		}
		t.Fatal(err)
	}
}

// namedUserACL is an ACL granting uid read and write besides owner rw,
// group and other nothing.
func namedUserACL(uid uint32) []aclEntry {
	return []aclEntry{
		{aclUserObj, 6, aclNoID},
		{aclUser, 6, uid},
		{aclGroupObj, 0, aclNoID},
		{aclMask, 6, aclNoID},
		{aclOther, 0, aclNoID},
	}
}

// A roster's lock files let in everyone who may write the roster: group
// read when its group class may read or write it, other read when its
// other class may or it carries an ACL — and nothing more than 0600 for a
// roster only its owner may write. A 0600 lock file left beside a shared
// roster by an earlier pilot is repaired. Before, every lock file was 0600
// (a writer's umask could only narrow it), so the first group member to
// write a 0660 roster locked every other member out (PR #148 review, P2-1).
// The umask is 077, the strictest a writer may have.
func TestRosterLockFilesLetTheRostersWritersIn(t *testing.T) {
	withUmask(t, 0o077)
	for name, tc := range map[string]struct {
		roster os.FileMode
		acl    bool
		want   os.FileMode
	}{
		"owner only":             {roster: 0o600, want: 0o600},
		"group may write":        {roster: 0o660, want: 0o640},
		"group may read":         {roster: 0o640, want: 0o640},
		"others may write":       {roster: 0o606, want: 0o604},
		"named user through ACL": {roster: 0o600, acl: true, want: 0o644},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeLockTestRoster(t)
			if tc.acl {
				setPOSIXACL(t, path, "system.posix_acl_access", namedUserACL(65534)...)
			} else if err := os.Chmod(path, tc.roster); err != nil {
				t.Fatal(err)
			}
			if err := AppendRosterUser(path, "erin"); err != nil {
				t.Fatal(err)
			}
			for i, got := range lockFileModes(t, path) {
				if got != tc.want {
					t.Errorf("%s mode = %v, want %v", rosterLockSuffixes[i], got, tc.want)
				}
			}
		})
	}
	t.Run("new roster: who may create it", func(t *testing.T) {
		for dirMode, want := range map[os.FileMode]os.FileMode{0o700: 0o600, 0o750: 0o600, 0o770: 0o640, 0o777: 0o644} {
			dir := t.TempDir()
			if err := os.Chmod(dir, dirMode); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "roster.yaml")
			if err := WriteMinimalRosterSkeleton(path, "admin", "Admin-pass_1"); err != nil {
				t.Fatal(err)
			}
			for i, got := range lockFileModes(t, path) {
				if got != want {
					t.Errorf("directory %v: %s mode = %v, want %v", dirMode, rosterLockSuffixes[i], got, want)
				}
			}
		}
	})
	t.Run("a leftover 0600 lock file of this user's is repaired", func(t *testing.T) {
		path := writeLockTestRoster(t)
		if err := os.Chmod(path, 0o660); err != nil {
			t.Fatal(err)
		}
		for _, suffix := range rosterLockSuffixes {
			if err := os.WriteFile(path+suffix, []byte("left by an older pilot\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := AppendRosterUser(path, "erin"); err != nil {
			t.Fatal(err)
		}
		for i, got := range lockFileModes(t, path) {
			if got != 0o640 {
				t.Errorf("%s mode = %v, want 0640", rosterLockSuffixes[i], got)
			}
		}
	})
}

// Every way of failing to open or flock a lock file other than its being
// a symlink or held — a read-only file system, no space, no lock support —
// is ErrRosterLockFile, for the writer and for the plan's probe alike, so
// pilot edit refuses the vault save instead of saving the vault and
// leaving the roster on the old password (PR #148 review, P2-1). Before,
// these came back unwrapped and the save went ahead.
func TestRosterLockFileFailuresAreErrRosterLockFile(t *testing.T) {
	for name, tc := range map[string]struct {
		existing bool
		inject   func(t *testing.T)
	}{
		"open: read-only file system": {inject: func(t *testing.T) {
			openLockFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
				return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EROFS}
			}
			t.Cleanup(func() { openLockFile = os.OpenFile })
		}},
		"open: no space": {inject: func(t *testing.T) {
			openLockFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
				return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ENOSPC}
			}
			t.Cleanup(func() { openLockFile = os.OpenFile })
		}},
		"open of an existing lock file: I/O error": {existing: true, inject: func(t *testing.T) {
			openLockFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
				if flag&os.O_CREATE != 0 {
					return os.OpenFile(name, flag, perm)
				}
				return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EIO}
			}
			t.Cleanup(func() { openLockFile = os.OpenFile })
		}},
		"flock: no lock support": {existing: true, inject: func(t *testing.T) {
			flockLockFile = func(int, int) error { return syscall.ENOLCK }
			t.Cleanup(func() { flockLockFile = syscall.Flock })
		}},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeLockTestRoster(t)
			if tc.existing {
				lk, err := lockRosterFile(path)
				if err != nil {
					t.Fatal(err)
				}
				lk.release() //nolint:errcheck
			}
			tc.inject(t)
			err := AppendRosterUser(path, "erin")
			if !errors.Is(err, ErrRosterLockFile) || errors.Is(err, ErrMutationLocked) {
				t.Fatalf("writer error = %v, want ErrRosterLockFile", err)
			}
			if !strings.Contains(err.Error(), path+".pilot-") {
				t.Errorf("writer error %q does not name the lock file", err)
			}
			if !bytes.Equal(mustRead(t, path), []byte(lockTestRoster)) {
				t.Fatal("roster changed")
			}
			if err := ProbeRosterWrite(path); !errors.Is(err, ErrRosterLockFile) {
				t.Fatalf("ProbeRosterWrite() = %v; the probe and the writer disagree", err)
			}
		})
	}
}
