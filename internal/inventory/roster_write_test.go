package inventory

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// failRename makes writeLockedRoster's rename fail with errno for t.
func failRename(t *testing.T, errno syscall.Errno) {
	t.Helper()
	renameRosterTemp = func(from, to string) error {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: errno}
	}
	t.Cleanup(func() { renameRosterTemp = os.Rename })
}

// A rename the roster's location refuses — EBUSY for a single-file bind
// mount (pilot-cli under `docker run -v roster:roster`), EXDEV, EPERM or
// EACCES for a sticky or protected directory — writes the roster in place
// instead: same inode, the new content, no temp file left. Before, every
// writer failed there although main wrote such a roster in place (PR #148
// review, P2-2). Any other rename failure fails the write and leaves the
// roster as it was.
func TestWriteLockedRosterWritesInPlaceWhenTheRenameIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		errno   syscall.Errno
		inPlace bool
	}{
		"EBUSY (bind mount)":         {syscall.EBUSY, true},
		"EXDEV":                      {syscall.EXDEV, true},
		"EPERM (sticky directory)":   {syscall.EPERM, true},
		"EACCES":                     {syscall.EACCES, true},
		"EIO":                        {syscall.EIO, false},
		"ENOSPC (directory entry)":   {syscall.ENOSPC, false},
		"EROFS (read-only, at last)": {syscall.EROFS, false},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeLockTestRoster(t)
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			failRename(t, tc.errno)
			err = AppendRosterUser(path, "erin")
			after, statErr := os.Stat(path)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if tc.inPlace {
				if err != nil {
					t.Fatalf("AppendRosterUser() = %v, want the roster written in place", err)
				}
				if !os.SameFile(before, after) || !bytes.Contains(mustRead(t, path), []byte("name: erin")) {
					t.Fatal("not written in place")
				}
				if _, err := ValidateRosterFile(path); err != nil {
					t.Fatalf("roster written in place does not validate: %v", err)
				}
			} else {
				if !errors.Is(err, tc.errno) || !strings.Contains(err.Error(), "left unchanged") {
					t.Fatalf("AppendRosterUser() = %v, want the %v failure with the roster left unchanged", err, tc.errno)
				}
				if !bytes.Equal(mustRead(t, path), []byte(lockTestRoster)) || !os.SameFile(before, after) {
					t.Fatal("roster changed")
				}
			}
			assertNoRosterTemps(t, path)
		})
	}
}

// A write in place that grows the roster reserves the room first, with the
// size kept, so a full disk or quota fails it before any byte changes and
// the error says the roster was left unchanged; where the file system has
// no fallocate it writes as before. A write that does not grow the roster
// reserves nothing (PR #148 review, P2-2).
func TestWriteRosterInPlaceReservesRoomFirst(t *testing.T) {
	failRename(t, syscall.EBUSY) // every write below goes in place
	for name, tc := range map[string]struct {
		errno syscall.Errno
		wrote bool
	}{
		"ENOSPC":     {syscall.ENOSPC, false},
		"EDQUOT":     {syscall.EDQUOT, false},
		"EOPNOTSUPP": {syscall.EOPNOTSUPP, true},
		"ENOSYS":     {syscall.ENOSYS, true},
		"reserved":   {0, true},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeLockTestRoster(t)
			var calls int
			fallocateRoster = func(fd int, mode uint32, off, size int64) error {
				calls++
				if mode != unix.FALLOC_FL_KEEP_SIZE || off != 0 || size <= int64(len(lockTestRoster)) {
					t.Errorf("fallocate(mode %#x, off %d, len %d); want KEEP_SIZE from 0 for the grown roster", mode, off, size)
				}
				if !bytes.Equal(mustRead(t, path), []byte(lockTestRoster)) {
					t.Error("the roster changed before its room was reserved")
				}
				if tc.errno != 0 {
					return tc.errno
				}
				return unix.Fallocate(fd, mode, off, size)
			}
			t.Cleanup(func() { fallocateRoster = unix.Fallocate })
			err := AppendRosterUser(path, "erin")
			if calls != 1 {
				t.Fatalf("fallocate called %d times, want once", calls)
			}
			if !tc.wrote {
				if !errors.Is(err, tc.errno) || !strings.Contains(err.Error(), "left unchanged") {
					t.Fatalf("AppendRosterUser() = %v, want the %v failure with the roster left unchanged", err, tc.errno)
				}
				if !bytes.Equal(mustRead(t, path), []byte(lockTestRoster)) {
					t.Fatal("roster changed")
				}
				return
			}
			if err != nil || !bytes.Contains(mustRead(t, path), []byte("name: erin")) {
				t.Fatalf("AppendRosterUser() = %v; the roster was not written", err)
			}
			if bytes.Contains(mustRead(t, path), []byte{0}) {
				t.Fatal("the roster holds NUL bytes after the write")
			}
		})
	}
	t.Run("a write that does not grow the roster reserves nothing", func(t *testing.T) {
		path := writeLockTestRoster(t)
		fallocateRoster = func(int, uint32, int64, int64) error {
			t.Error("fallocate called for a write that shrinks the roster")
			return nil
		}
		t.Cleanup(func() { fallocateRoster = unix.Fallocate })
		if got, err := SyncRosterAdminPassword(path, "Old-pass_1", "Np_2"); err != nil || got != RosterAdminUpdated {
			t.Fatalf("SyncRosterAdminPassword() = %v, %v", got, err)
		}
		if decodedAdminPassword(t, mustRead(t, path)) != "Np_2" {
			t.Fatal("roster not written")
		}
	})
}

// MutateEncryptedRosterFile no longer claims the original is untouched when
// the install itself fails: writeLockedRoster's error says whether it is.
func TestMutateEncryptedRosterFileReportsTheInstallTruthfully(t *testing.T) {
	requireAnsibleVault(t)
	l := newLockTestLayout(t, rosterWriterCase{body: removeFixture, encrypt: true})
	failRename(t, syscall.EIO)
	err := MutateEncryptedRosterFile(l.link, lockTestVaultPasswordFile(t), func(plaintextPath string) error {
		return RemoveRosterUser(plaintextPath, "dave", RemoveRosterUserOptions{})
	})
	if !errors.Is(err, syscall.EIO) || !strings.Contains(err.Error(), "left unchanged") || strings.Contains(err.Error(), "untouched") {
		t.Fatalf("error = %v, want the rename failure saying the roster was left unchanged", err)
	}
	l.assertUntouched(t)
}

// The temp file that replaces a roster gets the roster's owner and group
// before anything is written into it: a write as root (pilot-cli under
// `docker run`) never leaves the new content in a root-owned file, even
// for a moment (PR #148 review, F3: data was written first).
func TestWriteLockedRosterOwnsTheTempBeforeWritingIt(t *testing.T) {
	path := writeLockTestRoster(t)
	var chowned int
	fchownRosterTemp = func(f *os.File, uid, gid int) error {
		chowned++
		if info, err := f.Stat(); err != nil || info.Size() != 0 {
			t.Errorf("the temp file held %d bytes when it was chowned (err %v), want none", info.Size(), err)
		}
		return f.Chown(uid, gid)
	}
	t.Cleanup(func() { fchownRosterTemp = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) } })
	if err := AppendRosterUser(path, "erin"); err != nil {
		t.Fatal(err)
	}
	if chowned != 1 || !bytes.Contains(mustRead(t, path), []byte("name: erin")) {
		t.Fatalf("chowned %d times; want the roster replaced through one temp file", chowned)
	}
}

// A replacement must not change who may read the roster or what else the
// file carries. A temp file created in a directory with a default ACL
// inherits an access ACL — with the roster's group bits as its mask, a
// named user may read it — and a new file lacks the user.* attributes (or
// SELinux label) the roster has: either way the roster is written in place
// instead, keeping its inode, its lack of an ACL and its attributes. Before,
// the rename gave the roster the inherited ACL and dropped the attributes
// (PR #148 review, F3).
func TestWriteLockedRosterKeepsTheRostersExtendedAttributes(t *testing.T) {
	t.Run("the directory's default ACL is not inherited", func(t *testing.T) {
		path := writeLockTestRoster(t)
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		setPOSIXACL(t, filepath.Dir(path), "system.posix_acl_default", namedUserACL(65534)...)
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if hasPOSIXACL(path) {
			t.Fatal("the roster has an ACL before the write; the test needs one without")
		}
		if err := AppendRosterUser(path, "erin"); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if hasPOSIXACL(path) {
			t.Fatal("the roster carries the directory's default ACL after the write")
		}
		if !os.SameFile(before, after) || after.Mode().Perm() != 0o640 || !bytes.Contains(mustRead(t, path), []byte("name: erin")) {
			t.Fatalf("roster replaced or changed: same inode %v, mode %v", os.SameFile(before, after), after.Mode().Perm())
		}
		assertNoRosterTemps(t, path)
	})
	t.Run("a user.* attribute is kept", func(t *testing.T) {
		path := writeLockTestRoster(t)
		if err := unix.Setxattr(path, "user.pilot-test", []byte("keep me"), 0); err != nil {
			if errors.Is(err, unix.ENOTSUP) {
				t.Skipf("no user.* attributes on %s: %v", filepath.Dir(path), err)
			}
			t.Fatal(err)
		}
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := AppendRosterUser(path, "erin"); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, err := unix.Getxattr(path, "user.pilot-test", buf)
		if err != nil || string(buf[:n]) != "keep me" {
			t.Fatalf("user.pilot-test after the write = %q, %v; want it kept", buf[:max(n, 0)], err)
		}
		if !os.SameFile(before, after) || !bytes.Contains(mustRead(t, path), []byte("name: erin")) {
			t.Fatal("roster with a user.* attribute was replaced instead of written in place")
		}
		assertNoRosterTemps(t, path)
	})
	t.Run("equal attributes: still replaced", func(t *testing.T) {
		path := writeLockTestRoster(t)
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := AppendRosterUser(path, "erin"); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(before, after) {
			t.Fatal("a roster with nothing to keep was written in place, not replaced")
		}
	})
}
