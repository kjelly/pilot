package inventory

import (
	"bytes"
	"errors"
	"os"
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
