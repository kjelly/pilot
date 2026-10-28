package inventory

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// hardLinkedRoster is a roster with two names for one inode — what a backup
// tool that hard-links a roster leaves. actual is the file, alias the other
// name; a lock named by path alone would be two locks for one file.
type hardLinkedRoster struct{ actual, alias string }

func newHardLinkedRoster(t *testing.T) hardLinkedRoster {
	t.Helper()
	dir := t.TempDir()
	h := hardLinkedRoster{actual: filepath.Join(dir, "actual.yaml"), alias: filepath.Join(dir, "alias.yaml")}
	if err := os.WriteFile(h.actual, []byte(lockTestRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(h.actual, h.alias); err != nil {
		t.Fatal(err)
	}
	return h
}

// assertUnchanged fails when the roster no longer holds lockTestRoster
// through either of its names.
func (h hardLinkedRoster) assertUnchanged(t *testing.T) {
	t.Helper()
	for _, name := range []string{h.actual, h.alias} {
		if !bytes.Equal(mustRead(t, name), []byte(lockTestRoster)) {
			t.Fatalf("%s changed:\n%s", name, mustRead(t, name))
		}
	}
}

// A roster's lock is a lock on the roster, not on one spelling of it: two
// hard-linked names reach one inode, and the sidecar lock files are named by
// path, so the names must also share a lock on the inode itself. Before, a
// writer through the other name took its own sidecars and wrote the inode in
// place under the first one's feet (PR #148 review of 3a4d4a3 - P2).
func TestHardLinkedRosterNamesShareOneLock(t *testing.T) {
	shortLockContentionWait(t)
	writers := map[string]func(path string) error{
		"append user": func(path string) error { return AppendRosterUser(path, "erin") },
		"admin sync": func(path string) error {
			_, err := SyncRosterAdminPassword(path, "Old-pass_1", "New-pass_2")
			return err
		},
	}
	for _, order := range []struct {
		name         string
		hold, writer func(h hardLinkedRoster) string
	}{
		{"held through the file, written through the alias", func(h hardLinkedRoster) string { return h.actual }, func(h hardLinkedRoster) string { return h.alias }},
		{"held through the alias, written through the file", func(h hardLinkedRoster) string { return h.alias }, func(h hardLinkedRoster) string { return h.actual }},
	} {
		for writerName, write := range writers {
			t.Run(order.name+"/"+writerName, func(t *testing.T) {
				h := newHardLinkedRoster(t)
				release, err := HoldRosterLock(order.hold(h))
				if err != nil {
					t.Fatal(err)
				}
				if err := write(order.writer(h)); !errors.Is(err, ErrMutationLocked) {
					t.Fatalf("write through the other name = %v, want ErrMutationLocked", err)
				}
				h.assertUnchanged(t)
				if err := release(); err != nil {
					t.Fatal(err)
				}
				if err := write(order.writer(h)); err != nil {
					t.Fatalf("write once released: %v", err)
				}
			})
		}
	}
}

// A prepared admin-password sync holds the roster until Commit: an append
// through the other name is refused meanwhile, and once the sync is
// committed the append lands on top of it. Before, the append succeeded in
// the window and Commit then overwrote it: a lost update.
func TestPreparedAdminSyncHoldsEveryNameOfAHardLinkedRoster(t *testing.T) {
	shortLockContentionWait(t)
	h := newHardLinkedRoster(t)
	prepared, err := PrepareRosterAdminSync(h.actual, "Old-pass_1", "New-pass_2")
	if err != nil || prepared.Result != RosterAdminUpdated {
		t.Fatalf("PrepareRosterAdminSync() = %+v, %v", prepared, err)
	}
	if err := AppendRosterUser(h.alias, "erin"); !errors.Is(err, ErrMutationLocked) {
		t.Fatalf("AppendRosterUser(alias) while the sync is prepared = %v, want ErrMutationLocked", err)
	}
	if err := prepared.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := AppendRosterUser(h.alias, "erin"); err != nil {
		t.Fatalf("AppendRosterUser(alias) after the commit: %v", err)
	}
	for _, name := range []string{h.actual, h.alias} {
		got := string(mustRead(t, name))
		if !strings.Contains(got, "New-pass_2") || !strings.Contains(got, "erin") || strings.Contains(got, "Old-pass_1") {
			t.Fatalf("%s lost an update:\n%s", name, got)
		}
	}

	h2 := newHardLinkedRoster(t)
	prepared, err = PrepareRosterAdminSync(h2.actual, "Old-pass_1", "New-pass_2")
	if err != nil {
		t.Fatal(err)
	}
	prepared.Release()
	if err := AppendRosterUser(h2.alias, "erin"); err != nil {
		t.Fatalf("AppendRosterUser(alias) after Release: %v", err)
	}
}

// ProbeRosterWrite asks the same question a writer would, so a roster held
// through one name is refused through the other, and the probe creates no
// lock file for the name it asked about.
func TestProbeRosterWriteRefusesAHardLinkedRosterHeldThroughAnotherName(t *testing.T) {
	shortLockContentionWait(t)
	h := newHardLinkedRoster(t)
	release, err := HoldRosterLock(h.actual)
	if err != nil {
		t.Fatal(err)
	}
	before := dirNames(t, filepath.Dir(h.actual))
	if err := ProbeRosterWrite(h.alias); !errors.Is(err, ErrMutationLocked) {
		t.Fatalf("ProbeRosterWrite(alias) = %v, want ErrMutationLocked", err)
	}
	if after := dirNames(t, filepath.Dir(h.actual)); strings.Join(after, " ") != strings.Join(before, " ") {
		t.Fatalf("the probe changed the directory: %v -> %v", before, after)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := ProbeRosterWrite(h.alias); err != nil {
		t.Fatalf("ProbeRosterWrite(alias) once released = %v", err)
	}
	h.assertUnchanged(t)
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// flockCalls records every flock lockRosterFile and ProbeRosterWrite attempt,
// by the path they lock, until t ends.
func flockCalls(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	t.Cleanup(InjectFileFault(func(op, path string) error {
		if op == "flock" {
			calls = append(calls, path)
		}
		return nil
	}))
	return &calls
}

// A roster with one name has exactly its two sidecar locks, in order, and no
// lock on its inode: the single name is its identity (a rename changes the
// inode), and a file system whose roster cannot be flocked but whose sidecars
// can must keep working. The inode lock appears only once the roster has a
// second name.
func TestRosterInodeLockOnlyWhenTheRosterHasAnotherName(t *testing.T) {
	h := newHardLinkedRoster(t)
	calls := flockCalls(t)

	lk, err := lockRosterFile(h.actual)
	if err != nil {
		t.Fatal(err)
	}
	lk.release() //nolint:errcheck
	want := []string{h.actual + ".pilot-migrate.lock", h.actual + ".pilot-remove.lock", h.actual}
	if strings.Join(*calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("flocks with two names = %v, want the two sidecars then the roster %v", *calls, want)
	}

	if err := os.Remove(h.alias); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	lk, err = lockRosterFile(h.actual)
	if err != nil {
		t.Fatal(err)
	}
	lk.release() //nolint:errcheck
	want = want[:2]
	if strings.Join(*calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("flocks with one name = %v, want only the two sidecars %v", *calls, want)
	}

	*calls = nil
	if err := ProbeRosterWrite(h.actual); err != nil {
		t.Fatal(err)
	}
	for _, path := range *calls {
		if path == h.actual {
			t.Fatalf("the probe locked the inode of a one-name roster: %v", *calls)
		}
	}
}

// A roster's inode that cannot be locked fails closed, as ErrRosterLockFile:
// nothing is written and no lock is left behind.
func TestRosterInodeLockFailureFailsClosed(t *testing.T) {
	h := newHardLinkedRoster(t)
	restore := InjectFileFault(func(op, path string) error {
		if op == "flock" && path == h.actual {
			return syscall.ENOLCK
		}
		return nil
	})
	if err := AppendRosterUser(h.actual, "erin"); !errors.Is(err, ErrRosterLockFile) || !errors.Is(err, syscall.ENOLCK) {
		t.Fatalf("AppendRosterUser() = %v, want ErrRosterLockFile", err)
	}
	if err := ProbeRosterWrite(h.actual); !errors.Is(err, ErrRosterLockFile) {
		t.Fatalf("ProbeRosterWrite() = %v, want ErrRosterLockFile", err)
	}
	h.assertUnchanged(t)
	restore()
	// Nothing stayed locked: the sidecars and the inode are free again.
	if err := AppendRosterUser(h.actual, "erin"); err != nil {
		t.Fatalf("AppendRosterUser() after the fault: %v", err)
	}
}

// A hard link that appears after the lock was taken is a name nobody locked:
// writing in place would change what its holders see. The write is refused
// (retry), the roster untouched.
func TestRosterGainingAHardLinkWhileLockedIsRefused(t *testing.T) {
	path := writeLockTestRoster(t)
	lk, err := lockRosterFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.release() //nolint:errcheck
	alias := path + ".late-alias"
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := checkLockedRosterWritable(lk); !errors.Is(err, ErrMutationLocked) {
		t.Fatalf("checkLockedRosterWritable() = %v, want ErrMutationLocked", err)
	}
	if err := writeLockedRoster(lk, []byte("schema_version: 3\n")); !errors.Is(err, ErrMutationLocked) || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("writeLockedRoster() = %v, want ErrMutationLocked naming the new hard link", err)
	}
	if !bytes.Equal(mustRead(t, path), []byte(lockTestRoster)) || !bytes.Equal(mustRead(t, alias), []byte(lockTestRoster)) {
		t.Fatal("the roster was written through an unlocked name")
	}
}

// RosterFileKey is one identity for one file: the canonical path for a file
// with one name, an inode key shared by every name of a hard-linked file.
func TestRosterFileKey(t *testing.T) {
	h := newHardLinkedRoster(t)
	link := filepath.Join(t.TempDir(), "link.yaml")
	if err := os.Symlink(h.alias, link); err != nil {
		t.Fatal(err)
	}
	keyOf := func(path string) string {
		t.Helper()
		key, err := RosterFileKey(path)
		if err != nil {
			t.Fatalf("RosterFileKey(%s): %v", path, err)
		}
		return key
	}
	if !strings.HasPrefix(keyOf(h.actual), "inode:") || keyOf(h.actual) != keyOf(h.alias) || keyOf(h.alias) != keyOf(link) {
		t.Fatalf("keys of one hard-linked file differ: %q %q %q", keyOf(h.actual), keyOf(h.alias), keyOf(link))
	}
	single := writeLockTestRoster(t)
	if got, want := keyOf(single), canonicalPath(t, single); got != want {
		t.Fatalf("key of a one-name file = %q, want its canonical path %q", got, want)
	}
	missing := filepath.Join(filepath.Dir(single), "not-yet.yaml")
	if got, want := keyOf(missing), canonicalPath(t, missing); got != want {
		t.Fatalf("key of a file not created yet = %q, want %q", got, want)
	}
	if err := os.Remove(h.alias); err != nil {
		t.Fatal(err)
	}
	if got, want := keyOf(h.actual), canonicalPath(t, h.actual); got != want {
		t.Fatalf("key after the other name was removed = %q, want %q", got, want)
	}
}

// Two journals never watch one file, whatever names each gives it: the second
// registration through a hard link of a watched roster is busy, and a write
// through either name is recorded under the one key.
func TestRosterJournalIdentifiesHardLinkedNames(t *testing.T) {
	h := newHardLinkedRoster(t)
	first := openTestJournal(t, []string{h.actual}, nil)
	j, err := JournalRosterWrites([]string{h.alias}, nil)
	if !errors.Is(err, ErrRosterJournalBusy) || j != nil {
		t.Fatalf("JournalRosterWrites(alias) = %v, %v; want ErrRosterJournalBusy", j, err)
	}
	if err := AppendRosterUser(h.alias, "erin"); err != nil {
		t.Fatal(err)
	}
	key, err := RosterFileKey(h.actual)
	if err != nil {
		t.Fatal(err)
	}
	writes := first.Writes()
	if len(writes) != 1 || len(writes[key]) != 1 || string(writes[key][0].Before) != lockTestRoster {
		t.Fatalf("a write through the alias was not recorded under the file's key %q: %+v", key, writes)
	}

	// A journal that watches only one name of the file records a write made
	// through the other.
	h2 := newHardLinkedRoster(t)
	second := openTestJournal(t, []string{h2.alias}, nil)
	if err := AppendRosterUser(h2.actual, "erin"); err != nil {
		t.Fatal(err)
	}
	if len(second.Writes()) != 1 {
		t.Fatalf("a write through the file's other name was not recorded: %+v", second.Writes())
	}
}
