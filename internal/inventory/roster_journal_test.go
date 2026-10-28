package inventory

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/kjelly/pilot/internal/secretpath"
)

// openTestJournal opens a journal on targets and dirs, closed when t ends.
func openTestJournal(t *testing.T, targets, dirs []string) *RosterJournal {
	t.Helper()
	j, err := JournalRosterWrites(targets, dirs)
	if err != nil {
		t.Fatalf("JournalRosterWrites() = %v", err)
	}
	t.Cleanup(j.Close)
	return j
}

func canonicalPath(t *testing.T, path string) string {
	t.Helper()
	c, err := secretpath.Canonical(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// onlyWrite returns the one write j recorded to path, failing t if there
// is not exactly one.
func onlyWrite(t *testing.T, j *RosterJournal, path string) RosterWrite {
	t.Helper()
	writes := j.Writes()
	got := writes[canonicalPath(t, path)]
	if len(got) != 1 || len(writes) != 1 {
		t.Fatalf("journal = %+v; want exactly one write to %s", writes, path)
	}
	return got[0]
}

// Each way writeLockedRoster writes a roster — replaced through a renamed
// temp file, in place (a roster with a second hard link), created — is
// recorded exactly once, with what the roster held before (read under the
// lock) and what it holds after (PR #148 review: a rollback must undo only
// what its session's writes replaced).
func TestRosterJournalRecordsEveryWritePathOnce(t *testing.T) {
	t.Run("replaced", func(t *testing.T) {
		path := writeLockTestRoster(t)
		before, _ := os.Stat(path)
		j := openTestJournal(t, nil, []string{filepath.Dir(path)})
		if err := AppendRosterUser(path, "erin"); err != nil {
			t.Fatal(err)
		}
		if after, _ := os.Stat(path); os.SameFile(before, after) {
			t.Fatal("the roster was not replaced; this case must take the rename path")
		}
		w := onlyWrite(t, j, path)
		if !w.Existed || w.Failed || string(w.Before) != lockTestRoster || !bytes.Equal(w.After, mustRead(t, path)) {
			t.Fatalf("write = %+v", w)
		}
	})
	t.Run("in place", func(t *testing.T) {
		path := writeLockTestRoster(t)
		if err := os.Link(path, path+".second-name"); err != nil {
			t.Fatal(err)
		}
		before, _ := os.Stat(path)
		j := openTestJournal(t, []string{path}, nil)
		if err := AppendRosterUser(path, "erin"); err != nil {
			t.Fatal(err)
		}
		if after, _ := os.Stat(path); !os.SameFile(before, after) {
			t.Fatal("the roster was replaced; this case must write in place")
		}
		w := onlyWrite(t, j, path)
		if !w.Existed || w.Failed || string(w.Before) != lockTestRoster || !bytes.Equal(w.After, mustRead(t, path)) {
			t.Fatalf("write = %+v", w)
		}
	})
	t.Run("created", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ipa-identity.yaml")
		j := openTestJournal(t, nil, []string{dir})
		if err := WriteMinimalRosterSkeleton(path, "admin", "Admin-pass_1"); err != nil {
			t.Fatal(err)
		}
		w := onlyWrite(t, j, path)
		if w.Existed || w.Before != nil || w.Failed || !bytes.Equal(w.After, mustRead(t, path)) {
			t.Fatalf("write = %+v", w)
		}
	})
	t.Run("through a symlink", func(t *testing.T) {
		path := writeLockTestRoster(t)
		link := filepath.Join(t.TempDir(), "alias.yaml")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		j := openTestJournal(t, []string{link}, nil)
		if err := AppendRosterUser(link, "erin"); err != nil {
			t.Fatal(err)
		}
		// Recorded under the file the link names, the key lockRosterFile uses.
		if w := onlyWrite(t, j, path); string(w.Before) != lockTestRoster {
			t.Fatalf("write = %+v", w)
		}
	})
}

// A write in place that stops part-way is recorded Failed, with no After:
// what the roster holds is unknown, so a rollback must not restore over
// it. A write that fails with the roster unchanged is not recorded.
func TestRosterJournalRecordsAFailedWrite(t *testing.T) {
	t.Run("in place, part-way", func(t *testing.T) {
		path := writeLockTestRoster(t)
		if err := os.Link(path, path+".second-name"); err != nil {
			t.Fatal(err)
		}
		original := writeRosterAt
		t.Cleanup(func() { writeRosterAt = original })
		writeRosterAt = func(f *os.File, data []byte, off int64) (int, error) {
			n, _ := f.WriteAt(data[:len(data)/2], off)
			return n, syscall.EIO
		}
		j := openTestJournal(t, []string{path}, nil)
		if err := AppendRosterUser(path, "erin"); !errors.Is(err, syscall.EIO) || !strings.Contains(err.Error(), "partly written") {
			t.Fatalf("AppendRosterUser() = %v, want the part-way failure", err)
		}
		w := onlyWrite(t, j, path)
		if !w.Failed || w.After != nil || !w.Existed || string(w.Before) != lockTestRoster {
			t.Fatalf("write = %+v; want Failed with the roster's bytes before it", w)
		}
	})
	t.Run("unchanged", func(t *testing.T) {
		path := writeLockTestRoster(t)
		failRename(t, syscall.EIO)
		j := openTestJournal(t, []string{path}, nil)
		if err := AppendRosterUser(path, "erin"); !errors.Is(err, syscall.EIO) {
			t.Fatalf("AppendRosterUser() = %v, want the rename failure", err)
		}
		if writes := j.Writes(); len(writes) != 0 {
			t.Fatalf("journal = %+v; a write that changed nothing is not recorded", writes)
		}
	})
}

// A journal records only the rosters it watches, and nothing once closed;
// what it recorded stays readable after Close.
func TestRosterJournalRecordsOnlyWatchedRostersWhileOpen(t *testing.T) {
	watched, other := writeLockTestRoster(t), writeLockTestRoster(t)
	j := openTestJournal(t, []string{watched}, nil)
	if err := AppendRosterUser(other, "erin"); err != nil {
		t.Fatal(err)
	}
	if writes := j.Writes(); len(writes) != 0 {
		t.Fatalf("journal recorded an unwatched roster: %+v", writes)
	}
	if err := AppendRosterUser(watched, "erin"); err != nil {
		t.Fatal(err)
	}
	j.Close()
	if err := AppendRosterUser(watched, "frank"); err != nil {
		t.Fatal(err)
	}
	if w := onlyWrite(t, j, watched); bytes.Contains(w.After, []byte("frank")) {
		t.Fatal("a write after Close was recorded")
	}
	j.Close() // idempotent
}

// Two journals never watch one roster: an overlapping registration —
// the same directory however spelled, a file inside the other's directory,
// the same file — is refused with ErrRosterJournalBusy and watches nothing,
// and succeeds once the first journal is closed. (pilot edit's MCP server
// runs tool calls concurrently; each apply claims its rosters.)
func TestRosterJournalRefusesAnOverlappingRegistration(t *testing.T) {
	dir := t.TempDir()
	roster := filepath.Join(dir, "ipa-identity.yaml")
	if err := os.WriteFile(roster, []byte(lockTestRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(t.TempDir(), "vault-link")
	if err := os.Symlink(dir, linkedDir); err != nil {
		t.Fatal(err)
	}
	first := openTestJournal(t, nil, []string{dir})
	for name, tc := range map[string]struct{ targets, dirs []string }{
		"same directory":           {dirs: []string{dir}},
		"same directory, symlink":  {dirs: []string{linkedDir}},
		"file in the directory":    {targets: []string{roster}},
		"file through the symlink": {targets: []string{filepath.Join(linkedDir, "ipa-identity.yaml")}},
	} {
		t.Run(name, func(t *testing.T) {
			j, err := JournalRosterWrites(tc.targets, tc.dirs)
			if !errors.Is(err, ErrRosterJournalBusy) || j != nil {
				t.Fatalf("JournalRosterWrites() = %v, %v; want ErrRosterJournalBusy", j, err)
			}
			if !strings.Contains(err.Error(), canonicalPath(t, dir)) {
				t.Errorf("error %q does not name the shared path", err)
			}
		})
	}
	if err := AppendRosterUser(roster, "erin"); err != nil {
		t.Fatal(err)
	}
	if len(first.Writes()[canonicalPath(t, roster)]) != 1 {
		t.Fatalf("the first journal lost its roster to a refused registration: %+v", first.Writes())
	}
	first.Close()
	openTestJournal(t, []string{roster}, nil)
}

// A watched roster the writer cannot read is not written: the journal
// could not say what the write replaced.
func TestRosterJournalRefusesAWriteItCannotRecord(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a write-only file")
	}
	path := writeLockTestRoster(t)
	if err := os.Chmod(path, 0o200); err != nil {
		t.Fatal(err)
	}
	lk, err := lockRosterFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.release() //nolint:errcheck
	j := openTestJournal(t, []string{path}, nil)
	if err := writeLockedRoster(lk, []byte("schema_version: 3\n")); !errors.Is(err, ErrRosterNotWritable) || !strings.Contains(err.Error(), "left unchanged") {
		t.Fatalf("writeLockedRoster() = %v, want the write refused", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, path); string(got) != lockTestRoster {
		t.Fatalf("roster written:\n%s", got)
	}
	if writes := j.Writes(); len(writes) != 0 {
		t.Fatalf("journal = %+v", writes)
	}
}
