// roster_journal.go records, at the one place roster bytes are written
// (writeLockedRoster), every write made to the rosters a caller watches:
// pilot edit's apply opens a RosterJournal on its workspace's .vault/
// before the scenario runs, so its rollback undoes exactly what its own
// writes replaced, read under the roster lock as each write began, rather
// than inferring authorship from how the files differ between steps.
package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"

	"github.com/kjelly/pilot/internal/secretpath"
)

// RosterWrite is one write writeLockedRoster made to a watched roster.
type RosterWrite struct {
	// Before is what the roster held when the write began, read under the
	// roster lock; nil when it did not exist (Existed false).
	Before  []byte
	Existed bool
	// After is what the write left in the roster; nil when Failed.
	After []byte
	// Failed is a write in place that failed after it may have changed
	// the roster (its error wraps errRosterPartlyWritten): what the roster
	// holds is unknown. A write that failed with the roster unchanged is
	// not recorded.
	Failed bool
}

// ErrRosterJournalBusy is JournalRosterWrites refusing a roster another
// open RosterJournal in this process already watches: two applies cannot
// both claim one roster's writes.
var ErrRosterJournalBusy = errors.New("inventory: another pilot edit apply in this process is already recording writes to this roster")

// RosterJournal is a set of watched rosters and the writes made to them
// while it is open (JournalRosterWrites).
type RosterJournal struct {
	// targets are watched canonical files, dirs watched canonical
	// directories: every file directly inside one, existing or not.
	targets, dirs map[string]bool
	writes        map[string][]RosterWrite
	closed        bool
}

// rosterJournals is every open RosterJournal in this process. mu also
// guards each journal's writes and closed.
var rosterJournals struct {
	mu   sync.Mutex
	open []*RosterJournal
}

// JournalRosterWrites starts recording every roster write this process
// makes to targets — files, however spelled — and to any file directly
// inside dirs, until Close. Paths are canonicalized (secretpath.Canonical)
// as lockRosterFile does, so a write through any spelling of a watched
// file is recorded under its canonical path. A target or directory another
// open journal already watches is refused with ErrRosterJournalBusy, and
// nothing is watched.
//
// The journal sees writes, not writers: a roster write any goroutine of
// this process makes is recorded. Another process's writes are not — they
// are what a caller compares the recorded writes with.
func JournalRosterWrites(targets, dirs []string) (*RosterJournal, error) {
	j := &RosterJournal{targets: map[string]bool{}, dirs: map[string]bool{}, writes: map[string][]RosterWrite{}}
	for _, set := range []struct {
		paths []string
		into  map[string]bool
	}{{targets, j.targets}, {dirs, j.dirs}} {
		for _, path := range set.paths {
			canonical, err := secretpath.Canonical(path)
			if err != nil {
				return nil, fmt.Errorf("resolve %s to record writes to it: %w", path, err)
			}
			set.into[canonical] = true
		}
	}
	rosterJournals.mu.Lock()
	defer rosterJournals.mu.Unlock()
	for _, other := range rosterJournals.open {
		if conflict, ok := j.overlap(other); ok {
			return nil, fmt.Errorf("%s: %w; retry once it has finished", conflict, ErrRosterJournalBusy)
		}
	}
	rosterJournals.open = append(rosterJournals.open, j)
	return j, nil
}

// Close stops recording; writes recorded so far stay readable (Writes).
// Safe to call more than once.
func (j *RosterJournal) Close() {
	rosterJournals.mu.Lock()
	defer rosterJournals.mu.Unlock()
	if j.closed {
		return
	}
	j.closed = true
	for i, open := range rosterJournals.open {
		if open == j {
			rosterJournals.open = append(rosterJournals.open[:i], rosterJournals.open[i+1:]...)
			break
		}
	}
}

// Writes returns the recorded writes by canonical roster path, each
// roster's in the order they were made.
func (j *RosterJournal) Writes() map[string][]RosterWrite {
	rosterJournals.mu.Lock()
	defer rosterJournals.mu.Unlock()
	out := make(map[string][]RosterWrite, len(j.writes))
	for target, writes := range j.writes {
		out[target] = append([]RosterWrite(nil), writes...)
	}
	return out
}

// watches reports whether j records writes to the canonical file target.
func (j *RosterJournal) watches(target string) bool {
	return j.targets[target] || j.dirs[filepath.Dir(target)]
}

// overlap names a path both j and other would record, if any.
func (j *RosterJournal) overlap(other *RosterJournal) (string, bool) {
	var shared []string
	for dir := range j.dirs {
		if other.dirs[dir] {
			shared = append(shared, dir)
		}
	}
	for target := range j.targets {
		if other.watches(target) {
			shared = append(shared, target)
		}
	}
	for target := range other.targets {
		if j.watches(target) {
			shared = append(shared, target)
		}
	}
	if len(shared) == 0 {
		return "", false
	}
	sort.Strings(shared)
	return shared[0], true
}

// journaledRosterWrite is a write writeLockedRoster is making to a roster
// an open journal watches, with what the roster held as it began.
type journaledRosterWrite struct {
	journal *RosterJournal
	target  string
	before  []byte
	existed bool
}

// beginJournaledRosterWrite reads what the roster lk holds, under the
// lock, when an open journal watches it; nil when none does. A watched
// roster that cannot be read is not written: the journal could not say
// what the write replaced, so the rollback relying on it could not undo it.
func beginJournaledRosterWrite(lk *rosterLock) (*journaledRosterWrite, error) {
	rosterJournals.mu.Lock()
	var journal *RosterJournal
	for _, j := range rosterJournals.open {
		if j.watches(lk.target) {
			journal = j
			break
		}
	}
	rosterJournals.mu.Unlock()
	if journal == nil {
		return nil, nil
	}
	before, existed, err := readRosterBeforeWrite(lk.target)
	if err != nil {
		// What the writer itself would refuse (a symlink, not a regular
		// file, not writable) is reported as it would report it.
		if _, refused := checkRosterWritable(lk.target, lk.path); refused != nil {
			return nil, refused
		}
		return nil, fmt.Errorf("roster %s: cannot read it to record this write for the apply's rollback, so it was left unchanged: %w: %w", lk.path, ErrRosterNotWritable, err)
	}
	return &journaledRosterWrite{journal: journal, target: lk.target, before: before, existed: existed}, nil
}

// readRosterBeforeWrite reads the roster at target, never through a
// symlink and only if it is a regular file; existed is false when there
// is none.
func readRosterBeforeWrite(target string) (data []byte, existed bool, err error) {
	f, err := os.OpenFile(target, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return nil, false, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, false, fmt.Errorf("roster %s is not a regular file", target)
	}
	data, err = io.ReadAll(f)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// finish records the write's outcome, err from writeRosterBytes, in its
// journal: nothing when the roster was left unchanged, After when it now
// holds data (err nil), Failed when a write in place stopped part-way (err
// wraps errRosterPartlyWritten). A journal closed meanwhile records
// nothing.
func (w *journaledRosterWrite) finish(data []byte, err error) {
	partly := errors.Is(err, errRosterPartlyWritten)
	if w == nil || err != nil && !partly {
		return
	}
	record := RosterWrite{Before: w.before, Existed: w.existed}
	if partly {
		record.Failed = true
	} else {
		record.After = bytes.Clone(data)
	}
	rosterJournals.mu.Lock()
	defer rosterJournals.mu.Unlock()
	if !w.journal.closed {
		w.journal.writes[w.target] = append(w.journal.writes[w.target], record)
	}
}
