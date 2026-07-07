// Package statefile provides a small, versioned, crash-safe JSON store
// used by the target backends (dockertarget, vmtarget) to persist their
// list of targets. Both backends previously carried a byte-for-byte copy
// of the same atomic load/save logic — this package is the single, tested
// implementation they now share.
//
// The on-disk shape is a versioned envelope:
//
//	{ "version": <n>, "targets": [ ... ] }
//
// Writes are atomic: the payload is written to a temp file in the same
// directory and renamed into place, so a crash mid-write can never leave a
// half-written (corrupt) state file. A version mismatch on load is a hard
// error rather than a silent misparse.
//
// Cross-process safety: every operation takes an advisory flock(2) on a
// sidecar <file>.lock (the lock file is separate because the rename in
// Save replaces the data file's inode). Load takes a shared lock, Save and
// Mutate an exclusive one. Atomic writes alone are NOT enough for
// concurrent writers: two processes doing load → modify → save each write
// a complete file, so the last writer silently discards the other's entry
// (hit for real with two parallel `pilot vm-target up` runs). Any
// read-modify-write MUST therefore go through Mutate, which holds the
// exclusive lock across the whole load+apply+save cycle. The kernel
// releases flocks when the holder dies, so a crashed process can never
// leave the store wedged.
package statefile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// envelope is the on-disk JSON shape.
type envelope[T any] struct {
	Version int `json:"version"`
	Targets []T `json:"targets"`
}

// Store is a versioned, atomic JSON store for a slice of T.
type Store[T any] struct {
	dir     string
	path    string
	version int
	label   string // used in error messages and the temp-file prefix
}

// New constructs a Store writing dir/filename. label prefixes error
// messages (e.g. "vmtarget") and the temp file name. version is the schema
// version stamped on save and required on load. dir is created if missing.
func New[T any](dir, filename string, version int, label string) (*Store[T], error) {
	if dir == "" {
		return nil, fmt.Errorf("statefile: dir is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("statefile: mkdir %s: %w", dir, err)
	}
	return &Store[T]{
		dir:     dir,
		path:    filepath.Join(dir, filename),
		version: version,
		label:   label,
	}, nil
}

// Path returns the absolute path of the state file.
func (s *Store[T]) Path() string { return s.path }

// lock opens (creating if needed) the sidecar lock file and takes the
// requested advisory flock (syscall.LOCK_SH or syscall.LOCK_EX), blocking
// until it is granted. Closing the returned file releases the lock.
func (s *Store[T]) lock(how int) (*os.File, error) {
	f, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("%s: open state lock: %w", s.label, err)
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: lock state: %w", s.label, err)
	}
	return f, nil
}

// Load reads and parses the state file (under a shared lock). A missing
// file is NOT an error — it yields an empty slice (the caller simply has
// no entries yet). A version mismatch is a hard error.
func (s *Store[T]) Load() ([]T, error) {
	f, err := s.lock(syscall.LOCK_SH)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return s.loadLocked()
}

// loadLocked is Load without lock acquisition; the caller must hold the lock.
func (s *Store[T]) loadLocked() ([]T, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: read state: %w", s.label, err)
	}
	var e envelope[T]
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("%s: parse state: %w", s.label, err)
	}
	if e.Version != s.version {
		return nil, fmt.Errorf("%s: state version %d (want %d); refusing to load", s.label, e.Version, s.version)
	}
	return e.Targets, nil
}

// Save writes targets to the state file atomically (temp file + rename),
// under an exclusive lock.
//
// Save OVERWRITES the whole file with the caller's snapshot: only use it
// when the caller's slice is the sole source of truth. For any
// read-modify-write (append a target, delete one, update a field) use
// Mutate instead — a load…Save pair spanning other work re-persists a
// stale snapshot and silently discards concurrent writers' entries.
func (s *Store[T]) Save(targets []T) error {
	f, err := s.lock(syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer f.Close()
	return s.saveLocked(targets)
}

// saveLocked is Save without lock acquisition; the caller must hold the lock.
func (s *Store[T]) saveLocked(targets []T) error {
	data, err := json.MarshalIndent(envelope[T]{Version: s.version, Targets: targets}, "", "  ")
	if err != nil {
		return fmt.Errorf("%s: marshal state: %w", s.label, err)
	}
	tmp, err := os.CreateTemp(s.dir, "."+s.label+"-*.json.tmp")
	if err != nil {
		return fmt.Errorf("%s: create temp: %w", s.label, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("%s: write temp: %w", s.label, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("%s: close temp: %w", s.label, err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("%s: rename temp: %w", s.label, err)
	}
	return nil
}

// Mutate atomically applies fn to the freshly-loaded targets and persists
// the result, holding the exclusive cross-process lock across the whole
// load → fn → save cycle. This is the ONLY safe way to do a
// read-modify-write against a store shared by concurrent processes.
//
// fn receives the current targets (nil when the file doesn't exist yet)
// and returns the full slice to persist. If fn returns an error, nothing
// is written and the error is returned verbatim. fn runs while the lock is
// held: keep it a quick in-memory transform — it must not call back into
// this Store and must not do slow I/O.
func (s *Store[T]) Mutate(fn func(targets []T) ([]T, error)) error {
	f, err := s.lock(syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer f.Close()
	targets, err := s.loadLocked()
	if err != nil {
		return err
	}
	next, err := fn(targets)
	if err != nil {
		return err
	}
	return s.saveLocked(next)
}
