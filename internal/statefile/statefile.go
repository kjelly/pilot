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
package statefile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// Load reads and parses the state file. A missing file is NOT an error —
// it yields an empty slice (the caller simply has no entries yet). A
// version mismatch is a hard error.
func (s *Store[T]) Load() ([]T, error) {
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

// Save writes targets to the state file atomically (temp file + rename).
func (s *Store[T]) Save(targets []T) error {
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
