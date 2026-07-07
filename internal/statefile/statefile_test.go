package statefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type rec struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

func TestStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := New[rec](dir, "things.json", 1, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want := []rec{{Name: "a", N: 1}, {Name: "b", N: 2}}
	if err := s.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

func TestStore_MissingFileIsEmpty(t *testing.T) {
	dir := t.TempDir()
	s, _ := New[rec](dir, "absent.json", 1, "test")
	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load of missing file must not error, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("missing file should yield empty slice, got %+v", got)
	}
}

func TestStore_VersionMismatchRefuses(t *testing.T) {
	dir := t.TempDir()
	// Write a v1 file, then open the same path expecting v2.
	v1, _ := New[rec](dir, "s.json", 1, "test")
	if err := v1.Save([]rec{{Name: "x"}}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	v2, _ := New[rec](dir, "s.json", 2, "test")
	_, err := v2.Load()
	if err == nil || !strings.Contains(err.Error(), "state version") {
		t.Fatalf("want version-mismatch error, got %v", err)
	}
}

func TestStore_SaveIsAtomic_NoTempLeftBehind(t *testing.T) {
	dir := t.TempDir()
	s, _ := New[rec](dir, "s.json", 1, "test")
	if err := s.Save([]rec{{Name: "a"}}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json.tmp") {
			t.Errorf("atomic save left a temp file behind: %s", e.Name())
		}
	}
	// The real file must exist at the reported path.
	if _, err := os.Stat(s.Path()); err != nil {
		t.Errorf("state file not at Path(): %v", err)
	}
	if filepath.Dir(s.Path()) != dir {
		t.Errorf("Path() dir = %q, want %q", filepath.Dir(s.Path()), dir)
	}
}

func TestStore_ParseErrorSurfacesLabel(t *testing.T) {
	dir := t.TempDir()
	s, _ := New[rec](dir, "s.json", 1, "mylabel")
	if err := os.WriteFile(s.Path(), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := s.Load()
	if err == nil || !strings.Contains(err.Error(), "mylabel") {
		t.Fatalf("parse error should carry the label, got %v", err)
	}
}

func TestStore_MutateAppendsOnEmpty(t *testing.T) {
	dir := t.TempDir()
	s, _ := New[rec](dir, "s.json", 1, "test")
	err := s.Mutate(func(targets []rec) ([]rec, error) {
		if targets != nil {
			t.Errorf("fresh store should hand fn nil targets, got %+v", targets)
		}
		return append(targets, rec{Name: "a", N: 1}), nil
	})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	got, err := s.Load()
	if err != nil || len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("after Mutate: got %+v err %v", got, err)
	}
}

func TestStore_MutateErrorWritesNothing(t *testing.T) {
	dir := t.TempDir()
	s, _ := New[rec](dir, "s.json", 1, "test")
	if err := s.Save([]rec{{Name: "keep"}}); err != nil {
		t.Fatal(err)
	}
	wantErr := "refused"
	err := s.Mutate(func(targets []rec) ([]rec, error) {
		return nil, errors.New(wantErr)
	})
	if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("Mutate should return fn's error verbatim, got %v", err)
	}
	got, _ := s.Load()
	if len(got) != 1 || got[0].Name != "keep" {
		t.Fatalf("failed Mutate must not write; got %+v", got)
	}
}

// TestStore_ConcurrentMutateLosesNoEntries is the regression test for the
// parallel `vm-target up` incident (2026-07-06): two processes each did
// load → modify → save, and the last atomic save silently discarded the
// other's entry (last-writer-wins). Mutate holds an exclusive flock across
// the whole read-modify-write, so N writers — modeled here as N goroutines
// each with its OWN Store instance (flock arbitrates between file
// descriptors, so separate stores in one process contend exactly like
// separate processes) — must end with all N entries present.
func TestStore_ConcurrentMutateLosesNoEntries(t *testing.T) {
	dir := t.TempDir()
	const writers = 16
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := New[rec](dir, "s.json", 1, "test") // own instance = own lock fd
			if err != nil {
				errs <- err
				return
			}
			errs <- s.Mutate(func(targets []rec) ([]rec, error) {
				return append(targets, rec{Name: fmt.Sprintf("t%02d", i), N: i}), nil
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Mutate: %v", err)
		}
	}
	s, _ := New[rec](dir, "s.json", 1, "test")
	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != writers {
		t.Fatalf("lost entries under concurrency: got %d want %d (%+v)", len(got), writers, got)
	}
	seen := map[string]bool{}
	for _, r := range got {
		if seen[r.Name] {
			t.Errorf("duplicate entry %q", r.Name)
		}
		seen[r.Name] = true
	}
}
