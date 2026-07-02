package statefile

import (
	"os"
	"path/filepath"
	"strings"
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
