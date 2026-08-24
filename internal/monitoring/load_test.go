package monitoring

import (
	"path/filepath"
	"testing"
)

func TestLoadTargets_MissingFile(t *testing.T) {
	tf, err := LoadTargets(filepath.Join(t.TempDir(), "does-not-exist.yml"))
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if tf.SchemaVersion != SchemaVersion || len(tf.Targets) != 0 {
		t.Fatalf("missing file should be an empty registry, got %+v", tf)
	}
}

func TestLoadTargets_EmptyPath(t *testing.T) {
	tf, err := LoadTargets("")
	if err != nil {
		t.Fatalf("LoadTargets(\"\"): %v", err)
	}
	if len(tf.Targets) != 0 {
		t.Fatalf("empty path should be an empty registry, got %+v", tf)
	}
}

func TestLoadTargets_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	content := []byte(`schemaVersion: 1
targets:
  - name: nas01
    address: nas01.pilot.internal:9633
    profile: storage-exporter
    site: taipei
    enabled: true
    labels:
      owner: storage
`)
	if err := writeFile(path, content); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	tf, err := LoadTargets(path)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(tf.Targets) != 1 || tf.Targets[0].Name != "nas01" {
		t.Fatalf("unexpected parse result: %+v", tf)
	}
	if !tf.Targets[0].IsEnabled() {
		t.Fatalf("expected enabled target")
	}
}

func TestLoadTargets_EmptyFileIsEmptyRegistry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	if err := writeFile(path, []byte("")); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	tf, err := LoadTargets(path)
	if err != nil {
		t.Fatalf("LoadTargets on empty file: %v", err)
	}
	if len(tf.Targets) != 0 {
		t.Fatalf("expected empty targets, got %+v", tf)
	}
}

func TestLoadTargets_InvalidSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	if err := writeFile(path, []byte("schemaVersion: not-a-number\n")); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := LoadTargets(path); err == nil {
		t.Fatalf("expected a parse error for a non-numeric schemaVersion")
	}
}

func TestLoadProfiles_MissingFile(t *testing.T) {
	pf, err := LoadProfiles(filepath.Join(t.TempDir(), "does-not-exist.yml"))
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	if len(pf.Profiles) != 0 {
		t.Fatalf("missing file should be an empty profile registry, got %+v", pf)
	}
}

func TestSaveTargets_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "targets.yml")
	enabled := false
	tf := TargetFile{Targets: []Target{{Name: "a", Address: "1.2.3.4:9100", Profile: "p", Enabled: &enabled}}}
	if err := SaveTargets(path, tf); err != nil {
		t.Fatalf("SaveTargets: %v", err)
	}
	got, err := LoadTargets(path)
	if err != nil {
		t.Fatalf("LoadTargets after save: %v", err)
	}
	if len(got.Targets) != 1 || got.Targets[0].Name != "a" || got.Targets[0].IsEnabled() {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}
