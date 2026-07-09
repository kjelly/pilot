package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// repoRootForTest walks up from the current package directory until it
// finds go.mod. Tests run with cwd == the package's source directory,
// so deployCatalog's playbook paths (repo-root-relative) need this to
// actually stat the files on disk.
func repoRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod) above " + dir)
		}
		dir = parent
	}
}

func TestDeployCatalog_PlaybooksExistAndAreWellFormed(t *testing.T) {
	root := repoRootForTest(t)
	seen := map[string]bool{}
	for _, p := range deployCatalog {
		if p.Key == "" {
			t.Fatalf("catalog entry %q has an empty Key", p.Label)
		}
		if seen[p.Key] {
			t.Fatalf("duplicate catalog Key %q", p.Key)
		}
		seen[p.Key] = true

		if p.StageVar != "stage" && p.StageVar != "patch_stage" {
			t.Fatalf("%s: StageVar must be \"stage\" or \"patch_stage\", got %q", p.Key, p.StageVar)
		}

		full := filepath.Join(root, p.Playbook)
		if _, err := os.Stat(full); err != nil {
			t.Fatalf("%s: playbook %s does not exist: %v", p.Key, p.Playbook, err)
		}
	}
	// AGENTS.md §4.3 tracks this count; keep the two in sync deliberately
	// rather than silently drifting.
	if len(deployCatalog) != 20 {
		t.Fatalf("expected 20 apply playbooks in the catalog (see AGENTS.md §4.3), got %d", len(deployCatalog))
	}
}

func TestValidateOptionalKV(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"", false},
		{"  ", false},
		{"a=b", false},
		{"a=b c=d", false},
		{"a=b  c=d", false},
		{"noequals", true},
		{"a=b bad", true},
	}
	for _, c := range cases {
		err := validateOptionalKV(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("validateOptionalKV(%q) error=%v, wantErr=%v", c.in, err, c.wantErr)
		}
	}
}

func TestValidateHoursWithinWeek(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"0", false},
		{"168", false},
		{"169", true},
		{"-1", true},
		{"abc", true},
	}
	for _, c := range cases {
		err := validateHoursWithinWeek(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("validateHoursWithinWeek(%q) error=%v, wantErr=%v", c.in, err, c.wantErr)
		}
	}
}

func TestValidateFileExists(t *testing.T) {
	root := repoRootForTest(t)
	if err := validateFileExists(filepath.Join(root, "go.mod")); err != nil {
		t.Errorf("expected go.mod to exist: %v", err)
	}
	if err := validateFileExists(""); err == nil {
		t.Error("expected error for empty path")
	}
	if err := validateFileExists("/does/not/exist/nope"); err == nil {
		t.Error("expected error for missing file")
	}
}
