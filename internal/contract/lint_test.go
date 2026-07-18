package contract

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateBundleReferencesRejectsMissingSelectedRow(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "spec.md"), []byte("# Verification Spec — test\n\n## 2. Checklist\n| ID | Category | Check | Expected | Command |\n|----|----------|-------|----------|---------|\n| C1 | x | x | present | true |\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "apply.yml"), []byte("---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := NewCatalog([]Contract{{ID: "a", Role: "a", Specs: []Spec{{Path: "spec.md", Rows: RowSelector{IDs: []string{"C2"}}}}, Playbooks: Playbooks{Apply: "apply.yml"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBundleReferences(root, catalog); err == nil {
		t.Fatal("missing selected row accepted")
	}
}

func TestValidateBundleReferencesRejectsDependencyCycle(t *testing.T) {
	catalog, err := NewCatalog([]Contract{{ID: "a", Dependencies: []Dependency{{Component: "b"}}}, {ID: "b", Dependencies: []Dependency{{Component: "a"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDependencyCycles(map[string]Contract{"a": catalog.Components()[0], "b": catalog.Components()[1]}); err == nil {
		t.Fatal("cycle accepted")
	}
}
