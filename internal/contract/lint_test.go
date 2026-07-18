package contract

import (
	"os"
	"path/filepath"
	"strings"
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

func TestValidateBundleReferencesRejectsMissingTraceabilityTag(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "playbooks", "apply"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "spec.md"), []byte("# Verification Spec — test\n\n## 2. Checklist\n| ID | Category | Check | Expected | Command |\n|----|----------|-------|----------|---------|\n| C1 | x | x | present | true |\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	playbook := "playbooks/apply/apply.yml"
	if err := os.WriteFile(filepath.Join(root, playbook), []byte("---\n- hosts: all\n  tasks: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := NewCatalog([]Contract{{
		ID: "a", Role: "a",
		Specs:        []Spec{{Path: "spec.md", Rows: RowSelector{All: true}}},
		Playbooks:    Playbooks{Apply: playbook},
		Traceability: Traceability{Mode: "rowTags", Tag: &TagStrategy{Kind: "bare"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBundleReferences(root, catalog); err == nil || !strings.Contains(err.Error(), "missing playbook tag C1") {
		t.Fatalf("err=%v", err)
	}
}

func TestValidateBundleReferencesRejectsUnknownProviderEndpoint(t *testing.T) {
	components := map[string]Contract{
		"provider": {ID: "provider", Endpoints: []Endpoint{{Name: "api"}}},
		"client": {
			ID:       "client",
			Bindings: []Binding{{Input: "url", From: BindingFrom{Component: "provider", Endpoint: "missing"}}},
		},
	}
	if err := validateBindingEndpoints(components); err == nil || !strings.Contains(err.Error(), "unknown endpoint") {
		t.Fatalf("err=%v", err)
	}
}
