package contract

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoaderLoadsFinalFixtureDirectoryInStableOrder(t *testing.T) {
	t.Parallel()

	loader, err := NewLoader(contractRepoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	contracts, err := loader.LoadDir("docs/tmp/future/contracts")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	got := make([]string, 0, len(contracts))
	for _, contract := range contracts {
		got = append(got, contract.ID)
	}
	want := []string{"dns", "docker", "freeipa-server", "log-shipping", "ntp", "restic-backup"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("contract IDs = %v, want %v", got, want)
	}
}

func TestCatalogLooksUpComponentAndRole(t *testing.T) {
	t.Parallel()

	loader, err := NewLoader(contractRepoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadCatalog("docs/tmp/future/contracts")
	if err != nil {
		t.Fatal(err)
	}
	docker, ok := catalog.Component("docker")
	if !ok || docker.Role != "docker" {
		t.Fatalf("docker lookup = %#v, %t", docker, ok)
	}
	components := catalog.ComponentsForRole("log-server")
	if len(components) != 1 || components[0].ID != "log-shipping" {
		t.Fatalf("ComponentsForRole(log-server) = %#v", components)
	}
	if _, ok := catalog.Component("missing"); ok {
		t.Fatal("missing component unexpectedly resolved")
	}
}

func TestLoaderRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	fixture, err := os.ReadFile(filepath.Join(contractRepoRoot(t), "docs", "tmp", "future", "contracts", "docker.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docker.yaml"), append(fixture, []byte("\nunknownField: true\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	loader, err := NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = loader.LoadFile("docker.yaml")
	if err == nil || !strings.Contains(err.Error(), "field unknownField not found") {
		t.Fatalf("LoadFile error = %v, want strict unknown-field error", err)
	}
}

func contractRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestLoaderRejectsPathOutsideRoot(t *testing.T) {
	t.Parallel()

	loader, err := NewLoader(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = loader.LoadFile("../outside.yaml")
	if err == nil || !strings.Contains(err.Error(), "escapes root") {
		t.Fatalf("LoadFile error = %v, want root escape rejection", err)
	}
}

func TestLoaderRequiresV2SpecsForAutoDeploy(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	fixture, err := os.ReadFile(filepath.Join(contractRepoRoot(t), "docs", "tmp", "future", "contracts", "docker.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	contractYAML := strings.Replace(string(fixture), "docs/verification/docker.md", "spec.md", 1)
	contractYAML = strings.Replace(contractYAML, "autoDeploy: false", "autoDeploy: true", 1)
	if err := os.WriteFile(filepath.Join(root, "contract.yaml"), []byte(contractYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "spec.md"), []byte("# Verification Spec — v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loader, err := NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loader.LoadFile("contract.yaml"); err == nil || !strings.Contains(err.Error(), "requires Spec v2") {
		t.Fatalf("LoadFile error = %v, want v2 eligibility rejection", err)
	}

	v2 := "---\nschemaVersion: 2\n---\n# Verification Spec — v2\n"
	if err := os.WriteFile(filepath.Join(root, "spec.md"), []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loader.LoadFile("contract.yaml"); err != nil {
		t.Fatalf("LoadFile rejected Spec v2 autoDeploy contract: %v", err)
	}
}
