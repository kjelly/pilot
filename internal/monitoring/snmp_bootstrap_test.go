package monitoring

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/monitoring/snmp/generated"
)

func TestBootstrapSNMPBaselineCreatesCatalogAndOfficialIFMIB(t *testing.T) {
	dir := t.TempDir()
	result, err := BootstrapSNMPBaseline(dir)
	if err != nil {
		t.Fatalf("BootstrapSNMPBaseline() error = %v", err)
	}
	if !result.CatalogCreated || result.CatalogUpdated || !result.IFMIBCreated {
		t.Fatalf("result = %+v, want new catalog and module", result)
	}

	catalogPath := filepath.Join(dir, "monitoring", "snmp", "catalog.yml")
	catalog, err := LoadSNMPCatalog(catalogPath)
	if err != nil {
		t.Fatalf("LoadSNMPCatalog() error = %v", err)
	}
	if got := catalog.Modules["if_mib"].File; got != standardIFMIBModulePath {
		t.Fatalf("if_mib module path = %q, want %q", got, standardIFMIBModulePath)
	}
	if len(catalog.AuthProfiles) != 0 {
		t.Fatalf("auth profiles = %+v, want no credential-independent defaults", catalog.AuthProfiles)
	}

	modulePath := filepath.Join(dir, "monitoring", "snmp", "generated", "if_mib.yml")
	gotModule, err := os.ReadFile(modulePath)
	if err != nil {
		t.Fatalf("read generated module: %v", err)
	}
	if !bytes.Equal(gotModule, generated.IFMIB) {
		t.Fatal("generated if_mib module differs from the embedded reviewed asset")
	}

	result, err = BootstrapSNMPBaseline(dir)
	if err != nil {
		t.Fatalf("idempotent BootstrapSNMPBaseline() error = %v", err)
	}
	if result != (SNMPBootstrapResult{}) {
		t.Fatalf("idempotent result = %+v, want no writes", result)
	}
}

func TestBootstrapSNMPBaselineRefusesConflictingIFMIBDeclaration(t *testing.T) {
	dir := t.TempDir()
	catalogPath := filepath.Join(dir, "monitoring", "snmp", "catalog.yml")
	if err := os.MkdirAll(filepath.Dir(catalogPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalogPath, []byte("schemaVersion: 1\nmodules:\n  if_mib:\n    file: custom.yml\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := BootstrapSNMPBaseline(dir); err == nil {
		t.Fatal("BootstrapSNMPBaseline() succeeded with a conflicting if_mib module")
	}
	if _, err := os.Stat(filepath.Join(dir, "monitoring", "snmp", "generated", "if_mib.yml")); !os.IsNotExist(err) {
		t.Fatalf("standard module was created despite conflict: %v", err)
	}
}

func TestBootstrapSNMPBaselinePreservesExistingStandardPathModule(t *testing.T) {
	dir := t.TempDir()
	catalogPath := filepath.Join(dir, "monitoring", "snmp", "catalog.yml")
	modulePath := filepath.Join(dir, "monitoring", "snmp", "generated", "if_mib.yml")
	if err := os.MkdirAll(filepath.Dir(modulePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalogPath, []byte("schemaVersion: 1\nmodules:\n  if_mib:\n    file: generated/if_mib.yml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	customModule := []byte("if_mib:\n  walk: [1.3.6.1.2.1.2]\n")
	if err := os.WriteFile(modulePath, customModule, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := BootstrapSNMPBaseline(dir)
	if err != nil {
		t.Fatalf("BootstrapSNMPBaseline() error = %v", err)
	}
	if result != (SNMPBootstrapResult{}) {
		t.Fatalf("result = %+v, want no writes to an existing baseline", result)
	}
	got, err := os.ReadFile(modulePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, customModule) {
		t.Fatal("bootstrap overwrote an existing if_mib module")
	}
}
