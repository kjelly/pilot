package monitoring

import (
	"path/filepath"
	"testing"
)

func TestLoadSNMPCatalog_MissingFile(t *testing.T) {
	catalog, err := LoadSNMPCatalog(filepath.Join(t.TempDir(), "does-not-exist.yml"))
	if err != nil {
		t.Fatalf("LoadSNMPCatalog: %v", err)
	}
	if catalog.SchemaVersion != SNMPCatalogSchemaVersion || len(catalog.Modules) != 0 || len(catalog.AuthProfiles) != 0 {
		t.Fatalf("missing file should be an empty catalog, got %+v", catalog)
	}
}

func TestLoadSNMPCatalog_EmptyPath(t *testing.T) {
	catalog, err := LoadSNMPCatalog("")
	if err != nil {
		t.Fatalf("LoadSNMPCatalog(\"\"): %v", err)
	}
	if len(catalog.Modules) != 0 || len(catalog.AuthProfiles) != 0 {
		t.Fatalf("empty path should be an empty catalog, got %+v", catalog)
	}
}

func TestLoadSNMPCatalog_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.yml")
	content := []byte(`schemaVersion: 1

modules:
  if_mib:
    file: generated/if_mib.yml

authProfiles:
  core-switch-v3:
    version: 3
    securityLevel: authPriv
    authProtocol: SHA256
    privProtocol: AES
    credentialRef: core-switch-v3
`)
	if err := writeFile(path, content); err != nil {
		t.Fatalf("seed catalog: %v", err)
	}

	catalog, err := LoadSNMPCatalog(path)
	if err != nil {
		t.Fatalf("LoadSNMPCatalog: %v", err)
	}
	if catalog.SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d, want 1", catalog.SchemaVersion)
	}
	module, ok := catalog.Modules["if_mib"]
	if !ok || module.File != "generated/if_mib.yml" {
		t.Fatalf("Modules[\"if_mib\"] = %+v, ok=%v", module, ok)
	}
	auth, ok := catalog.AuthProfiles["core-switch-v3"]
	if !ok {
		t.Fatalf("AuthProfiles[\"core-switch-v3\"] missing")
	}
	if auth.Version != 3 || auth.SecurityLevel != "authPriv" || auth.CredentialRef != "core-switch-v3" {
		t.Fatalf("AuthProfiles[\"core-switch-v3\"] = %+v", auth)
	}
}

func TestLoadSNMPCatalog_RejectsMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.yml")
	if err := writeFile(path, []byte("modules: [this is not a map")); err != nil {
		t.Fatalf("seed catalog: %v", err)
	}
	if _, err := LoadSNMPCatalog(path); err == nil {
		t.Fatal("LoadSNMPCatalog should reject malformed YAML")
	}
}
