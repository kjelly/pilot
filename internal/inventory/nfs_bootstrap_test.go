package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteMinimalNFSServerRosterCreatesDemoSkeleton(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".vault", "ipa-identity.yaml")
	if err := WriteMinimalNFSServerRoster(path, "nfs-demo", "ipa.example.test", "admin", "a-real-password"); err != nil {
		t.Fatalf("WriteMinimalNFSServerRoster() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read roster: %v", err)
	}
	content := string(data)
	for _, want := range []string{
		"schema_version: 3",
		"netgroups: []",
		"grants: []",
		"principal: admin",
		"password: a-real-password",
		"host: nfs-demo.ipa.example.test",
		"principal: nfs/nfs-demo.ipa.example.test",
		"shares: []",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("roster missing %q:\n%s", want, content)
		}
	}
	if strings.Contains(content, "domain:") {
		t.Fatalf("a new schema-v3 roster must not generate freeipa.domain:\n%s", content)
	}
	if mode := dataMode(t, path); mode.Perm() != 0o600 {
		t.Fatalf("roster mode = %o, want 600", mode.Perm())
	}

	root := mustParseRoster(t, content)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("generated skeleton failed ValidateRosterV3: %v", v)
	}
}

func TestWriteMinimalRosterSkeletonCreatesCurrentSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".vault", "ipa-identity.yaml")
	if err := WriteMinimalRosterSkeleton(path, "admin", "a-real-password"); err != nil {
		t.Fatalf("WriteMinimalRosterSkeleton() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read roster: %v", err)
	}
	content := string(data)
	for _, want := range []string{"schema_version: 3", "netgroups: []", "grants: []", "principal: admin", "password: a-real-password"} {
		if !strings.Contains(content, want) {
			t.Fatalf("roster missing %q:\n%s", want, content)
		}
	}
	if strings.Contains(content, "domain:") {
		t.Fatalf("a new schema-v3 roster must not generate freeipa.domain:\n%s", content)
	}

	root := mustParseRoster(t, content)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("generated skeleton failed ValidateRosterV3: %v", v)
	}
}

func TestWriteMinimalNFSServerRosterNeverOverwritesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roster.yaml")
	original := []byte("schema_version: 1\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("write original: %v", err)
	}
	if err := WriteMinimalNFSServerRoster(path, "nfs-demo", "ipa.example.test", "admin", "secret"); err == nil {
		t.Fatal("expected existing roster to be rejected")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read original: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("existing roster changed: %q", got)
	}
}

func TestWriteMinimalFreeIPAVaultCreatesAndProtectsPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".vault", "main.yaml")
	if err := WriteMinimalFreeIPAVault(path, "a-real-password"); err != nil {
		t.Fatalf("WriteMinimalFreeIPAVault() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	if string(data) != "ipa_admin_password: a-real-password\n" {
		t.Fatalf("vault = %q, want minimal ipa_admin_password", data)
	}
	if mode := dataMode(t, path); mode.Perm() != 0o600 {
		t.Fatalf("vault mode = %o, want 600", mode.Perm())
	}
}

func dataMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode()
}
