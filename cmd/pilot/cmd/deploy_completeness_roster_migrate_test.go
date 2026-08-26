package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// freeIPARosterMigrateInventoryYAML declares two freeipa-server hosts that
// both point at the same roster file — used to prove
// ensureFreeIPARostersCurrent migrates a shared roster exactly once rather
// than once per host.
const freeIPARosterMigrateInventoryYAML = `---
all:
  hosts:
    ipa1:
      ansible_host: 10.0.0.10
      freeipa_roster_file: "%s"
    ipa2:
      ansible_host: 10.0.0.11
      freeipa_roster_file: "%s"
  children:
    freeipa-server:
      hosts:
        ipa1:
        ipa2:
`

func writeFreeIPARosterMigrateFixture(t *testing.T, rosterContent string) (dir, inv, rosterPath string) {
	t.Helper()
	dir = t.TempDir()
	rosterPath = filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(rosterContent), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	inv = filepath.Join(dir, "inventory.yml")
	invContent := strings.ReplaceAll(freeIPARosterMigrateInventoryYAML, "%s", rosterPath)
	if err := os.WriteFile(inv, []byte(invContent), 0o644); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	return dir, inv, rosterPath
}

func TestEnsureFreeIPARostersCurrent_MigratesV1RosterOnce(t *testing.T) {
	_, inv, rosterPath := writeFreeIPARosterMigrateFixture(t, rosterWithDomainOnly)

	var out bytes.Buffer
	if err := ensureFreeIPARostersCurrent(context.Background(), &out, inv); err != nil {
		t.Fatalf("ensureFreeIPARostersCurrent() error = %v", err)
	}
	if !strings.Contains(out.String(), "Automatically upgraded to schema v3") {
		t.Fatalf("output = %q, want an auto-upgrade notice", out.String())
	}

	migrated, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migrated), "schema_version: 3") {
		t.Fatalf("roster on disk = %q, want it upgraded to schema_version: 3", migrated)
	}

	// Shared by both ipa1 and ipa2 — must migrate exactly once, not twice
	// (a second attempt on an already-current roster is harmless, but a
	// naive per-host loop without dedup would still print two notices).
	if n := strings.Count(out.String(), "Automatically upgraded"); n != 1 {
		t.Fatalf("output printed %d upgrade notice(s), want exactly 1:\n%s", n, out.String())
	}
	backups, err := filepath.Glob(rosterPath + ".v*.bak")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("found %d backup file(s), want exactly 1: %v", len(backups), backups)
	}
}

func TestEnsureFreeIPARostersCurrent_EncryptedRosterIsSilentlySkipped(t *testing.T) {
	_, inv, rosterPath := writeFreeIPARosterMigrateFixture(t, "$ANSIBLE_VAULT;1.1;AES256\n633864363...\n")

	var out bytes.Buffer
	if err := ensureFreeIPARostersCurrent(context.Background(), &out, inv); err != nil {
		t.Fatalf("ensureFreeIPARostersCurrent() error = %v", err)
	}
	if out.String() != "" {
		t.Fatalf("output = %q, want no output for an encrypted roster (expected, not a warning)", out.String())
	}
	got, err := os.ReadFile(rosterPath)
	if err != nil || string(got) != "$ANSIBLE_VAULT;1.1;AES256\n633864363...\n" {
		t.Fatalf("encrypted roster was modified (err=%v): %q", err, got)
	}
}

func TestEnsureFreeIPARostersCurrent_InvalidV1RosterWarnsWithoutBlocking(t *testing.T) {
	_, inv, _ := writeFreeIPARosterMigrateFixture(t, "schema_version: 1\nusers:\n  - name: Alice\n")

	var out bytes.Buffer
	if err := ensureFreeIPARostersCurrent(context.Background(), &out, inv); err != nil {
		t.Fatalf("ensureFreeIPARostersCurrent() error = %v, want it to never block on a migration failure", err)
	}
	if !strings.Contains(out.String(), "warning:") {
		t.Fatalf("output = %q, want a warning about the unmigratable roster", out.String())
	}
}

func TestEnsureFreeIPARostersCurrent_AlreadyCurrentIsSilentNoOp(t *testing.T) {
	v3 := strings.Replace(rosterWithDomainOnly, "schema_version: 1", "schema_version: 3\nnetgroups: []\ngrants: []", 1)
	_, inv, _ := writeFreeIPARosterMigrateFixture(t, v3)

	var out bytes.Buffer
	if err := ensureFreeIPARostersCurrent(context.Background(), &out, inv); err != nil {
		t.Fatalf("ensureFreeIPARostersCurrent() error = %v", err)
	}
	if out.String() != "" {
		t.Fatalf("output = %q, want no output for an already-current roster", out.String())
	}
}

func TestEnsureFreeIPARostersCurrent_UpgradesV2Roster(t *testing.T) {
	v2 := strings.Replace(rosterWithDomainOnly, "schema_version: 1", "schema_version: 2\nnetgroups: []", 1)
	_, inv, rosterPath := writeFreeIPARosterMigrateFixture(t, v2)

	var out bytes.Buffer
	if err := ensureFreeIPARostersCurrent(context.Background(), &out, inv); err != nil {
		t.Fatalf("ensureFreeIPARostersCurrent() error = %v", err)
	}
	if !strings.Contains(out.String(), "Roster schema v2 detected") || !strings.Contains(out.String(), "Automatically upgraded to schema v3") {
		t.Fatalf("output = %q, want a v2->v3 auto-upgrade notice", out.String())
	}
	migrated, err := os.ReadFile(rosterPath)
	if err != nil || !strings.Contains(string(migrated), "schema_version: 3") {
		t.Fatalf("roster on disk = %q, err = %v, want it upgraded to schema_version: 3", migrated, err)
	}
}
