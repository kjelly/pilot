package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

// nfsBootstrapV1RosterWithExistingEntry is a valid v1 roster that already
// has an nfs.servers entry for "nfs-demo" — used so AppendMissingNFSServerStub
// itself is a no-op (appended=false) and any banner text is purely from the
// migration this test is actually checking.
const nfsBootstrapV1RosterWithExistingEntry = `---
schema_version: 1
freeipa:
  admin: {principal: admin, password: x}
nfs:
  servers:
    - host: nfs-demo.ipa.pilot.internal
      state: present
      service_principal:
        ensure: true
        principal: nfs/nfs-demo.ipa.pilot.internal
        keytab: /etc/krb5.keytab
      shares: []
`

func TestAutofixNFSRosterEntry_MigratesV1RosterBeforeAppending(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(nfsBootstrapV1RosterWithExistingEntry), 0o600); err != nil {
		t.Fatal(err)
	}
	h := inventory.Host{Name: "nfs-demo", Extra: map[string]string{"freeipa_roster_file": rosterPath}}

	banner := autofixNFSRosterEntry(dir, h)
	if !strings.Contains(banner, "Automatically upgraded to schema v3") {
		t.Fatalf("banner = %q, want an auto-upgrade notice", banner)
	}

	migrated, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migrated), "schema_version: 3") {
		t.Fatalf("roster on disk = %q, want it upgraded to schema_version: 3", migrated)
	}
}

func TestAutofixNFSRosterEntry_NoRosterPathIsANoOp(t *testing.T) {
	dir := t.TempDir()
	h := inventory.Host{Name: "nfs-demo", Extra: map[string]string{}}
	if banner := autofixNFSRosterEntry(dir, h); banner != "" {
		t.Fatalf("banner = %q, want empty when no freeipa_roster_file is set", banner)
	}
}

func TestWriteMissingNFSRosterEntries_MigratesV1RosterBeforeAppending(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte("schema_version: 1\nfreeipa:\n  admin: {principal: admin, password: x}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "nfs-demo", Roles: []string{"freeipa-nfs-server"}, Extra: map[string]string{"freeipa_roster_file": rosterPath}},
	}}

	var out strings.Builder
	writeMissingNFSRosterEntries(&out, dir, hf)

	if !strings.Contains(out.String(), "auto-upgraded schema v1 -> v3") {
		t.Fatalf("output = %q, want an auto-upgrade notice", out.String())
	}
	if !strings.Contains(out.String(), "appended nfs.servers entry") {
		t.Fatalf("output = %q, want the usual appended-entry notice too", out.String())
	}
	migrated, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migrated), "schema_version: 3") {
		t.Fatalf("roster on disk = %q, want it upgraded to schema_version: 3", migrated)
	}
}

// TestPushRosterManager_ShowsAutoMigrationNotice covers the "pilot edit
// roster entry" / MCP semantic roster driver call site: pushRosterManager
// is the one screen both paths funnel through before reaching
// Users/Groups/Host access/Sudo (see edit_automation_driver_roster.go's
// ensureRosterUsersList, which drives this exact screen by ID).
func TestPushRosterManager_ShowsAutoMigrationNotice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte("schema_version: 1\nfreeipa:\n  admin: {principal: admin, password: x}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var router editRouterModel
	pushRosterManager(&router, dir, path, "")

	if !strings.Contains(router.banner, "Automatically upgraded to schema v3") {
		t.Fatalf("banner = %q, want an auto-upgrade notice", router.banner)
	}
	rosterMigrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rosterMigrated), "schema_version: 3") {
		t.Fatalf("roster on disk = %q, want it upgraded to schema_version: 3", rosterMigrated)
	}
}

func TestPushRosterManager_NoNoticeForAlreadyCurrentRoster(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte("schema_version: 3\nfreeipa:\n  admin: {principal: admin, password: x}\nnetgroups: []\ngrants: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var router editRouterModel
	pushRosterManager(&router, dir, path, "")

	if strings.Contains(router.banner, "Automatically upgraded") {
		t.Fatalf("banner = %q, did not expect a migration notice for an already-current roster", router.banner)
	}
}

func TestPushRosterManager_PreservesExistingBannerAlongsideMigrationNotice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte("schema_version: 1\nfreeipa:\n  admin: {principal: admin, password: x}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var router editRouterModel
	pushRosterManager(&router, dir, path, "some other banner")

	if !strings.Contains(router.banner, "Automatically upgraded to schema v3") || !strings.Contains(router.banner, "some other banner") {
		t.Fatalf("banner = %q, want both the migration notice and the caller's own banner", router.banner)
	}
}
