package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rosterFixtureNoNFS = `---
schema_version: 1
freeipa:
  domain: ipa.pilot.internal
  realm: IPA.PILOT.INTERNAL
  server: ipa1.ipa.pilot.internal
users:
- name: alice
  state: present
`

const rosterFixtureWithNFS = `---
schema_version: 1
freeipa:
  domain: ipa.pilot.internal
users: []
nfs:
  servers:
    - host: nfs1.ipa.pilot.internal
      state: present
      service_principal:
        ensure: true
        principal: nfs/nfs1.ipa.pilot.internal
        keytab: /etc/krb5.keytab
      shares: []
`

func writeRosterFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "roster.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func readFileHelper(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestRosterDomain_ReadsFreeIPADomain(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	got, err := RosterDomain(path)
	if err != nil {
		t.Fatalf("RosterDomain() error = %v", err)
	}
	if got != "ipa.pilot.internal" {
		t.Fatalf("RosterDomain() = %q, want ipa.pilot.internal", got)
	}
}

func TestRosterHasNFSServer_TrueWhenPrincipalMatches(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureWithNFS)
	got, err := RosterHasNFSServer(path, "nfs1.ipa.pilot.internal")
	if err != nil {
		t.Fatalf("RosterHasNFSServer() error = %v", err)
	}
	if !got {
		t.Fatalf("RosterHasNFSServer() = false, want true")
	}
}

func TestRosterHasNFSServer_FalseWhenAbsent(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	got, err := RosterHasNFSServer(path, "nexus.ipa.pilot.internal")
	if err != nil {
		t.Fatalf("RosterHasNFSServer() error = %v", err)
	}
	if got {
		t.Fatalf("RosterHasNFSServer() = true, want false")
	}
}

func TestAppendMissingNFSServerStub_CreatesNFSSectionWhenAbsent(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)

	appended, err := AppendMissingNFSServerStub(path, "nexus")
	if err != nil {
		t.Fatalf("AppendMissingNFSServerStub() error = %v", err)
	}
	if !appended {
		t.Fatalf("AppendMissingNFSServerStub() appended = false, want true")
	}

	has, err := RosterHasNFSServer(path, "nexus.ipa.pilot.internal")
	if err != nil {
		t.Fatalf("RosterHasNFSServer() error = %v", err)
	}
	if !has {
		t.Fatalf("expected nexus.ipa.pilot.internal to now be in the roster")
	}

	data := readFileHelper(t, path)
	if !strings.Contains(data, "alice") {
		t.Fatalf("append should not disturb existing users content:\n%s", data)
	}
	if !strings.Contains(data, "principal: nfs/nexus.ipa.pilot.internal") {
		t.Fatalf("expected generated principal in roster:\n%s", data)
	}
}

func TestAppendMissingNFSServerStub_AppendsAlongsideExistingServer(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureWithNFS)

	appended, err := AppendMissingNFSServerStub(path, "nexus")
	if err != nil {
		t.Fatalf("AppendMissingNFSServerStub() error = %v", err)
	}
	if !appended {
		t.Fatalf("AppendMissingNFSServerStub() appended = false, want true")
	}

	data := readFileHelper(t, path)
	if !strings.Contains(data, "nfs1.ipa.pilot.internal") {
		t.Fatalf("existing server entry should still be present:\n%s", data)
	}
	if !strings.Contains(data, "nexus.ipa.pilot.internal") {
		t.Fatalf("new server entry should have been appended:\n%s", data)
	}

	has1, _ := RosterHasNFSServer(path, "nfs1.ipa.pilot.internal")
	has2, _ := RosterHasNFSServer(path, "nexus.ipa.pilot.internal")
	if !has1 || !has2 {
		t.Fatalf("expected both servers present, got nfs1=%v nexus=%v", has1, has2)
	}
}

func TestAppendMissingNFSServerStub_IdempotentOnRepeatedCalls(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)

	if _, err := AppendMissingNFSServerStub(path, "nexus"); err != nil {
		t.Fatalf("first append error = %v", err)
	}
	appended, err := AppendMissingNFSServerStub(path, "nexus")
	if err != nil {
		t.Fatalf("second append error = %v", err)
	}
	if appended {
		t.Fatalf("second AppendMissingNFSServerStub() appended = true, want false (already present)")
	}

	data := readFileHelper(t, path)
	if strings.Count(data, "principal: nfs/nexus.ipa.pilot.internal") != 1 {
		t.Fatalf("expected exactly one nexus entry, got:\n%s", data)
	}
}

func TestRosterDomain_EncryptedFileReturnsErrRosterEncrypted(t *testing.T) {
	path := writeRosterFixture(t, "$ANSIBLE_VAULT;1.1;AES256\n633864363...\n")

	if _, err := RosterDomain(path); err != ErrRosterEncrypted {
		t.Fatalf("RosterDomain() error = %v, want ErrRosterEncrypted", err)
	}
	if _, err := AppendMissingNFSServerStub(path, "nexus"); err != ErrRosterEncrypted {
		t.Fatalf("AppendMissingNFSServerStub() error = %v, want ErrRosterEncrypted", err)
	}
}
