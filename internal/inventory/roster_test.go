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

func TestRosterUserNames_ListsExistingUsers(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	got, err := RosterUserNames(path)
	if err != nil {
		t.Fatalf("RosterUserNames() error = %v", err)
	}
	if len(got) != 1 || got[0] != "alice" {
		t.Fatalf("RosterUserNames() = %v, want [alice]", got)
	}
}

func TestRosterGroupNames_EmptyWhenNoGroups(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	got, err := RosterGroupNames(path)
	if err != nil {
		t.Fatalf("RosterGroupNames() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("RosterGroupNames() = %v, want none", got)
	}
}

func TestSimulateAddRosterUser_ReportsNoViolationsForAValidName(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	violations, err := SimulateAddRosterUser(path, "bob")
	if err != nil {
		t.Fatalf("SimulateAddRosterUser() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("SimulateAddRosterUser() violations = %v, want none", violations)
	}
	// simulation must not have written anything.
	if got, _ := RosterUserNames(path); len(got) != 1 {
		t.Fatalf("simulation should not persist a new user, got %v", got)
	}
}

func TestSimulateAddRosterUser_ReportsViolationForBadName(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	violations, err := SimulateAddRosterUser(path, "Bob")
	if err != nil {
		t.Fatalf("SimulateAddRosterUser() error = %v", err)
	}
	if len(violations) == 0 {
		t.Fatalf("expected a violation for an uppercase user name, got none")
	}
}

func TestSimulateAddRosterUser_ReportsViolationForDuplicateName(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	violations, err := SimulateAddRosterUser(path, "alice")
	if err != nil {
		t.Fatalf("SimulateAddRosterUser() error = %v", err)
	}
	if len(violations) == 0 {
		t.Fatalf("expected a violation for a duplicate user name, got none")
	}
}

func TestAppendRosterUser_PersistsAMinimalStub(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	if err := AppendRosterUser(path, "bob"); err != nil {
		t.Fatalf("AppendRosterUser() error = %v", err)
	}
	got, err := RosterUserNames(path)
	if err != nil {
		t.Fatalf("RosterUserNames() error = %v", err)
	}
	if len(got) != 2 || got[0] != "alice" || got[1] != "bob" {
		t.Fatalf("RosterUserNames() = %v, want [alice bob]", got)
	}
	// the roster must still validate clean after the append.
	violations, err := ValidateRosterFile(path)
	if err != nil {
		t.Fatalf("ValidateRosterFile() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected the roster to still pass validation after append, got %v", violations)
	}
}

func TestAppendRosterUser_NeverTouchesUnrelatedContent(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureWithNFS)
	before := readFileHelper(t, path)

	if err := AppendRosterUser(path, "bob"); err != nil {
		t.Fatalf("AppendRosterUser() error = %v", err)
	}

	after := readFileHelper(t, path)
	if !strings.Contains(after, "nfs1.ipa.pilot.internal") {
		t.Fatalf("expected the existing nfs section to survive the append:\n%s", after)
	}
	if before == after {
		t.Fatalf("expected the file to actually change (bob added)")
	}
}

func TestSimulateAddRosterGroup_ReportsNoViolationsForAValidNameAndCategory(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	violations, err := SimulateAddRosterGroup(path, "team-ops", "team")
	if err != nil {
		t.Fatalf("SimulateAddRosterGroup() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("SimulateAddRosterGroup() violations = %v, want none", violations)
	}
}

func TestSimulateAddRosterGroup_ReportsViolationForWrongPrefix(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	violations, err := SimulateAddRosterGroup(path, "ops-team", "team")
	if err != nil {
		t.Fatalf("SimulateAddRosterGroup() error = %v", err)
	}
	if len(violations) == 0 {
		t.Fatalf("expected a violation for a group name missing the team- prefix, got none")
	}
}

func TestAppendRosterGroup_PersistsAMinimalStub(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	if err := AppendRosterGroup(path, "team-ops", "team"); err != nil {
		t.Fatalf("AppendRosterGroup() error = %v", err)
	}
	got, err := RosterGroupNames(path)
	if err != nil {
		t.Fatalf("RosterGroupNames() error = %v", err)
	}
	if len(got) != 1 || got[0] != "team-ops" {
		t.Fatalf("RosterGroupNames() = %v, want [team-ops]", got)
	}
	violations, err := ValidateRosterFile(path)
	if err != nil {
		t.Fatalf("ValidateRosterFile() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected the roster to still pass validation after append, got %v", violations)
	}
}

func TestSimulateAddRosterUser_EncryptedFileReturnsErrRosterEncrypted(t *testing.T) {
	path := writeRosterFixture(t, "$ANSIBLE_VAULT;1.1;AES256\n633864363...\n")
	if _, err := SimulateAddRosterUser(path, "bob"); err != ErrRosterEncrypted {
		t.Fatalf("SimulateAddRosterUser() error = %v, want ErrRosterEncrypted", err)
	}
	if err := AppendRosterUser(path, "bob"); err != ErrRosterEncrypted {
		t.Fatalf("AppendRosterUser() error = %v, want ErrRosterEncrypted", err)
	}
}
