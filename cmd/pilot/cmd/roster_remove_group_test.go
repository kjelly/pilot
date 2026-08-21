package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

const removeGroupCLIFixture = `---
schema_version: 2
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: testpassword123}
groups:
  - name: team-never-applied
    category: team
  - name: team-parent
    category: team
    membership: {users: [], groups: [team-never-applied]}
  - name: data-project-alpha-rw
    category: filesystem
  - name: team-absent-already
    category: team
    state: absent
nfs:
  servers:
    - host: nfs1.ipa.pilot.internal
      shares:
        - name: project-alpha
          ownership: {group: data-project-alpha-rw}
          acl:
            access: {named_groups: [{name: data-project-alpha-rw}]}
            default: {named_groups: []}
`

func writeRemoveGroupFixture(t *testing.T) (rosterPath, inventoryPath string) {
	t.Helper()
	dir := t.TempDir()
	rosterPath = filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(removeGroupCLIFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	inventoryPath = filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(inventoryPath, []byte("all:\n  hosts:\n    localhost:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return rosterPath, inventoryPath
}

func TestRosterRemoveGroupCmd_NeverAppliedSucceeds(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveGroupFixture(t)
	fake := &fakeProbeRunner{result: `{"schema_version":1,"kind":"group","name":"team-never-applied","ever_applied":false,"freeipa_state":"not_found","history_marker":"pilot-internal-history-g-abc"}`}
	withFakeProbeRunner(t, fake)

	out, err := execRosterRemove(t, []string{"roster", "remove-group", rosterPath, "team-never-applied", "-i", inventoryPath, "--cascade-references"})
	if err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out)
	}
	if !strings.Contains(out, `Removed roster-only group "team-never-applied"`) {
		t.Fatalf("output = %q, want a success message", out)
	}
	names, rerr := inventory.RosterGroupNames(rosterPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if containsString(names, "team-never-applied") {
		t.Fatalf("expected team-never-applied removed from disk, got %v", names)
	}
	parent, _, gerr := inventory.RosterGroup(rosterPath, "team-parent")
	if gerr != nil {
		t.Fatal(gerr)
	}
	if fmtContainsString(parent, "team-never-applied") {
		t.Fatalf("expected the membership reference cascaded away, got %v", parent)
	}
}

func TestRosterRemoveGroupCmd_DryRunDoesNotMutate(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveGroupFixture(t)
	fake := &fakeProbeRunner{result: `{"schema_version":1,"kind":"group","name":"team-never-applied","ever_applied":false,"freeipa_state":"not_found","history_marker":"pilot-internal-history-g-abc"}`}
	withFakeProbeRunner(t, fake)
	before, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}

	out, err := execRosterRemove(t, []string{"roster", "remove-group", rosterPath, "team-never-applied", "-i", inventoryPath, "--cascade-references", "--dry-run"})
	if err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out)
	}
	if !strings.Contains(out, `Would remove roster-only group "team-never-applied"`) {
		t.Fatalf("output = %q, want a dry-run message", out)
	}
	after, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("dry-run must not mutate the roster")
	}
}

func TestRosterRemoveGroupCmd_ActiveGroupDenied(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveGroupFixture(t)
	fake := &fakeProbeRunner{result: `{"schema_version":1,"kind":"group","name":"team-never-applied","ever_applied":true,"freeipa_state":"active_with_marker","history_marker":"pilot-internal-history-g-abc"}`}
	withFakeProbeRunner(t, fake)
	before, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}

	out, err := execRosterRemove(t, []string{"roster", "remove-group", rosterPath, "team-never-applied", "-i", inventoryPath, "--cascade-references"})
	if err == nil {
		t.Fatalf("expected an error, output: %s", out)
	}
	if !strings.Contains(out, "FreeIPA history marker proves this group has entered the managed lifecycle") {
		t.Fatalf("output = %q, want the applied-group refusal message", out)
	}
	after, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("roster bytes must remain unchanged when the group is applied")
	}
}

func TestRosterRemoveGroupCmd_HistoricalMarkerDenied(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveGroupFixture(t)
	fake := &fakeProbeRunner{result: `{"schema_version":1,"kind":"group","name":"team-never-applied","ever_applied":true,"freeipa_state":"historical_marker","history_marker":"pilot-internal-history-g-abc"}`}
	withFakeProbeRunner(t, fake)

	out, err := execRosterRemove(t, []string{"roster", "remove-group", rosterPath, "team-never-applied", "-i", inventoryPath, "--cascade-references"})
	if err == nil {
		t.Fatalf("expected an error, output: %s", out)
	}
	if !strings.Contains(out, "pilot-internal-history-g-abc") {
		t.Fatalf("output = %q, want the marker printed", out)
	}
}

func TestRosterRemoveGroupCmd_StateAbsentDenied(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveGroupFixture(t)
	fake := &fakeProbeRunner{}
	withFakeProbeRunner(t, fake)

	out, err := execRosterRemove(t, []string{"roster", "remove-group", rosterPath, "team-absent-already", "-i", inventoryPath})
	if err == nil {
		t.Fatalf("expected an error, output: %s", out)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected the local state:absent rejection to skip the FreeIPA probe, got %d calls", len(fake.calls))
	}
}

func TestRosterRemoveGroupCmd_NFSOwnershipBlockedEvenWithCascade(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveGroupFixture(t)
	fake := &fakeProbeRunner{result: `{"schema_version":1,"kind":"group","name":"data-project-alpha-rw","ever_applied":false,"freeipa_state":"not_found","history_marker":"pilot-internal-history-g-abc"}`}
	withFakeProbeRunner(t, fake)

	out, err := execRosterRemove(t, []string{"roster", "remove-group", rosterPath, "data-project-alpha-rw", "-i", inventoryPath, "--cascade-references"})
	if err == nil {
		t.Fatalf("expected an error: ownership.group is a blocked reference even with cascade, output: %s", out)
	}
	if !strings.Contains(out, "non-cascadeable reference") || !strings.Contains(out, "ownership.group") {
		t.Fatalf("output = %q, want the blocked-reference report", out)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected the blocked-reference refusal to skip the FreeIPA probe entirely, got %d calls", len(fake.calls))
	}
	names, rerr := inventory.RosterGroupNames(rosterPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !containsString(names, "data-project-alpha-rw") {
		t.Fatalf("roster must be unchanged on refusal, got %v", names)
	}
}

func TestRosterRemoveGroupCmd_MissingGroupErrors(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveGroupFixture(t)
	out, err := execRosterRemove(t, []string{"roster", "remove-group", rosterPath, "nobody-group", "-i", inventoryPath})
	if err == nil {
		t.Fatalf("expected an error, output: %s", out)
	}
}

func TestRosterRemoveGroupCmd_ProbeFailureDeniedAndRosterUnchanged(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveGroupFixture(t)
	before, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeProbeRunner{exitCode: 4}
	withFakeProbeRunner(t, fake)

	out, err := execRosterRemove(t, []string{"roster", "remove-group", rosterPath, "team-never-applied", "-i", inventoryPath, "--cascade-references"})
	if err == nil {
		t.Fatalf("expected an error, output: %s", out)
	}
	if !strings.Contains(out, "unable to prove that the group has never been applied") {
		t.Fatalf("output = %q, want the probe-failure message", out)
	}
	after, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("roster bytes must remain unchanged on probe failure")
	}
}

func TestRosterRemoveGroupCmd_EncryptedRosterSucceeds(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(removeGroupCLIFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultPasswordFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "s3cret-pw")
	encryptFileForTest(t, rosterPath, vaultPasswordFile)
	inventoryPath := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(inventoryPath, []byte("all:\n  hosts:\n    localhost:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeProbeRunner{result: `{"schema_version":1,"kind":"group","name":"team-never-applied","ever_applied":false,"freeipa_state":"not_found","history_marker":"pilot-internal-history-g-abc"}`}
	withFakeProbeRunner(t, fake)

	out, err := execRosterRemove(t, []string{"roster", "remove-group", rosterPath, "team-never-applied", "-i", inventoryPath, "--cascade-references", "--vault-password-file", vaultPasswordFile})
	if err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out)
	}

	installed, rerr := os.ReadFile(rosterPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(installed)), "$ANSIBLE_VAULT") {
		t.Fatalf("installed roster is not ansible-vault encrypted:\n%s", installed)
	}
	plaintext := viewFileForTest(t, rosterPath, vaultPasswordFile)
	if strings.Contains(string(plaintext), "name: team-never-applied") {
		t.Fatalf("expected team-never-applied removed from the re-encrypted roster:\n%s", plaintext)
	}
}
