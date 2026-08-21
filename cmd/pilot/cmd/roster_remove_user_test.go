package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/inventory"
)

// requireAnsibleVault/writeVaultPasswordFile/encryptFileForTest/viewFileForTest
// mirror internal/inventory's roster_migrate_file_test.go helpers of the
// same name — package-private there, so the cmd package needs its own
// copies for the encrypted-roster CLI tests below.

func requireAnsibleVault(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible-vault"); err != nil {
		t.Skipf("ansible-vault not installed: %v", err)
	}
}

func writeVaultPasswordFile(t *testing.T, path, password string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func encryptFileForTest(t *testing.T, path, vaultPasswordFile string) {
	t.Helper()
	cmd := exec.Command("ansible-vault", "encrypt", "--vault-password-file", vaultPasswordFile, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ansible-vault encrypt (test setup) failed: %v: %s", err, out)
	}
}

func viewFileForTest(t *testing.T, path, vaultPasswordFile string) []byte {
	t.Helper()
	cmd := exec.Command("ansible-vault", "view", "--vault-password-file", vaultPasswordFile, path)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ansible-vault view (test verification) failed: %v", err)
	}
	return out
}

// containsString is already defined package-wide in edit_tui_vault_backfill_test.go.

// fakeProbeRunner writes result to whatever path the invocation's -e @<file>
// extra-vars named pilot_identity_probe_output, then returns exitCode/runErr
// — simulating an ansible-playbook probe run without a real FreeIPA server.
// calls records every invocation's argv for call-count assertions (e.g.
// "Phase B must never run when Phase A already refused locally").
type fakeProbeRunner struct {
	result   string
	exitCode int
	calls    [][]string
}

func (f *fakeProbeRunner) Run(_ context.Context, args ...string) (*ansible.Result, error) {
	f.calls = append(f.calls, append([]string{}, args...))
	if f.result != "" {
		outputPath := extraVarsProbeOutputPath(args)
		if outputPath == "" {
			panic("fakeProbeRunner: could not find pilot_identity_probe_output in extra-vars")
		}
		if err := os.WriteFile(outputPath, []byte(f.result), 0o600); err != nil {
			panic(err)
		}
	}
	return &ansible.Result{ExitCode: f.exitCode, Stderr: "boom"}, nil
}

func extraVarsProbeOutputPath(args []string) string {
	for i, a := range args {
		if a == "-e" && i+1 < len(args) && len(args[i+1]) > 1 && args[i+1][0] == '@' {
			data, err := os.ReadFile(args[i+1][1:])
			if err != nil {
				return ""
			}
			var vars map[string]string
			if err := json.Unmarshal(data, &vars); err != nil {
				return ""
			}
			return vars["pilot_identity_probe_output"]
		}
	}
	return ""
}

func withFakeProbeRunner(t *testing.T, r *fakeProbeRunner) {
	t.Helper()
	rosterRemoveTestProbeRunner = r
	t.Cleanup(func() { rosterRemoveTestProbeRunner = nil })
}

const removeUserCLIFixture = `---
schema_version: 2
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: testpassword123}
users:
  - name: typo-user
    state: present
  - name: alice
    state: present
  - name: bob
    state: absent
groups:
  - name: team-platform
    category: team
    membership: {users: [typo-user], groups: []}
`

func writeRemoveUserFixture(t *testing.T) (rosterPath, inventoryPath string) {
	t.Helper()
	dir := t.TempDir()
	rosterPath = filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(removeUserCLIFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	inventoryPath = filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(inventoryPath, []byte("all:\n  hosts:\n    localhost:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return rosterPath, inventoryPath
}

// execRosterRemove resets every remove-user/remove-group flag var to its
// documented default before each Execute() — pflag/cobra do not reset a
// flag to its default when a later invocation simply omits it, so
// without this, a bool flag set by an earlier test (e.g. --dry-run) would
// silently leak into every subsequent test in this binary that forgets
// to pass it explicitly.
func execRosterRemove(t *testing.T, args []string) (string, error) {
	t.Helper()
	rosterRemoveUserInventory = "inventory.yml"
	rosterRemoveUserVaultPasswordFile = ""
	rosterRemoveUserDryRun = false
	rosterRemoveUserCascade = false
	rosterRemoveGroupInventory = "inventory.yml"
	rosterRemoveGroupVaultPasswordFile = ""
	rosterRemoveGroupDryRun = false
	rosterRemoveGroupCascade = false

	var out bytes.Buffer
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)
	err := rootCmd.Execute()
	return out.String(), err
}

func TestRosterRemoveUserCmd_NeverAppliedUnreferencedSucceeds(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveUserFixture(t)
	fake := &fakeProbeRunner{result: `{"schema_version":1,"kind":"user","name":"alice","ever_applied":false,"freeipa_state":"not_found"}`}
	withFakeProbeRunner(t, fake)

	out, err := execRosterRemove(t, []string{"roster", "remove-user", rosterPath, "alice", "-i", inventoryPath})
	if err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out)
	}
	if !strings.Contains(out, `Removed roster-only user "alice"`) {
		t.Fatalf("output = %q, want a success message", out)
	}
	names, rerr := inventory.RosterUserNames(rosterPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if containsString(names, "alice") {
		t.Fatalf("expected alice removed from disk, got %v", names)
	}
	// Two probes: Phase B + Phase D pre-write recheck (spec.md §16 TOCTOU).
	if len(fake.calls) != 2 {
		t.Fatalf("expected 2 FreeIPA probe calls, got %d", len(fake.calls))
	}
}

func TestRosterRemoveUserCmd_DryRunDoesNotMutate(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveUserFixture(t)
	fake := &fakeProbeRunner{result: `{"schema_version":1,"kind":"user","name":"alice","ever_applied":false,"freeipa_state":"not_found"}`}
	withFakeProbeRunner(t, fake)
	before, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}

	out, err := execRosterRemove(t, []string{"roster", "remove-user", rosterPath, "alice", "-i", inventoryPath, "--dry-run"})
	if err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out)
	}
	if !strings.Contains(out, `Would remove roster-only user "alice"`) {
		t.Fatalf("output = %q, want a dry-run message", out)
	}
	after, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("dry-run must not mutate the roster")
	}
	// Only the one Phase B probe — dry-run exits before Phase D's recheck.
	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 FreeIPA probe call for dry-run, got %d", len(fake.calls))
	}
}

func TestRosterRemoveUserCmd_ReferencedWithoutCascadeNeverProbesFreeIPA(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveUserFixture(t)
	fake := &fakeProbeRunner{result: `{"schema_version":1,"kind":"user","name":"typo-user","ever_applied":false,"freeipa_state":"not_found"}`}
	withFakeProbeRunner(t, fake)

	out, err := execRosterRemove(t, []string{"roster", "remove-user", rosterPath, "typo-user", "-i", inventoryPath})
	if err == nil {
		t.Fatalf("expected an error, output: %s", out)
	}
	if !strings.Contains(out, "resource is still referenced") || !strings.Contains(out, "groups[team-platform].membership.users") {
		t.Fatalf("output = %q, want a references report", out)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected Phase A refusal to skip the FreeIPA probe entirely (spec.md §16), got %d calls", len(fake.calls))
	}
}

func TestRosterRemoveUserCmd_ReferencedWithCascadeSucceeds(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveUserFixture(t)
	fake := &fakeProbeRunner{result: `{"schema_version":1,"kind":"user","name":"typo-user","ever_applied":false,"freeipa_state":"not_found"}`}
	withFakeProbeRunner(t, fake)

	out, err := execRosterRemove(t, []string{"roster", "remove-user", rosterPath, "typo-user", "-i", inventoryPath, "--cascade-references"})
	if err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out)
	}
	if !strings.Contains(out, "References removed: 1") {
		t.Fatalf("output = %q, want References removed: 1", out)
	}
	group, _, gerr := inventory.RosterGroup(rosterPath, "team-platform")
	if gerr != nil {
		t.Fatal(gerr)
	}
	if fmtContainsString(group, "typo-user") {
		t.Fatalf("expected typo-user cascaded out of group membership, got %v", group)
	}
}

func TestRosterRemoveUserCmd_AppliedUserDenied(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveUserFixture(t)
	fake := &fakeProbeRunner{result: `{"schema_version":1,"kind":"user","name":"alice","ever_applied":true,"freeipa_state":"active_or_preserved"}`}
	withFakeProbeRunner(t, fake)
	before, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}

	out, err := execRosterRemove(t, []string{"roster", "remove-user", rosterPath, "alice", "-i", inventoryPath})
	if err == nil {
		t.Fatalf("expected an error, output: %s", out)
	}
	if !strings.Contains(out, "FreeIPA reports an active or preserved user") {
		t.Fatalf("output = %q, want the applied-user refusal message", out)
	}
	after, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("roster bytes must remain unchanged when the user is applied")
	}
}

func TestRosterRemoveUserCmd_StateAbsentDenied(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveUserFixture(t)
	fake := &fakeProbeRunner{}
	withFakeProbeRunner(t, fake)

	out, err := execRosterRemove(t, []string{"roster", "remove-user", rosterPath, "bob", "-i", inventoryPath})
	if err == nil {
		t.Fatalf("expected an error, output: %s", out)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected the local state:absent rejection to skip the FreeIPA probe, got %d calls", len(fake.calls))
	}
}

func TestRosterRemoveUserCmd_ProbeFailureDeniedAndRosterUnchanged(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveUserFixture(t)
	before, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeProbeRunner{exitCode: 4} // no result written: simulates an unreachable host
	withFakeProbeRunner(t, fake)

	out, err := execRosterRemove(t, []string{"roster", "remove-user", rosterPath, "alice", "-i", inventoryPath})
	if err == nil {
		t.Fatalf("expected an error, output: %s", out)
	}
	if !strings.Contains(out, "unable to prove that the user has never been applied") {
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

func TestRosterRemoveUserCmd_MissingUserErrors(t *testing.T) {
	rosterPath, inventoryPath := writeRemoveUserFixture(t)
	out, err := execRosterRemove(t, []string{"roster", "remove-user", rosterPath, "nobody", "-i", inventoryPath})
	if err == nil {
		t.Fatalf("expected an error, output: %s", out)
	}
}

func TestRosterRemoveUserCmd_EncryptedRosterWithoutVaultPasswordFileErrors(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(removeUserCLIFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultPasswordFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "s3cret-pw")
	encryptFileForTest(t, rosterPath, vaultPasswordFile)
	inventoryPath := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(inventoryPath, []byte("all:\n  hosts:\n    localhost:\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := execRosterRemove(t, []string{"roster", "remove-user", rosterPath, "alice", "-i", inventoryPath})
	if err == nil {
		t.Fatalf("expected an error, output: %s", out)
	}
	if !strings.Contains(out, "--vault-password-file") {
		t.Fatalf("output = %q, want a --vault-password-file hint", out)
	}
}

func TestRosterRemoveUserCmd_EncryptedRosterSucceeds(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(removeUserCLIFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultPasswordFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "s3cret-pw")
	encryptFileForTest(t, rosterPath, vaultPasswordFile)
	inventoryPath := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(inventoryPath, []byte("all:\n  hosts:\n    localhost:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeProbeRunner{result: `{"schema_version":1,"kind":"user","name":"alice","ever_applied":false,"freeipa_state":"not_found"}`}
	withFakeProbeRunner(t, fake)

	out, err := execRosterRemove(t, []string{"roster", "remove-user", rosterPath, "alice", "-i", inventoryPath, "--vault-password-file", vaultPasswordFile})
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
	if strings.Contains(string(plaintext), "name: alice") {
		t.Fatalf("expected alice removed from the re-encrypted roster:\n%s", plaintext)
	}
}

// fmtContainsString is a tiny helper for asserting a nested map no longer
// references a string value anywhere in its membership lists.
func fmtContainsString(m map[string]any, s string) bool {
	membership, _ := m["membership"].(map[string]any)
	for _, key := range []string{"users", "groups"} {
		list, _ := membership[key].([]any)
		for _, v := range list {
			if str, ok := v.(string); ok && str == s {
				return true
			}
		}
	}
	return false
}
