package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Which .vault/ files the rollback treats as rosters is decided from what the
// apply knew before it ran (the file's own shape, the rosters the workspace
// references) and what its journal recorded — never from the bytes a
// session left, which a vault edit can shape like anything (PR #148 review of
// 3a4d4a3, P3: a plain main.yaml that gained a `groups` key was taken for a
// roster, left "changed while a step ran", and reported as a failed
// rollback with a freeipa.admin.password hint).

func sortedRosterShapedKeys() []string {
	var keys []string
	for key := range rosterShapedKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// A plain vault file the session gives a roster-shaped key is not a roster:
// the rollback restores it byte for byte, as it does every other vault file.
func TestEditApplyRollbackRestoresAPlainVaultFileTheSessionMadeRosterShaped(t *testing.T) {
	for _, key := range sortedRosterShapedKeys() {
		t.Run(key, func(t *testing.T) {
			dir := t.TempDir()
			mainVault := filepath.Join(dir, ".vault", "main.yaml")
			writeSyncFile(t, mainVault, "ipa_admin_password: \"Admin-pass_1\"\n")
			before := snapshotFiles(t, mainVault)
			result, err := applyEditScenario(dir, "issue-146-plain-"+key, editScenario{Version: 1, Steps: []editAction{
				{Action: "add_vault_key", File: "main.yaml", Key: key, Value: "x"},
				{Action: "save_vault", File: "main.yaml"},
				failingStep,
			}}, editAgentSessionOptions{})
			if err != nil || result == nil || !result.RolledBack || len(result.Warnings) != 0 {
				t.Fatalf("applyEditScenario() = %+v, %v; want a complete rollback", result, err)
			}
			assertUnchanged(t, before)
		})
	}
}

// A plain vault file that already held a roster-shaped scalar before the
// apply, which the session deletes, is restored too.
func TestEditApplyRollbackRestoresAPlainVaultFileThatHadARosterShapedScalar(t *testing.T) {
	dir := t.TempDir()
	mainVault := filepath.Join(dir, ".vault", "main.yaml")
	writeSyncFile(t, mainVault, "ipa_admin_password: \"Admin-pass_1\"\ngroups: foo\n")
	before := snapshotFiles(t, mainVault)
	result, err := applyEditScenario(dir, "issue-146-plain-scalar", editScenario{Version: 1, Steps: []editAction{
		{Action: "delete_vault_key", File: "main.yaml", Key: "groups"},
		{Action: "save_vault", File: "main.yaml"},
		failingStep,
	}}, editAgentSessionOptions{})
	if err != nil || result == nil || !result.RolledBack {
		t.Fatalf("applyEditScenario() = %+v, %v; want a complete rollback", result, err)
	}
	assertUnchanged(t, before)
}

// What is a roster stays one: a roster-shaped file with a mapping or a list
// — which the vault editor never writes — another process changed while a
// step ran is left for a hand check, with the password hint; a scalar-only
// file the workspace references as its roster is kept as the roster it is
// (restoring it would undo that process's change); an encrypted file is left
// without the password hint, which is about a plaintext roster; and a roster
// the session created itself is removed.
func TestEditApplyRollbackStillTreatsRostersAsRosters(t *testing.T) {
	t.Run("mapping, changed by another process while a step ran", func(t *testing.T) {
		dir := t.TempDir()
		other := filepath.Join(dir, ".vault", "team.yaml")
		writeSyncFile(t, other, syncTestRoster(`"Team-pass_9"`))
		var theirs []byte
		step := 0
		opts := editAgentSessionOptions{BeforeStep: func() {
			if step++; step == 2 {
				theirs = saveAsAnotherProcess(t, other, "while save_hosts ran")
			}
		}}
		result, err := applyEditScenario(dir, "issue-146-class-mapping", editScenario{Version: 1, Steps: []editAction{
			{Action: "create_host", Host: "web-01"},
			{Action: "save_hosts"},
			failingStep,
		}}, opts)
		if err == nil || result != nil || !strings.Contains(err.Error(), ".vault/team.yaml (it changed while a step ran") || !strings.Contains(err.Error(), "freeipa.admin.password") {
			t.Fatalf("applyEditScenario() = %+v, %v; want the roster left, with the password hint", result, err)
		}
		if got, _ := os.ReadFile(other); !bytes.Equal(got, theirs) {
			t.Fatalf("rollback reverted a roster it did not write:\n%s", got)
		}
	})
	t.Run("scalar-only roster the workspace references", func(t *testing.T) {
		dir := t.TempDir()
		roster := filepath.Join(dir, ".vault", "scalar-roster.yaml")
		writeSyncFile(t, roster, "schema_version: 3\n")
		writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n  h1:\n    ansible_host: 10.0.0.1\n    roles: [freeipa-client]\n    freeipa_roster_file: "+roster+"\n")
		var theirs []byte
		opts := editAgentSessionOptions{Trace: func(event automationTraceEvent) {
			if event.Step == 1 {
				theirs = saveAsAnotherProcess(t, roster, "between steps")
			}
		}}
		result, err := applyEditScenario(dir, "issue-146-class-scalar", editScenario{Version: 1, Steps: []editAction{
			{Action: "create_host", Host: "web-01"},
			failingStep,
		}}, opts)
		assertRollbackKeptTheirChange(t, dir, result, err, roster, theirs)
	})
	t.Run("encrypted, changed by another process while a step ran", func(t *testing.T) {
		dir := t.TempDir()
		vault := filepath.Join(dir, ".vault", "keycloak.yaml")
		writeSyncFile(t, vault, "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n")
		writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
		var theirs []byte
		step := 0
		opts := editAgentSessionOptions{BeforeStep: func() {
			if step++; step == 2 {
				data, _ := os.ReadFile(vault)
				theirs = append(data, []byte("6667\n")...)
				if err := os.WriteFile(vault, theirs, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}}
		result, err := applyEditScenario(dir, "issue-146-class-encrypted", editScenario{Version: 1, Steps: []editAction{
			{Action: "create_host", Host: "web-01"},
			{Action: "save_hosts"},
			failingStep,
		}}, opts)
		if err == nil || result != nil || !strings.Contains(err.Error(), ".vault/keycloak.yaml (it changed while a step ran") || !strings.Contains(err.Error(), "by hand") {
			t.Fatalf("applyEditScenario() = %+v, %v; want the encrypted file left for a hand check", result, err)
		}
		if strings.Contains(err.Error(), "freeipa.admin.password") {
			t.Errorf("error gives the roster password hint for an encrypted file that is not a roster: %v", err)
		}
		if got, _ := os.ReadFile(vault); !bytes.Equal(got, theirs) {
			t.Fatalf("rollback reverted an encrypted file it never wrote:\n%s", got)
		}
	})
	t.Run("created by the session", func(t *testing.T) {
		dir := t.TempDir()
		writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
		roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
		result, err := applyEditScenario(dir, "issue-146-class-created", editScenario{Version: 1, Steps: []editAction{
			{Action: "create_user", User: "alice"},
			failingStep,
		}}, editAgentSessionOptions{})
		if err != nil || result == nil || !result.RolledBack {
			t.Fatalf("applyEditScenario() = %+v, %v; want a complete rollback", result, err)
		}
		if _, err := os.Lstat(roster); !os.IsNotExist(err) {
			t.Fatalf("the roster the session created was not removed (lstat err=%v)", err)
		}
	})
}
