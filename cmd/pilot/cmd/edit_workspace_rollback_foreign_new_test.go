package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A roster another pilot process (pilot roster add-user, pilot access,
// decommission) creates in .vault/ while an apply runs is that process's:
// the apply's snapshot does not have it and its journal recorded no write to
// it, so the rollback cannot tell it from a file the session created by its
// bytes before the apply — it must still not remove it (PR #148 review of
// 374a7ca4, P2: a new roster was deleted silently, RolledBack=true, no
// warning).

const foreignNewRosterName = ".vault/ipa-identity.yaml"

// A new roster appears between two steps: the rollback keeps it and says so.
func TestEditApplyRollbackKeepsARosterAnotherProcessCreatedBetweenSteps(t *testing.T) {
	dir := t.TempDir()
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	theirs := syncTestRoster(`"Other-pass_9"`)
	opts := editAgentSessionOptions{Trace: func(event automationTraceEvent) {
		if event.Step == 1 {
			writeSyncFile(t, roster, theirs)
		}
	}}
	result, err := applyEditScenario(dir, "issue-146-new-between", editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-01"},
		failingStep,
	}}, opts)
	assertRollbackKeptTheirChange(t, dir, result, err, roster, []byte(theirs))
	if !slices.ContainsFunc(result.Warnings, func(w string) bool { return strings.Contains(w, foreignNewRosterName) }) {
		t.Errorf("warnings %q do not name the kept roster", result.Warnings)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "hosts.yml")); string(got) != "hosts: {}\n" {
		t.Errorf("hosts.yml was not rolled back: %q", got)
	}
}

// A new roster appears while a step ran: pilot cannot tell whose it is, so
// it is left for a hand check — never removed.
func TestEditApplyRollbackLeavesARosterAnotherProcessCreatedDuringAStep(t *testing.T) {
	dir := t.TempDir()
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	roster := filepath.Join(dir, ".vault", "late-roster.yaml")
	theirs := syncTestRoster(`"Other-pass_9"`)
	step := 0
	opts := editAgentSessionOptions{BeforeStep: func() {
		if step++; step == 2 {
			writeSyncFile(t, roster, theirs)
		}
	}}
	result, err := applyEditScenario(dir, "issue-146-new-during", editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-01"},
		{Action: "save_hosts"},
		failingStep,
	}}, opts)
	if err == nil || result != nil || !strings.Contains(err.Error(), ".vault/late-roster.yaml (it changed while a step ran") || !strings.Contains(err.Error(), "by hand") {
		t.Fatalf("applyEditScenario() = %+v, %v; want the new roster left for a hand check", result, err)
	}
	if got, _ := os.ReadFile(roster); string(got) != theirs {
		t.Fatalf("rollback removed or changed a roster it did not write: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "hosts.yml")); string(got) != "hosts: {}\n" {
		t.Errorf("hosts.yml was not rolled back: %q", got)
	}
}

// A new ansible-vault encrypted file another process created is no file the
// session can have made: kept, as a roster would be.
func TestEditApplyRollbackKeepsAnEncryptedFileAnotherProcessCreated(t *testing.T) {
	dir := t.TempDir()
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	vault := filepath.Join(dir, ".vault", "keycloak.yaml")
	theirs := "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n"
	opts := editAgentSessionOptions{Trace: func(event automationTraceEvent) {
		if event.Step == 1 {
			writeSyncFile(t, vault, theirs)
		}
	}}
	result, err := applyEditScenario(dir, "issue-146-new-encrypted", editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-01"},
		failingStep,
	}}, opts)
	assertRollbackKeptTheirChange(t, dir, result, err, vault, []byte(theirs))
}

// A new roster-shaped file with a mapping another process created, under a
// name the workspace does not reference, is kept too.
func TestEditApplyRollbackKeepsARosterShapedFileAnotherProcessCreated(t *testing.T) {
	dir := t.TempDir()
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	roster := filepath.Join(dir, ".vault", "team.yaml")
	theirs := syncTestRoster(`"Team-pass_9"`)
	opts := editAgentSessionOptions{Trace: func(event automationTraceEvent) {
		if event.Step == 1 {
			writeSyncFile(t, roster, theirs)
		}
	}}
	result, err := applyEditScenario(dir, "issue-146-new-shaped", editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-01"},
		failingStep,
	}}, opts)
	assertRollbackKeptTheirChange(t, dir, result, err, roster, []byte(theirs))
}

// What the session itself creates is still removed: a scalar-only plain
// vault file the vault editor wrote, and a roster the session's own writer
// journaled.
func TestEditApplyRollbackStillRemovesWhatTheSessionCreated(t *testing.T) {
	t.Run("a scalar-only vault file the vault editor created", func(t *testing.T) {
		dir := t.TempDir()
		writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
		extra := filepath.Join(dir, ".vault", "extra.yaml")
		result, err := applyEditScenario(dir, "issue-146-new-plain", editScenario{Version: 1, Steps: []editAction{
			{Action: "add_vault_key", File: "extra.yaml", Key: "some_secret", Value: "x"},
			{Action: "save_vault", File: "extra.yaml"},
			failingStep,
		}}, editAgentSessionOptions{})
		if err != nil || result == nil || !result.RolledBack || len(result.Warnings) != 0 {
			t.Fatalf("applyEditScenario() = %+v, %v; want a complete rollback with no warnings", result, err)
		}
		if _, err := os.Lstat(extra); !os.IsNotExist(err) {
			t.Fatalf("the vault file the session created was not removed (lstat err=%v)", err)
		}
	})
	t.Run("a roster the session's writer created", func(t *testing.T) {
		dir := t.TempDir()
		writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
		roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
		result, err := applyEditScenario(dir, "issue-146-new-journaled", editScenario{Version: 1, Steps: []editAction{
			{Action: "create_user", User: "alice"},
			failingStep,
		}}, editAgentSessionOptions{})
		if err != nil || result == nil || !result.RolledBack || len(result.Warnings) != 0 {
			t.Fatalf("applyEditScenario() = %+v, %v; want a complete rollback with no warnings", result, err)
		}
		if _, err := os.Lstat(roster); !os.IsNotExist(err) {
			t.Fatalf("the roster the session created was not removed (lstat err=%v)", err)
		}
	})
}

// Control: a new file another process created that is neither encrypted nor
// roster-shaped nor referenced is indistinguishable from what the vault
// editor writes, so it is removed like the session's own — the documented
// limit of deciding from the bytes it holds.
func TestEditApplyRollbackRemovesAScalarOnlyNewVaultFile(t *testing.T) {
	dir := t.TempDir()
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	plain := filepath.Join(dir, ".vault", "plain.yaml")
	opts := editAgentSessionOptions{Trace: func(event automationTraceEvent) {
		if event.Step == 1 {
			writeSyncFile(t, plain, "some_secret: \"x\"\n")
		}
	}}
	result, err := applyEditScenario(dir, "issue-146-new-scalar", editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-01"},
		failingStep,
	}}, opts)
	if err != nil || result == nil || !result.RolledBack {
		t.Fatalf("applyEditScenario() = %+v, %v; want a complete rollback", result, err)
	}
	if _, err := os.Lstat(plain); !os.IsNotExist(err) {
		t.Fatalf("scalar-only new vault file survived (lstat err=%v)", err)
	}
}

// The conservative edge: the vault editor can create the default roster
// name with scalar values only; pilot cannot tell that from a roster another
// process created there, so the rollback does not remove it. It changed
// while a step ran, so it is left for a hand check, never removed.
func TestEditApplyRollbackDoesNotRemoveAScalarFileUnderTheDefaultRosterName(t *testing.T) {
	dir := t.TempDir()
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	result, err := applyEditScenario(dir, "issue-146-new-default-name", editScenario{Version: 1, Steps: []editAction{
		{Action: "add_vault_key", File: "ipa-identity.yaml", Key: "some_secret", Value: "x"},
		{Action: "save_vault", File: "ipa-identity.yaml"},
		failingStep,
	}}, editAgentSessionOptions{})
	if err == nil || result != nil || !strings.Contains(err.Error(), ".vault/ipa-identity.yaml (it changed while a step ran") {
		t.Fatalf("applyEditScenario() = %+v, %v; want the file left for a hand check", result, err)
	}
	if _, err := os.Lstat(roster); err != nil {
		t.Fatalf("the rollback removed a file that may be another process's roster: %v", err)
	}
}
