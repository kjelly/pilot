package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// failingStep fails an apply after the steps before it ran.
var failingStep = editAction{Action: "enable_role", Host: "no-such-host", Role: "docker"}

// saveAsAnotherProcess changes the roster at path the way another pilot
// process would — a raw write, outside this process's roster writers —
// and returns the bytes it left.
func saveAsAnotherProcess(t *testing.T, path, note string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("# saved by another pilot process: "+note+"\n")...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

// assertRollbackKeptTheirChange checks a rolled-back apply that left the
// roster at path holding another process's change, theirs: complete (no
// error), the change kept and named in the warnings, and the result's
// After the workspace as it is, of revision RevisionAfter.
func assertRollbackKeptTheirChange(t *testing.T, dir string, result *editApplyResult, err error, path string, theirs []byte) {
	t.Helper()
	if err != nil || result == nil || !result.RolledBack {
		t.Fatalf("applyEditScenario() = %+v, %v; want a complete rollback", result, err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, theirs) {
		t.Fatalf("rollback did not keep the other process's change; roster now:\n%s", got)
	}
	if got := revisionOfEntries(result.After); got != result.RevisionAfter {
		t.Errorf("revision of the result's After = %s, RevisionAfter = %s", got, result.RevisionAfter)
	}
	if now, err := computeWorkspaceRevision(dir); err != nil || now != result.RevisionAfter {
		t.Errorf("workspace revision = %s (%v), RevisionAfter = %s", now, err, result.RevisionAfter)
	}
	rel := filepath.ToSlash(strings.TrimPrefix(path, dir+string(filepath.Separator)))
	if !slices.ContainsFunc(result.Warnings, func(w string) bool { return strings.Contains(w, rel) }) {
		t.Errorf("warnings %q do not name the kept roster %s", result.Warnings, rel)
	}
	for _, secret := range []string{syncOldPassword, syncNewPassword} {
		if strings.Contains(strings.Join(result.Warnings, "\n"), secret) {
			t.Fatal("rollback warnings leak a password")
		}
	}
}

// Another pilot process changes a roster after the apply's snapshot but
// before the session's sync writes it — between the set_vault_value and
// save_vault steps. The sync rewrites that roster with the new password;
// the rollback puts back what the sync replaced, the other process's
// change, not the pre-apply bytes (PR #148 review, P2: it used to restore
// the snapshot and report a clean rollback).
func TestEditApplyRollbackKeepsAChangeSavedBeforeTheSync(t *testing.T) {
	dir, rosters := scopeWorkspace(t)
	t.Setenv("PILOT_TEST_NEW_ADMIN_PASSWORD", syncNewPassword)
	before := snapshotFiles(t, rosters["group_vars"], rosters["external"], filepath.Join(dir, ".vault", "main.yaml"))
	var theirs []byte
	opts := editAgentSessionOptions{Trace: func(event automationTraceEvent) {
		if event.Action == "set_vault_value" {
			theirs = saveAsAnotherProcess(t, rosters["default"], "before the sync")
		}
	}}
	result, err := applyEditScenario(dir, "issue-146-before-sync", rotationScenario(failingStep), opts)
	assertRollbackKeptTheirChange(t, dir, result, err, rosters["default"], theirs)
	if got := syncRosterPassword(t, rosters["default"]); got != syncOldPassword {
		t.Errorf("roster password after the rollback = %q, want the old one", got)
	}
	assertUnchanged(t, before)
}

// The same during the save_vault step itself, before its sync writes the
// roster: the session's write began from the other process's bytes, so
// those are what the rollback restores.
func TestEditApplyRollbackKeepsAChangeSavedDuringTheSyncStep(t *testing.T) {
	dir, rosters := scopeWorkspace(t)
	t.Setenv("PILOT_TEST_NEW_ADMIN_PASSWORD", syncNewPassword)
	before := snapshotFiles(t, rosters["group_vars"], rosters["external"], filepath.Join(dir, ".vault", "main.yaml"))
	var theirs []byte
	step := 0
	opts := editAgentSessionOptions{BeforeStep: func() {
		if step++; step == 2 { // save_vault, before it runs
			theirs = saveAsAnotherProcess(t, rosters["default"], "during the sync step")
		}
	}}
	result, err := applyEditScenario(dir, "issue-146-during-sync", rotationScenario(failingStep), opts)
	assertRollbackKeptTheirChange(t, dir, result, err, rosters["default"], theirs)
	assertUnchanged(t, before)
}

// A roster changed while a step that writes no roster ran is not the
// session's to undo: the rollback leaves it as it is, and — since pilot
// cannot tell whose change it is — names it for a hand check instead of
// reporting a clean rollback. Everything else is still rolled back.
func TestEditApplyRollbackNeverRevertsARosterItDidNotWrite(t *testing.T) {
	dir := t.TempDir()
	roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	writeSyncFile(t, roster, syncTestRoster(`"Admin-pass_1"`))
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: \"Admin-pass_1\"\n")
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	before := snapshotFiles(t, filepath.Join(dir, "hosts.yml"), filepath.Join(dir, ".vault", "main.yaml"))
	var theirs []byte
	step := 0
	opts := editAgentSessionOptions{BeforeStep: func() {
		if step++; step == 2 { // save_hosts: writes hosts.yml, no roster
			theirs = saveAsAnotherProcess(t, roster, "while save_hosts ran")
		}
	}}
	result, err := applyEditScenario(dir, "issue-146-not-ours", editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-01"},
		{Action: "save_hosts"},
		failingStep,
	}}, opts)
	if err == nil || result != nil {
		t.Fatalf("applyEditScenario() = %+v, %v; want an error naming the roster for a hand check", result, err)
	}
	for _, want := range []string{".vault/ipa-identity.yaml (it changed while a step ran", "cannot tell whose change it is", "by hand"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not say %q: %v", want, err)
		}
	}
	if got, _ := os.ReadFile(roster); !bytes.Equal(got, theirs) {
		t.Fatalf("rollback reverted a roster it did not write:\n%s", got)
	}
	assertUnchanged(t, before)
}

// Another pilot process saves a roster between two of the session's writes
// to it: undoing the session's writes would undo that change too, so the
// rollback leaves the roster exactly as it is and names it for a hand
// check.
func TestEditApplyRollbackNamesARosterChangedBetweenTheSessionsWrites(t *testing.T) {
	dir, roster := busyRosterWorkspace(t)
	var final []byte
	opts := editAgentSessionOptions{Trace: func(event automationTraceEvent) {
		switch event.Step {
		case 1:
			saveAsAnotherProcess(t, roster, "between the writes")
		case 2:
			final, _ = os.ReadFile(roster)
		}
	}}
	result, err := applyEditScenario(dir, "issue-146-between-writes", editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "alice"},
		{Action: "create_user", User: "bob"},
		failingStep,
	}}, opts)
	if err == nil || result != nil {
		t.Fatalf("applyEditScenario() = %+v, %v; want an error naming the roster", result, err)
	}
	if !strings.Contains(err.Error(), ".vault/ipa-identity.yaml (another pilot process changed it between this apply's writes") || !strings.Contains(err.Error(), "by hand") {
		t.Errorf("error does not name the roster for a hand check: %v", err)
	}
	if got, _ := os.ReadFile(roster); !bytes.Equal(got, final) || !bytes.Contains(got, []byte("name: bob")) {
		t.Fatalf("rollback changed the roster:\n%s", got)
	}
}

// A rolled-back result's After is the workspace as the rollback left it —
// the snapshot, but for a roster another process changed and the rollback
// kept — so it and RevisionAfter (and managed-files-after.json) agree
// (PR #148 review, P3).
func TestEditApplyRolledBackResultAfterIsTheWorkspaceItLeft(t *testing.T) {
	dir, _ := scopeWorkspace(t)
	other := filepath.Join(dir, ".vault", "team.yaml")
	writeSyncFile(t, other, syncTestRoster(`"Team-pass_9"`))
	t.Setenv("PILOT_TEST_NEW_ADMIN_PASSWORD", syncNewPassword)
	var theirs []byte
	opts := editAgentSessionOptions{Trace: func(event automationTraceEvent) {
		if event.Action == "save_vault" {
			theirs = saveAsAnotherProcess(t, other, "between steps")
		}
	}}
	result, err := applyEditScenario(dir, "issue-146-after", rotationScenario(failingStep), opts)
	assertRollbackKeptTheirChange(t, dir, result, err, other, theirs)
	for _, e := range result.After {
		if e.RelPath == ".vault/team.yaml" && !bytes.Equal(e.Content, theirs) {
			t.Fatalf("result After holds team.yaml as before the apply, not as the rollback left it")
		}
	}
}

// The session's own writes to vault files — not rosters — are rolled back
// exactly as before: restored to the snapshot even though nothing records
// them but the step that changed them.
func TestEditApplyRollbackRestoresTheSessionsOwnVaultWrites(t *testing.T) {
	dir := t.TempDir()
	mainVault := filepath.Join(dir, ".vault", "main.yaml")
	keycloak := filepath.Join(dir, ".vault", "keycloak.yaml")
	writeSyncFile(t, mainVault, "ipa_admin_password: \"Admin-pass_1\"\nother: \"x\"\n")
	writeSyncFile(t, keycloak, "keycloak_admin_password: \"Kc-pass_1\"\n")
	before := snapshotFiles(t, mainVault, keycloak)
	revisionBefore, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatal(err)
	}
	result, err := applyEditScenario(dir, "issue-146-vault", editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "other", Value: "y"},
		{Action: "save_vault", File: "main.yaml"},
		{Action: "set_vault_value", File: "keycloak.yaml", Key: "keycloak_admin_password", Value: "Kc-pass_2"},
		{Action: "save_vault", File: "keycloak.yaml"},
		failingStep,
	}}, editAgentSessionOptions{})
	if err != nil || result == nil || !result.RolledBack {
		t.Fatalf("applyEditScenario() = %+v, %v; want a complete rollback", result, err)
	}
	assertUnchanged(t, before)
	if result.RevisionAfter != revisionBefore || len(result.Warnings) != 0 {
		t.Fatalf("RevisionAfter = %s (want %s), warnings %q", result.RevisionAfter, revisionBefore, result.Warnings)
	}
}
