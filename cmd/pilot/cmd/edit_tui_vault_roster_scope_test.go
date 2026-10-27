package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// scopeWorkspace is a workspace whose rosters all hold the old password:
// the default .vault/ipa-identity.yaml referenced by an absolute
// freeipa_roster_file (as pilot edit itself writes it), one referenced
// from group_vars, and one outside the workspace altogether.
func scopeWorkspace(t *testing.T) (dir string, rosters map[string]string) {
	t.Helper()
	dir = t.TempDir()
	quotedOld := `"Old\"pass#1"`
	rosters = map[string]string{
		"default":    filepath.Join(dir, ".vault", "ipa-identity.yaml"),
		"group_vars": filepath.Join(dir, ".vault", "group-roster.yaml"),
		"external":   filepath.Join(t.TempDir(), "ipa-identity.yaml"),
	}
	for _, path := range rosters {
		writeSyncFile(t, path, syncTestRoster(quotedOld))
	}
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: "+quotedOld+"\n")
	writeSyncFile(t, filepath.Join(dir, "group_vars", "freeipa-client.yml"), "freeipa_roster_file: .vault/group-roster.yaml\n")
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n"+
		"  h1:\n    ansible_host: 10.0.0.1\n    roles: [freeipa-client]\n    freeipa_roster_file: "+rosters["default"]+"\n"+
		"  h2:\n    ansible_host: 10.0.0.2\n    roles: [freeipa-client]\n    freeipa_roster_file: "+rosters["external"]+"\n")
	return dir, rosters
}

func snapshotFiles(t *testing.T, paths ...string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out[path] = data
	}
	return out
}

func assertUnchanged(t *testing.T, before map[string][]byte) {
	t.Helper()
	for path, data := range before {
		if after, _ := os.ReadFile(path); !bytes.Equal(after, data) {
			t.Errorf("%s changed:\n%s", path, after)
		}
	}
}

func rotationScenario(steps ...editAction) editScenario {
	return editScenario{Version: 1, Steps: append([]editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", ValueEnv: "PILOT_TEST_NEW_ADMIN_PASSWORD"},
		{Action: "save_vault", File: "main.yaml"},
	}, steps...)}
}

// The vault editor writes only its own .vault/ rosters; a roster outside
// the workspace is reported, never written (PR #148 review, P1).
func TestEditAutomationDriverVaultSyncStaysInsideVault(t *testing.T) {
	dir, rosters := scopeWorkspace(t)
	external := snapshotFiles(t, rosters["external"])
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", Value: syncNewPassword},
		{Action: "save_vault", File: "main.yaml"},
	}}); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	for _, name := range []string{"default", "group_vars"} {
		if got := syncRosterPassword(t, rosters[name]); got != syncNewPassword {
			t.Errorf("%s roster freeipa.admin.password = %q, want the new password", name, got)
		}
	}
	assertUnchanged(t, external)
	if !strings.Contains(r.banner, "⚠️  未同步 "+rosters["external"]+"：不在這個 workspace 的 .vault/ 下") {
		t.Errorf("banner does not report the external roster:\n%s", r.banner)
	}
}

// A plan previews the rotation in its scratch copy and leaves every real
// file alone, the workspace's own rosters included (PR #148 review, P1).
func TestEditPlanVaultRotationLeavesRealRostersAlone(t *testing.T) {
	dir, rosters := scopeWorkspace(t)
	t.Setenv("PILOT_TEST_NEW_ADMIN_PASSWORD", syncNewPassword)
	before := snapshotFiles(t, rosters["default"], rosters["group_vars"], rosters["external"], filepath.Join(dir, ".vault", "main.yaml"))

	result, err := planEditScenario(dir, rotationScenario(), editAgentSessionOptions{})
	if err != nil {
		t.Fatalf("planEditScenario() error = %v", err)
	}
	assertUnchanged(t, before)
	for _, want := range []string{".vault/main.yaml", ".vault/ipa-identity.yaml", ".vault/group-roster.yaml"} {
		if !slices.Contains(result.AffectedFiles, want) {
			t.Errorf("plan does not preview %s: %v", want, result.AffectedFiles)
		}
	}
	for _, secret := range []string{syncOldPassword, syncNewPassword} {
		if strings.Contains(result.Diff, secret) {
			t.Fatal("plan diff leaks a password")
		}
	}
}

// An apply that fails after the rotation restores the rosters it synced
// along with the vault (PR #148 review, P1).
func TestEditApplyRollbackRestoresSyncedRosters(t *testing.T) {
	dir, rosters := scopeWorkspace(t)
	t.Setenv("PILOT_TEST_NEW_ADMIN_PASSWORD", syncNewPassword)
	before := snapshotFiles(t, rosters["default"], rosters["group_vars"], rosters["external"], filepath.Join(dir, ".vault", "main.yaml"))

	result, err := applyEditScenario(dir, "issue-146-rollback", rotationScenario(
		editAction{Action: "delete_vault_key", File: "main.yaml", Key: "no_such_key"},
	), editAgentSessionOptions{})
	if err != nil || result == nil || !result.RolledBack || result.ScenarioErr == nil {
		t.Fatalf("applyEditScenario() = %+v, %v; want the missing key to fail and roll back", result, err)
	}
	assertUnchanged(t, before)
}

// After `ansible-vault edit` of an encrypted .vault/main.yaml, pilot cannot
// see a rotation, so it says the rosters are the operator's to update.
func TestEncryptedMainVaultEditShowsRosterHint(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, ".vault", "main.yaml")
	other := filepath.Join(dir, ".vault", "other.yaml")
	for _, path := range []string{main, other} {
		writeSyncFile(t, path, "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n")
	}
	for path, want := range map[string]bool{main: true, other: false} {
		r := newEditRouterModel(dir)
		model, _ := r.Update(vaultShelloutDoneMsg{dir: dir, path: path})
		banner := model.(editRouterModel).banner
		if got := strings.Contains(banner, "加密的 .vault/main.yaml 不會自動同步名冊"); got != want {
			t.Errorf("%s: hint shown = %v, want %v (banner %q)", filepath.Base(path), got, want, banner)
		}
	}
}

// The preflight checks the editor's default roster even when no host
// references it, as the sync updates it.
func TestWarnFreeIPARosterAdminDriftChecksTheDefaultRoster(t *testing.T) {
	dir := t.TempDir()
	writeSyncFile(t, filepath.Join(dir, ".vault", "ipa-identity.yaml"), syncTestRoster(`"Stale-pass_1"`))
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: \"Vault-pass_2\"\n")
	var out bytes.Buffer
	if err := ensureFreeIPARostersCurrentSnapshot(&out, filepath.Join(dir, "inventory.yml"), deployInventorySnapshot{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "warning: "+filepath.Join(dir, ".vault", "ipa-identity.yaml")+" ") {
		t.Fatalf("no warning for the unreferenced default roster:\n%s", out.String())
	}
}
