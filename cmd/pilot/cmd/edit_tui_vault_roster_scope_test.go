package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
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
	if !strings.Contains(r.banner, "⚠️  未同步 "+rosters["external"]+"：pilot edit 只改這個 workspace .vault/ 目錄裡的") {
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

// A failed apply puts a synced roster back only while it still holds what
// the session wrote: one that another pilot process changed after reading
// the synced roster, or holds, is left as it is and named in the error so
// the operator checks it by hand — the rest of the workspace is still
// rolled back (PR #148 re-review, F2).
func TestEditApplyRollbackLeavesARosterAnotherProcessTouched(t *testing.T) {
	for name, touch := range map[string]func(t *testing.T, roster string){
		"changed since": func(t *testing.T, roster string) {
			data, _ := os.ReadFile(roster)
			writeSyncFile(t, roster, string(data)+"# saved by pilot roster after reading the synced roster\n")
		},
		"held": func(t *testing.T, roster string) {
			holdRosterFlock(t, roster+".pilot-remove.lock")
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, rosters := scopeWorkspace(t)
			t.Setenv("PILOT_TEST_NEW_ADMIN_PASSWORD", syncNewPassword)
			mainVault := filepath.Join(dir, ".vault", "main.yaml")
			before := snapshotFiles(t, rosters["group_vars"], rosters["external"], mainVault)
			var touched []byte
			opts := editAgentSessionOptions{Trace: func(event automationTraceEvent) {
				if event.Action == "save_vault" {
					touch(t, rosters["default"])
					touched, _ = os.ReadFile(rosters["default"])
				}
			}}

			_, err := applyEditScenario(dir, "issue-146-rollback-touched", rotationScenario(
				editAction{Action: "delete_vault_key", File: "main.yaml", Key: "no_such_key"},
			), opts)
			if err == nil || !strings.Contains(err.Error(), "rolled back everything except .vault/ipa-identity.yaml") || !strings.Contains(err.Error(), "by hand") {
				t.Fatalf("applyEditScenario() error = %v, want the touched roster named for a hand check", err)
			}
			if after, _ := os.ReadFile(rosters["default"]); !bytes.Equal(after, touched) {
				t.Fatalf("rollback overwrote the touched roster:\n%s", after)
			}
			assertUnchanged(t, before)
			for _, secret := range []string{syncOldPassword, syncNewPassword} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("rollback error leaks a password")
				}
			}
		})
	}
}

// A roster with two managed names — .vault/alias.yaml linking to
// .vault/ipa-identity.yaml — is restored once, and the rollback is
// complete, not a partial failure naming the second name (PR #148
// re-review).
func TestEditApplyRollbackRestoresARosterWithTwoNames(t *testing.T) {
	dir, rosters := scopeWorkspace(t)
	alias := filepath.Join(dir, ".vault", "alias.yaml")
	if err := os.Symlink("ipa-identity.yaml", alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_TEST_NEW_ADMIN_PASSWORD", syncNewPassword)
	before := snapshotFiles(t, rosters["default"], rosters["group_vars"], filepath.Join(dir, ".vault", "main.yaml"))

	result, err := applyEditScenario(dir, "issue-146-rollback-alias", rotationScenario(
		editAction{Action: "delete_vault_key", File: "main.yaml", Key: "no_such_key"},
	), editAgentSessionOptions{})
	if err != nil || result == nil || !result.RolledBack {
		t.Fatalf("applyEditScenario() = %+v, %v; want a complete rollback", result, err)
	}
	assertUnchanged(t, before)
	assertLinkTo(t, alias, "ipa-identity.yaml")
}

// A roster this session never wrote, which another pilot process changed
// meanwhile, is that process's change: the rollback leaves it and is no
// partial failure (PR #148 re-review).
func TestEditApplyRollbackKeepsARosterTheSessionNeverWrote(t *testing.T) {
	dir, _ := scopeWorkspace(t)
	other := filepath.Join(dir, ".vault", "team.yaml")
	writeSyncFile(t, other, syncTestRoster(`"Team-pass_9"`))
	t.Setenv("PILOT_TEST_NEW_ADMIN_PASSWORD", syncNewPassword)
	var changed []byte
	opts := editAgentSessionOptions{Trace: func(event automationTraceEvent) {
		if event.Action == "save_vault" {
			data, _ := os.ReadFile(other)
			writeSyncFile(t, other, string(data)+"# saved by pilot roster\n")
			changed, _ = os.ReadFile(other)
		}
	}}
	result, err := applyEditScenario(dir, "issue-146-rollback-other", rotationScenario(
		editAction{Action: "delete_vault_key", File: "main.yaml", Key: "no_such_key"},
	), opts)
	if err != nil || result == nil || !result.RolledBack {
		t.Fatalf("applyEditScenario() = %+v, %v; want a complete rollback", result, err)
	}
	if after, _ := os.ReadFile(other); !bytes.Equal(after, changed) {
		t.Fatalf("rollback undid another process's change:\n%s", after)
	}
}

// nestedVarsWorkspace sets freeipa_roster_file only in nested vars files,
// which Ansible reads but a plan's scratch copy does not hold
// (managedFileEntries copies the top of group_vars/ and host_vars/): a
// .vault/ roster the save syncs, and a relative reference outside .vault/
// the save reports. Both rosters hold the old password.
func nestedVarsWorkspace(t *testing.T) (dir, synced, outside string) {
	t.Helper()
	dir = t.TempDir()
	quotedOld := `"Old\"pass#1"`
	synced = filepath.Join(dir, ".vault", "other.yaml")
	outside = filepath.Join(dir, "rosters", "outside.yaml")
	for _, path := range []string{synced, outside} {
		writeSyncFile(t, path, syncTestRoster(quotedOld))
	}
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: "+quotedOld+"\n")
	writeSyncFile(t, filepath.Join(dir, "group_vars", "freeipa-client", "main.yml"), "freeipa_roster_file: .vault/other.yaml\n")
	writeSyncFile(t, filepath.Join(dir, "host_vars", "h2", "main.yml"), "freeipa_roster_file: rosters/outside.yaml\n")
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n"+
		"  h1:\n    ansible_host: 10.0.0.1\n    roles: [freeipa-client]\n"+
		"  h2:\n    ansible_host: 10.0.0.2\n    roles: [freeipa-client]\n")
	return dir, synced, outside
}

// A plan finds the rosters nested vars files name, as the apply does: it
// previews the .vault/ roster the apply syncs, fails where the apply fails
// when that roster is busy, and reports the relative reference outside
// .vault/ with the apply's warning — while leaving every real file alone.
func TestEditPlanAndApplyAgreeOnNestedVarsRosterReferences(t *testing.T) {
	t.Setenv("PILOT_TEST_NEW_ADMIN_PASSWORD", syncNewPassword)
	t.Run("synced and reported", func(t *testing.T) {
		dir, synced, outside := nestedVarsWorkspace(t)
		before := snapshotFiles(t, synced, outside, filepath.Join(dir, ".vault", "main.yaml"))
		plan, err := planEditScenario(dir, rotationScenario(), editAgentSessionOptions{})
		if err != nil {
			t.Fatalf("planEditScenario() error = %v", err)
		}
		assertUnchanged(t, before)
		apply, err := applyEditScenario(dir, "issue-146-nested-vars", rotationScenario(), editAgentSessionOptions{})
		if err != nil || apply.RolledBack {
			t.Fatalf("applyEditScenario() = %+v, %v", apply, err)
		}
		if got := syncRosterPassword(t, synced); got != syncNewPassword {
			t.Fatalf("apply did not sync %s", synced)
		}
		if !slices.Equal(plan.AffectedFiles, apply.AffectedFiles) || !slices.Contains(plan.AffectedFiles, ".vault/other.yaml") {
			t.Errorf("plan AffectedFiles %v, apply %v; want the same, with .vault/other.yaml", plan.AffectedFiles, apply.AffectedFiles)
		}
		if !slices.Equal(plan.Warnings, apply.Warnings) {
			t.Errorf("plan warnings %q differ from apply warnings %q", plan.Warnings, apply.Warnings)
		}
		if !slices.ContainsFunc(apply.Warnings, func(w string) bool { return strings.HasPrefix(w, "未同步 rosters/outside.yaml：") }) {
			t.Errorf("apply warnings do not name rosters/outside.yaml: %q", apply.Warnings)
		}
	})
	t.Run("busy", func(t *testing.T) {
		dir, synced, outside := nestedVarsWorkspace(t)
		busyRosterCases()["held"](t, synced)
		before := snapshotFiles(t, synced, outside, filepath.Join(dir, ".vault", "main.yaml"))
		if _, err := planEditScenario(dir, rotationScenario(), editAgentSessionOptions{}); !errors.Is(err, inventory.ErrMutationLocked) {
			t.Errorf("planEditScenario() error = %v, want the busy roster to fail the plan", err)
		}
		apply, err := applyEditScenario(dir, "issue-146-nested-vars-busy", rotationScenario(), editAgentSessionOptions{})
		if apply != nil && apply.RolledBack {
			err = apply.ScenarioErr
		}
		if !errors.Is(err, inventory.ErrMutationLocked) {
			t.Errorf("applyEditScenario() error = %v, want the busy roster to fail the apply", err)
		}
		assertUnchanged(t, before)
	})
}
