package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kjelly/pilot/internal/inventory"
)

// linkedRosterWorkspace is a workspace whose default roster is a symlink
// to a roster shared from outside it, both holding the old password.
func linkedRosterWorkspace(t *testing.T) (dir, link, shared string) {
	t.Helper()
	dir = t.TempDir()
	sharedDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	shared = filepath.Join(sharedDir, "ipa-identity.yaml")
	writeSyncFile(t, shared, syncTestRoster(`"Old\"pass#1"`))
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: \"Old\\\"pass#1\"\n")
	link = filepath.Join(dir, ".vault", "ipa-identity.yaml")
	if err := os.Symlink(shared, link); err != nil {
		t.Fatal(err)
	}
	return dir, link, shared
}

// holdRosterFlock holds path's lock file as another pilot process would:
// `pilot roster remove-*` on the shared roster's real path, say.
func holdRosterFlock(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
}

func rotateMainVault(t *testing.T, dir string) string {
	t.Helper()
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, rotationSteps(syncNewPassword)); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	return r.banner
}

// rotationSteps sets .vault/main.yaml's ipa_admin_password to password and
// saves it.
func rotationSteps(password string) editScenario {
	return editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", Value: password},
		{Action: "save_vault", File: "main.yaml"},
	}}
}

// Through the real save path: a workspace roster that links to a roster
// another pilot process holds on its real path refuses the vault save —
// the vault, the shared roster and the link are left as they were — since
// a save that went ahead would leave the roster on the old password with
// no later save to carry it forward (PR #148 round 4, R8). Unlocked, the
// same save updates the shared file and keeps the link.
func TestEditAutomationDriverVaultSyncRespectsTheLinkedRostersLock(t *testing.T) {
	for _, suffix := range []string{".pilot-remove.lock", ".pilot-migrate.lock"} {
		t.Run(suffix, func(t *testing.T) {
			dir, link, shared := linkedRosterWorkspace(t)
			mainVault := filepath.Join(dir, ".vault", "main.yaml")
			before := snapshotFiles(t, shared, mainVault)
			holdRosterFlock(t, shared+suffix)

			r := newEditRouterModel(dir)
			d := automationDriver{dir: dir}
			err := d.run(&r, rotationSteps(syncNewPassword))
			if !errors.Is(err, inventory.ErrMutationLocked) || !strings.Contains(err.Error(), ".vault/main.yaml was not saved") {
				t.Fatalf("driver.run() error = %v; want the save refused on the locked roster", err)
			}
			assertUnchanged(t, before)
			assertLinkTo(t, link, shared)
		})
	}
	t.Run("unlocked", func(t *testing.T) {
		dir, link, shared := linkedRosterWorkspace(t)
		banner := rotateMainVault(t, dir)
		if got := syncRosterPassword(t, shared); got != syncNewPassword {
			t.Fatalf("shared roster password = %q, want the new one; banner:\n%s", got, banner)
		}
		assertLinkTo(t, link, shared)
	})
}

func assertLinkTo(t *testing.T, link, dest string) {
	t.Helper()
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is no longer a symlink (err %v)", link, err)
	}
	if got, _ := os.Readlink(link); got != dest {
		t.Fatalf("%s points at %s, want %s", link, got, dest)
	}
}

// A roster named twice — the default .vault/ipa-identity.yaml, a link, and
// a hosts.yml reference to the file it links to — is considered once,
// under its .vault/ spelling, so the sync writes and reports it once.
func TestRosterCandidatesListEachFileOnce(t *testing.T) {
	dir, link, shared := linkedRosterWorkspace(t)
	relLink := filepath.Join(dir, ".vault", "alias.yaml")
	if err := os.Symlink("ipa-identity.yaml", relLink); err != nil {
		t.Fatal(err)
	}
	got := rosterCandidates(dir, "", []string{shared, ".vault/alias.yaml", link})
	if len(got) != 1 || got[0] != link {
		t.Fatalf("rosterCandidates() = %v, want only %s", got, link)
	}
	// Referenced from outside first, the file still gets its .vault/ name.
	other := t.TempDir()
	vaultLink := filepath.Join(other, ".vault", "nfs.yaml")
	if err := os.MkdirAll(filepath.Dir(vaultLink), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shared, vaultLink); err != nil {
		t.Fatal(err)
	}
	if got := rosterCandidates(other, "", []string{shared, ".vault/nfs.yaml"}); len(got) != 1 || got[0] != vaultLink {
		t.Fatalf("rosterCandidates() = %v, want only %s", got, vaultLink)
	}
}

// busyRosterCases block a roster's writes three ways: another pilot process
// holds its lock, its lock file is one this user cannot open (a root-run
// pilot left it 0000), or the roster itself is not writable by this user
// (0400). Each returns the reason an error or banner must name, and how to
// unblock. The last two skip as root, which opens either.
func busyRosterCases() map[string]func(t *testing.T, roster string) (reason string, unblock func()) {
	return map[string]func(t *testing.T, roster string) (string, func()){
		"held": func(t *testing.T, roster string) (string, func()) {
			f, err := os.OpenFile(roster+".pilot-remove.lock", os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.Close() })
			return "another pilot process holds its lock", func() { f.Close() }
		},
		"lock file not openable": func(t *testing.T, roster string) (string, func()) {
			if os.Geteuid() == 0 {
				t.Skip("root opens any lock file")
			}
			lock := roster + ".pilot-migrate.lock"
			if err := os.WriteFile(lock, nil, 0o000); err != nil {
				t.Fatal(err)
			}
			return "exists but this user cannot open it", func() { os.Remove(lock) }
		},
		"roster not writable": func(t *testing.T, roster string) (string, func()) {
			if os.Geteuid() == 0 {
				t.Skip("root writes a 0400 roster")
			}
			if err := os.Chmod(roster, 0o400); err != nil {
				t.Fatal(err)
			}
			return "is not writable by this user", func() { os.Chmod(roster, 0o600) } //nolint:errcheck
		},
	}
}

func busyRosterWorkspace(t *testing.T) (dir, roster string) {
	t.Helper()
	dir = t.TempDir()
	roster = filepath.Join(dir, ".vault", "ipa-identity.yaml")
	writeSyncFile(t, roster, syncTestRoster(`"Admin-pass_1"`))
	return dir, roster
}

// Under automation a busy roster fails the step, naming the roster and the
// reason, and the apply rolls back: a scenario never reports a roster
// write that did not happen (PR #148 re-review, P1).
func TestEditApplyFailsOnABusyRoster(t *testing.T) {
	for name, block := range busyRosterCases() {
		t.Run(name, func(t *testing.T) {
			dir, roster := busyRosterWorkspace(t)
			reason, _ := block(t, roster)
			before, _ := os.ReadFile(roster)

			result, err := applyEditScenario(dir, "issue-146-busy", editScenario{Version: 1, Steps: []editAction{
				{Action: "create_user", User: "alice"},
			}}, editAgentSessionOptions{})
			if err != nil {
				t.Fatalf("applyEditScenario() error = %v", err)
			}
			if !result.RolledBack || result.ScenarioErr == nil {
				t.Fatalf("result = %+v; want the busy roster to fail the step and roll back", result)
			}
			if msg := result.ScenarioErr.Error(); !strings.Contains(msg, "roster "+roster+" was not written") || !strings.Contains(msg, reason) {
				t.Fatalf("step error %q does not name the roster and %q", msg, reason)
			}
			if after, _ := os.ReadFile(roster); !bytes.Equal(after, before) {
				t.Fatalf("busy roster written:\n%s", after)
			}
		})
	}
}

// Enabling freeipa-nfs-server appends the host's nfs.servers entry to the
// roster; on a busy roster that step fails under automation, instead of
// enabling the role without the entry its playbook needs (PR #148
// re-review, P1 §5.10 scan).
func TestEditApplyFailsWhenEnablingNFSOnABusyRoster(t *testing.T) {
	dir, roster := busyRosterWorkspace(t)
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: \"Admin-pass_1\"\n")
	reason, _ := busyRosterCases()["held"](t, roster)
	before, _ := os.ReadFile(roster)
	result, err := applyEditScenario(dir, "issue-146-busy-nfs", editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "nexus"},
		{Action: "enable_role", Host: "nexus", Role: "freeipa-nfs-server"},
		{Action: "save_hosts"},
	}}, editAgentSessionOptions{})
	if err != nil || result == nil || !result.RolledBack || result.ScenarioErr == nil {
		t.Fatalf("applyEditScenario() = %+v, %v; want the busy roster to fail enable_role and roll back", result, err)
	}
	if msg := result.ScenarioErr.Error(); !strings.Contains(msg, "roster "+roster+" was not written") || !strings.Contains(msg, reason) {
		t.Fatalf("step error %q does not name the roster and %q", msg, reason)
	}
	if after, _ := os.ReadFile(roster); !bytes.Equal(after, before) {
		t.Fatalf("busy roster written:\n%s", after)
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); !os.IsNotExist(err) {
		t.Fatalf("hosts.yml left behind by the rolled-back apply (stat err=%v)", err)
	}
}

// Through the MCP apply tool, a busy roster is an apply_failed error that
// rolled back, never Result "applied" (PR #148 re-review, P1).
func TestApplyHandler_BusyRosterIsAnErrorNotApplied(t *testing.T) {
	dir, roster := busyRosterWorkspace(t)
	auditDir := t.TempDir()
	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatal(err)
	}
	scenario := editScenario{Version: 1, Steps: []editAction{{Action: "create_user", User: "alice"}}}
	_, planOut, err := planHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir})(context.Background(), &mcp.CallToolRequest{}, planInput{BaseRevision: rev, Scenario: scenario})
	if err != nil || planOut.PlanID == "" {
		t.Fatalf("planHandler() = %+v, %v", planOut, err)
	}
	busyRosterCases()["held"](t, roster)
	before, _ := os.ReadFile(roster)

	result, out, err := applyHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir, WriteEnabled: true})(context.Background(), &mcp.CallToolRequest{}, applyInput{PlanID: planOut.PlanID, ExpectedRevision: rev})
	if err != nil {
		t.Fatalf("applyHandler() error = %v", err)
	}
	if result == nil || !result.IsError || out.Result == "applied" {
		t.Fatalf("busy roster reported as %+v / %+v; want an error result", result, out)
	}
	toolErr := decodeToolError(t, result)
	if toolErr.Code != mcpErrApplyFailed || !toolErr.RolledBack || !strings.Contains(toolErr.Message, "roster "+roster+" was not written") {
		t.Fatalf("toolErr = %+v; want apply_failed, rolled back, naming the roster", toolErr)
	}
	if after, _ := os.ReadFile(roster); !bytes.Equal(after, before) {
		t.Fatalf("busy roster written:\n%s", after)
	}
}

// At the terminal a busy roster is a banner and the session goes on: the
// router, driven with key presses, shows it, keeps running, and writes the
// same user once the roster is free (PR #148 re-review, F4).
func TestEditTUIBusyRosterKeepsTheSessionOpen(t *testing.T) {
	for name, block := range busyRosterCases() {
		t.Run(name, func(t *testing.T) {
			dir, roster := busyRosterWorkspace(t)
			reason, unblock := block(t, roster)
			before, _ := os.ReadFile(roster)
			r := newEditRouterModel(dir)
			addUser := func(user string) tea.Cmd {
				t.Helper()
				pushRosterAddUser(&r, dir, roster)
				var cmd tea.Cmd
				for _, key := range append(strings.Split(user, ""), "enter") {
					msg := keyTextMsg(key)
					if key == "enter" {
						msg = keyEnter()
					}
					var model tea.Model
					model, cmd = r.Update(msg)
					r = model.(editRouterModel)
				}
				return cmd
			}

			cmd := addUser("alice")
			if r.err != nil || r.quit || isQuitCmd(cmd) {
				t.Fatalf("session ended on a busy roster: err=%v quit=%v", r.err, r.quit)
			}
			want := "另一個 pilot 名冊操作正鎖住它"
			if name != "held" {
				want = reason
			}
			if !strings.Contains(r.banner, "⚠️  未寫入 "+roster+"：") || !strings.Contains(r.banner, want) {
				t.Fatalf("banner does not report the busy roster (%q):\n%s", want, r.banner)
			}
			if after, _ := os.ReadFile(roster); !bytes.Equal(after, before) {
				t.Fatalf("busy roster written:\n%s", after)
			}

			unblock()
			addUser("alice")
			if r.err != nil {
				t.Fatalf("retry in the same session: %v", r.err)
			}
			if after, _ := os.ReadFile(roster); !bytes.Contains(after, []byte("alice")) {
				t.Fatalf("roster after the retry:\n%s", after)
			}
		})
	}
}

// isQuitCmd reports whether cmd, run, quits the program.
func isQuitCmd(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	_, quit := cmd().(tea.QuitMsg)
	return quit
}

// fakeAnsibleVault puts an ansible-vault on PATH whose `edit` records that
// it ran (ran) and waits for release to exist before exiting.
func fakeAnsibleVault(t *testing.T) (ran, release string) {
	t.Helper()
	bin := t.TempDir()
	ran, release = filepath.Join(bin, "ran"), filepath.Join(bin, "release")
	script := "#!/bin/sh\ntouch '" + ran + "'\ni=0\nwhile [ ! -e '" + release + "' ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i+1)); done\n"
	writeSyncFile(t, filepath.Join(bin, "ansible-vault"), script)
	if err := os.Chmod(filepath.Join(bin, "ansible-vault"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return ran, release
}

func encryptedVaultWorkspace(t *testing.T) (dir, roster, mainVault string) {
	t.Helper()
	dir = t.TempDir()
	roster = filepath.Join(dir, ".vault", "ipa-identity.yaml")
	mainVault = filepath.Join(dir, ".vault", "main.yaml")
	for _, path := range []string{roster, mainVault} {
		writeSyncFile(t, path, "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n")
	}
	return dir, roster, mainVault
}

// `ansible-vault edit` of an encrypted .vault/ file that may be a roster
// runs under the roster lock — held while the editor runs, released when
// it exits — so no other roster writer saves while it is open; a held
// roster never opens the editor; the deploy vault is not locked (PR #148
// re-review, F6).
func TestAnsibleVaultEditHoldsTheRosterLock(t *testing.T) {
	ran, release := fakeAnsibleVault(t)
	dir, roster, mainVault := encryptedVaultWorkspace(t)
	bin, err := exec.LookPath("ansible-vault")
	if err != nil {
		t.Fatal(err)
	}
	if edit := newVaultEditCommand(dir, bin, mainVault); edit.roster != "" {
		t.Fatal("the deploy vault would be locked as a roster")
	}

	edit := newVaultEditCommand(dir, bin, roster)
	done := make(chan error, 1)
	go func() { done <- edit.Run() }()
	for i := 0; ; i++ {
		if _, err := os.Stat(ran); err == nil {
			break
		}
		if i > 200 {
			t.Fatal("the editor never ran")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := inventory.HoldRosterLock(roster); !errors.Is(err, inventory.ErrMutationLocked) {
		t.Errorf("roster lock while the editor runs: error = %v, want ErrMutationLocked", err)
	}
	writeSyncFile(t, release, "")
	if err := <-done; err != nil {
		t.Fatalf("Run() = %v", err)
	}
	unlock, err := inventory.HoldRosterLock(roster)
	if err != nil {
		t.Fatalf("roster lock still held after the editor exited: %v", err)
	}

	// Held by another process: the editor does not open, and the router
	// reports a banner and stays.
	os.Remove(ran)
	if err := newVaultEditCommand(dir, bin, roster).Run(); !errors.Is(err, inventory.ErrMutationLocked) {
		t.Fatalf("Run() on a held roster = %v, want ErrMutationLocked", err)
	}
	if _, err := os.Stat(ran); !os.IsNotExist(err) {
		t.Fatal("the editor ran on a held roster")
	}
	unlock() //nolint:errcheck
	r := newEditRouterModel(dir)
	model, _ := r.Update(vaultShelloutDoneMsg{dir: dir, path: roster, err: fmt.Errorf("roster %s: %w", roster, inventory.ErrMutationLocked)})
	r = model.(editRouterModel)
	if r.err != nil || r.quit || !strings.Contains(r.banner, "⚠️  未寫入 "+roster+"：另一個 pilot 名冊操作正鎖住它") {
		t.Fatalf("held roster after the shell-out: err=%v quit=%v banner=%q", r.err, r.quit, r.banner)
	}
}

// Under automation the driver never runs the shell-out command; the roster
// lock must not be left held by it — in the long-lived `pilot mcp` server
// every other roster writer would fail until a GC finalized the file
// (PR #148 re-review).
func TestEditApplyLeavesNoRosterLockAfterAnEncryptedFileStep(t *testing.T) {
	fakeAnsibleVault(t)
	dir, roster, _ := encryptedVaultWorkspace(t)
	result, err := applyEditScenario(dir, "issue-146-encrypted-step", editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "ipa-identity.yaml", Key: "x", Value: "y"},
	}}, editAgentSessionOptions{})
	if err != nil || result == nil || !result.RolledBack {
		t.Fatalf("applyEditScenario() = %+v, %v; want the encrypted file's step to fail and roll back", result, err)
	}
	release, err := inventory.HoldRosterLock(roster)
	if err != nil {
		t.Fatalf("roster lock left held after the apply returned: %v", err)
	}
	release() //nolint:errcheck
}
