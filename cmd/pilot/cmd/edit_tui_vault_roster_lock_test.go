package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

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
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", Value: syncNewPassword},
		{Action: "save_vault", File: "main.yaml"},
	}}); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	return r.banner
}

// Through the real save path: a workspace roster that links to a roster
// another pilot process holds on its real path is reported as not synced
// and left alone, the link included (PR #148 review). Unlocked, the same
// save updates the shared file and keeps the link.
func TestEditAutomationDriverVaultSyncRespectsTheLinkedRostersLock(t *testing.T) {
	for _, suffix := range []string{".pilot-remove.lock", ".pilot-migrate.lock"} {
		t.Run(suffix, func(t *testing.T) {
			dir, link, shared := linkedRosterWorkspace(t)
			before, _ := os.ReadFile(shared)
			holdRosterFlock(t, shared+suffix)

			banner := rotateMainVault(t, dir)
			if after, _ := os.ReadFile(shared); !bytes.Equal(after, before) {
				t.Fatalf("locked roster rewritten through its link:\n%s", after)
			}
			if !strings.Contains(banner, "⚠️  未同步 .vault/ipa-identity.yaml：另一個 pilot 名冊操作正鎖住它") || strings.Contains(banner, "已同步") {
				t.Errorf("banner does not report the locked roster as not synced:\n%s", banner)
			}
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

// A roster another pilot process holds, or whose lock file this user
// cannot open (a root-run pilot left it 0000), is a banner in pilot edit,
// not the end of the session: nothing is written, and once the lock is
// gone the same session writes (PR #148 re-review, F4).
func TestEditAutomationDriverBusyRosterKeepsTheSessionOpen(t *testing.T) {
	for name, block := range map[string]func(t *testing.T, roster string) (want string, unblock func()){
		"held": func(t *testing.T, roster string) (string, func()) {
			f, err := os.OpenFile(roster+".pilot-remove.lock", os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			return "另一個 pilot 名冊操作正鎖住它", func() { f.Close() }
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
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
			writeSyncFile(t, roster, syncTestRoster(`"Admin-pass_1"`))
			want, unblock := block(t, roster)
			before, _ := os.ReadFile(roster)

			r := newEditRouterModel(dir)
			d := automationDriver{dir: dir}
			if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{{Action: "create_user", User: "alice"}}}); err != nil {
				t.Fatalf("driver.run() error = %v; the session must survive a busy roster", err)
			}
			if r.err != nil || r.quit {
				t.Fatalf("session ended: err=%v quit=%v", r.err, r.quit)
			}
			if !strings.Contains(r.banner, "⚠️  未寫入 "+roster+"：") || !strings.Contains(r.banner, want) {
				t.Fatalf("banner does not report the busy roster (%q):\n%s", want, r.banner)
			}
			if after, _ := os.ReadFile(roster); !bytes.Equal(after, before) {
				t.Fatalf("busy roster written:\n%s", after)
			}

			unblock()
			if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{{Action: "create_user", User: "bob"}}}); err != nil {
				t.Fatalf("same session after the lock is gone: %v", err)
			}
			if after, _ := os.ReadFile(roster); !bytes.Contains(after, []byte("bob")) || bytes.Contains(after, []byte("alice")) {
				t.Fatalf("roster after retry:\n%s", after)
			}
		})
	}
}

// `ansible-vault edit` of an encrypted .vault/ file that may be a roster
// runs under the roster lock, so no other roster writer saves while it is
// open; a held roster is a banner, not an editor; the deploy vault itself
// is not locked (PR #148 re-review, F6).
func TestAnsibleVaultEditHoldsTheRosterLock(t *testing.T) {
	bin := t.TempDir()
	writeSyncFile(t, filepath.Join(bin, "ansible-vault"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(bin, "ansible-vault"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dir := t.TempDir()
	roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	mainVault := filepath.Join(dir, ".vault", "main.yaml")
	for _, path := range []string{roster, mainVault} {
		writeSyncFile(t, path, "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n")
	}

	r := newEditRouterModel(dir)
	if cmd := pushAnsibleVaultShellout(&r, dir, roster); cmd == nil || r.err != nil {
		t.Fatalf("shell-out not started: err=%v", r.err)
	}
	if _, err := inventory.HoldRosterLock(roster); !errors.Is(err, inventory.ErrMutationLocked) {
		t.Fatalf("roster lock while ansible-vault edit runs: error = %v, want ErrMutationLocked", err)
	}
	model, _ := r.Update(vaultShelloutDoneMsg{dir: dir, path: roster})
	r = model.(editRouterModel)
	release, err := inventory.HoldRosterLock(roster)
	if err != nil {
		t.Fatalf("roster lock still held after ansible-vault edit exited: %v", err)
	}

	busy := newEditRouterModel(dir)
	pushAnsibleVaultShellout(&busy, dir, roster)
	if busy.err != nil || busy.releaseVaultEdit != nil || !strings.Contains(busy.banner, "⚠️  未寫入 "+roster+"：另一個 pilot 名冊操作正鎖住它") {
		t.Fatalf("held roster: err=%v holding=%v banner=%q", busy.err, busy.releaseVaultEdit != nil, busy.banner)
	}
	release() //nolint:errcheck

	deploy := newEditRouterModel(dir)
	pushAnsibleVaultShellout(&deploy, dir, mainVault)
	if deploy.releaseVaultEdit != nil {
		t.Fatal("the deploy vault was locked as a roster")
	}
}
