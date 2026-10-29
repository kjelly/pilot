package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

// vaultSaveRefusal is one way the roster a rotation must carry the new
// password into cannot be written: setup arranges it for the workspace's
// .vault/ipa-identity.yaml (or returns a fault to inject into the inventory
// package's opens and flocks).
type vaultSaveRefusal struct {
	skipRoot string
	setup    func(t *testing.T, roster string) func(op, path string) error
}

func injectedFault(op, suffix string, errno syscall.Errno) func(string, string) error {
	return func(o, p string) error {
		if o == op && strings.HasSuffix(p, suffix) {
			return errno
		}
		return nil
	}
}

// vaultSaveRefusals enumerates every refusal inventory's lockRosterFile,
// acquireMutationLock, writeLockedRoster and PrepareRosterAdminSync can
// produce for the roster (TestRosterRefusalsAgreeAcrossPrepareProbeAndWriter
// checks each one's class there), except a path re-resolving between
// locking and checking, which only an inventory test hook can produce.
func vaultSaveRefusals() map[string]vaultSaveRefusal {
	const migrate, remove = ".pilot-migrate.lock", ".pilot-remove.lock"
	file := func(fn func(t *testing.T, roster string)) func(*testing.T, string) func(string, string) error {
		return func(t *testing.T, roster string) func(string, string) error {
			fn(t, roster)
			return nil
		}
	}
	return map[string]vaultSaveRefusal{
		"migrate lock held": {setup: file(func(t *testing.T, r string) { holdRosterFlock(t, r+migrate) })},
		"remove lock held":  {setup: file(func(t *testing.T, r string) { holdRosterFlock(t, r+remove) })},
		"lock file not openable": {skipRoot: "root opens any lock file", setup: file(func(t *testing.T, r string) {
			writeMode(t, r+migrate, 0o000)
		})},
		"lock file cannot be created": {skipRoot: "root writes any directory", setup: file(func(t *testing.T, r string) {
			dir := filepath.Dir(r)
			if err := os.Chmod(dir, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(dir, 0o700) }) //nolint:errcheck
		})},
		"lock file is a symlink": {setup: file(func(t *testing.T, r string) {
			if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), r+migrate); err != nil {
				t.Fatal(err)
			}
		})},
		"lock file is a directory": {setup: file(func(t *testing.T, r string) {
			if err := os.Mkdir(r+migrate, 0o700); err != nil {
				t.Fatal(err)
			}
		})},
		"lock file is a FIFO": {setup: file(func(t *testing.T, r string) {
			if err := syscall.Mkfifo(r+remove, 0o600); err != nil {
				t.Fatal(err)
			}
		})},
		"lock file has another name": {setup: file(func(t *testing.T, r string) {
			writeMode(t, r+migrate, 0o600)
			if err := os.Link(r+migrate, r+".other-name"); err != nil {
				t.Fatal(err)
			}
		})},
		"lock file open EROFS (injected)": {setup: func(*testing.T, string) func(string, string) error {
			return injectedFault("open", migrate, syscall.EROFS)
		}},
		"lock file open EIO (injected)": {setup: func(*testing.T, string) func(string, string) error { return injectedFault("open", remove, syscall.EIO) }},
		"lock file open ENOSPC (injected)": {setup: func(*testing.T, string) func(string, string) error {
			return injectedFault("open", migrate, syscall.ENOSPC)
		}},
		"flock EIO (injected)": {setup: func(t *testing.T, r string) func(string, string) error {
			writeMode(t, r+remove, 0o600) // so the plan's probe flocks it too
			return injectedFault("flock", remove, syscall.EIO)
		}},
		"roster not writable": {skipRoot: "root writes a 0400 roster (TestVaultSaveRosterSyncParity/unwritable_roster)", setup: file(func(t *testing.T, r string) {
			if err := os.Chmod(r, 0o400); err != nil {
				t.Fatal(err)
			}
		})},
		"roster open EROFS (injected)": {setup: func(*testing.T, string) func(string, string) error {
			return injectedFault("open", ".vault/ipa-identity.yaml", syscall.EROFS)
		}},
		// An error no inventory sentinel classifies: the save refuses on
		// errors it does not recognise too (fail closed).
		"roster path cannot be resolved (injected)": {setup: func(*testing.T, string) func(string, string) error {
			return injectedFault("resolve", ".vault/ipa-identity.yaml", syscall.EIO)
		}},
		"roster open EIO (injected)": {setup: func(*testing.T, string) func(string, string) error {
			return injectedFault("open", ".vault/ipa-identity.yaml", syscall.EIO)
		}},
	}
}

func writeMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, nil, mode); err != nil {
		t.Fatal(err)
	}
}

// Every refusal of the roster a rotation must update refuses the whole
// save on every front-end — the terminal router, --actions, a plan and an
// apply: the error says the vault was not saved and names the roster (the
// plan the real workspace's paths, not its scratch copy's), carries no
// password, and the vault and the roster are byte-identical (PR #148 round
// 6, P2-1; P3-5 for the plan's paths).
func TestVaultSaveRefusesEveryRosterWriteRefusal(t *testing.T) {
	for name, cause := range vaultSaveRefusals() {
		t.Run(name, func(t *testing.T) {
			if cause.skipRoot != "" && os.Geteuid() == 0 {
				t.Skip(cause.skipRoot)
			}
			t.Setenv(parityEnv, "New-pass_2")
			for _, frontEnd := range []string{"terminal router", "--actions", "plan", "apply"} {
				t.Run(frontEnd, func(t *testing.T) {
					dir := t.TempDir()
					vault, roster := parityWorkspace(t, dir, syncTestRoster(`"Old-pass_1"`))
					if fault := cause.setup(t, roster); fault != nil {
						t.Cleanup(inventory.InjectFileFault(fault))
					}
					before := snapshotFiles(t, vault, roster)
					run := parityFrontEnds()[frontEnd](t, dir)
					assertUnchanged(t, before)
					if run.err == nil {
						t.Fatal("the save went ahead")
					}
					msg := run.err.Error()
					if !strings.Contains(msg, vault+" was not saved") || !strings.Contains(msg, "roster .vault/ipa-identity.yaml was not written") {
						t.Errorf("error does not say the vault was not saved and name the roster: %v", run.err)
					}
					for _, leak := range []string{"Old-pass_1", "New-pass_2", "pilot-edit-plan-"} {
						if strings.Contains(msg, leak) {
							t.Errorf("error contains %q: %v", leak, run.err)
						}
					}
					if errors.Is(run.err, inventory.ErrRosterNeedsHandEdit) {
						t.Errorf("refusal classed as a hand-edit case: %v", run.err)
					}
				})
			}
		})
	}
}
