package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// `ansible-vault edit` locks only a file that is one of the workspace's
// rosters: any other encrypted .vault/ file gets no lock files, and opens
// even where none could be created (PR #148 review, P3). A referenced
// roster under any name still locks.
func TestAnsibleVaultEditLocksOnlyRosters(t *testing.T) {
	ran, release := fakeAnsibleVault(t)
	writeSyncFile(t, release, "")
	dir, _, _ := encryptedVaultWorkspace(t)
	keycloak := filepath.Join(dir, ".vault", "keycloak.yaml")
	team := filepath.Join(dir, ".vault", "team.yaml")
	for _, path := range []string{keycloak, team} {
		writeSyncFile(t, path, "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n")
	}
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n  h1:\n    ansible_host: 10.0.0.1\n    freeipa_roster_file: .vault/team.yaml\n")
	bin, err := exec.LookPath("ansible-vault")
	if err != nil {
		t.Fatal(err)
	}
	if edit := newVaultEditCommand(dir, bin, team); edit.roster != team {
		t.Fatalf("the referenced roster %s would not be locked", team)
	}

	edit := newVaultEditCommand(dir, bin, keycloak)
	if edit.roster != "" {
		t.Fatalf("keycloak.yaml would be locked as a roster")
	}
	if os.Geteuid() != 0 {
		// No lock file could be created here: the editor opens regardless.
		vaultDir := filepath.Join(dir, ".vault")
		if err := os.Chmod(vaultDir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(vaultDir, 0o700) }) //nolint:errcheck
	}
	if err := edit.Run(); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if _, err := os.Stat(ran); err != nil {
		t.Fatal("the editor did not run")
	}
	if locks, _ := filepath.Glob(keycloak + ".pilot-*.lock"); len(locks) != 0 {
		t.Fatalf("lock files left beside a file that is not a roster: %v", locks)
	}
}
