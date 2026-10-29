package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A roster bind-mounted as a single file — pilot-cli under
// `docker run -v ~/ws/.vault/ipa-identity.yaml:/ws/.vault/ipa-identity.yaml`
// — cannot be renamed over (EBUSY), so the sync writes it in place: the
// host's file gets the new password and keeps its inode, and no temp file
// is left in the container's directory. Before, every roster writer failed
// there although main wrote such a roster in place (PR #148 review, P2-2).
// Needs root to bind-mount.
func TestRosterSyncThroughASingleFileBindMount(t *testing.T) {
	requireRoot(t)
	host := filepath.Join(t.TempDir(), "ipa-identity.yaml")
	if err := os.WriteFile(host, []byte(lockTestRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(host)
	if err != nil {
		t.Fatal(err)
	}
	container := filepath.Join(t.TempDir(), "ipa-identity.yaml")
	if err := os.WriteFile(container, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(host, container, "", syscall.MS_BIND, ""); err != nil {
		if errors.Is(err, syscall.EPERM) && os.Getenv("PILOT_REQUIRE_ROOT_TESTS") != "1" {
			t.Skipf("root without CAP_SYS_ADMIN cannot bind-mount: %v", err)
		}
		t.Fatalf("bind-mount %s on %s: %v", host, container, err)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(container, 0); err != nil {
			t.Errorf("unmount %s: %v", container, err)
		}
	})
	// The premise: nothing can be renamed over the mount point.
	probe := filepath.Join(filepath.Dir(container), "probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(probe, container); !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("rename over the bind mount: %v, want EBUSY", err)
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}

	got, err := SyncRosterAdminPassword(container, "Old-pass_1", "New-pass_2")
	if err != nil || got != RosterAdminUpdated {
		t.Fatalf("SyncRosterAdminPassword(bind-mounted roster) = %v, %v; want it written in place", got, err)
	}
	if pw := decodedAdminPassword(t, mustRead(t, host)); pw != "New-pass_2" {
		t.Fatalf("host roster password = %v, want New-pass_2", pw)
	}
	after, err := os.Stat(host)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("the host's roster was replaced, not written in place")
	}
	assertNoRosterTemps(t, container)
	if err := AppendRosterUser(container, "erin"); err != nil {
		t.Fatalf("AppendRosterUser(bind-mounted roster) = %v", err)
	}
	if _, err := ValidateRosterFile(host); err != nil {
		t.Fatal(err)
	}
}
