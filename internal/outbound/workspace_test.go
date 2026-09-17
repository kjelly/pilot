package outbound

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOutboundWorkspace_WorkspaceKeyDeterministicAndDistinct(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	k1, err := WorkspaceKey(dirA)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := WorkspaceKey(dirA)
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Fatalf("WorkspaceKey must be deterministic for the same path: %q vs %q", k1, k2)
	}
	k3, err := WorkspaceKey(dirB)
	if err != nil {
		t.Fatal(err)
	}
	if k1 == k3 {
		t.Fatal("WorkspaceKey must differ for distinct workspace paths")
	}
}

// TestOutboundDispatcher_H29Permissions (design spec §37, C29): a new
// history.db is created 0600, an existing wider-permission one is
// narrowed, and -wal/-shm sidecars are narrowed too.
func TestOutboundDispatcher_PermissionsNewFile(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("no Unix permission bits on this platform")
	}
	dbPath := filepath.Join(t.TempDir(), "history.db")
	if err := SecureHistoryDBPermissions(dbPath); err != nil {
		t.Fatalf("SecureHistoryDBPermissions (create): %v", err)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("new history.db mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestOutboundDispatcher_PermissionsNarrowsExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("no Unix permission bits on this platform")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "history.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	walPath := dbPath + "-wal"
	shmPath := dbPath + "-shm"
	if err := os.WriteFile(walPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shmPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := SecureHistoryDBPermissions(dbPath); err != nil {
		t.Fatalf("SecureHistoryDBPermissions (narrow): %v", err)
	}
	for _, p := range []string{dbPath, walPath, shmPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 0600", p, info.Mode().Perm())
		}
	}
}
