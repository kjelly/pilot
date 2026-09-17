// workspace.go implements design spec §7.4.1's workspace_key derivation
// and §37's history.db permission securing.
package outbound

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
)

// WorkspaceKey returns the local-only identity key for workspaceDir
// (design spec §7.4.1): sha256 of the canonical (cleaned, absolute,
// symlink-resolved where possible) workspace path. It never appears on
// the wire — only source_id/webhook_name do.
func WorkspaceKey(workspaceDir string) (string, error) {
	abs, err := filepath.Abs(workspaceDir)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:]), nil
}

// SecureHistoryDBPermissions narrows dbPath (and its -wal/-shm sidecars,
// if present) to 0600 (design spec §37) — called before AND after
// opening the store/outbox connection, so a newly-created file never has
// a wider-than-0600 window and any sidecar WAL/SHM files the driver
// creates get caught too. It is a no-op (returns nil) on platforms
// without Unix permission bits.
func SecureHistoryDBPermissions(dbPath string) error {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		// V1 has no Windows/Plan9-specific secure-storage policy; see
		// design spec §37's explicit call-out not to silently claim 0600
		// verified on a platform that doesn't support the bits.
		return nil
	}
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			f, ferr := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0o600)
			if ferr != nil {
				return ferr
			}
			return f.Close()
		}
		return err
	}
	if err := os.Chmod(dbPath, 0o600); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		sidecar := dbPath + suffix
		if _, err := os.Stat(sidecar); err == nil {
			if err := os.Chmod(sidecar, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}
