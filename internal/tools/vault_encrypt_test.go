package tools

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestVaultEncryptValidatePath(t *testing.T) {
	tmpDir := t.TempDir()
	tft := &VaultEncryptStringTool{
		AllowedPlaybookRoots: []string{tmpDir},
	}

	allowedPath := filepath.Join(tmpDir, "vault-pwd.txt")
	if err := tft.ValidatePath(allowedPath); err != nil {
		t.Errorf("expected path %s to be allowed, got: %v", allowedPath, err)
	}

	otherDir := t.TempDir()
	blockedPath := filepath.Join(otherDir, "vault-pwd.txt")
	if err := tft.ValidatePath(blockedPath); err == nil {
		t.Errorf("expected path %s to be blocked, but was allowed", blockedPath)
	}
}

func TestVaultEncryptInvalidArgs(t *testing.T) {
	tft := &VaultEncryptStringTool{}
	_, err := tft.Execute(context.Background(), json.RawMessage(`{invalid`))
	if err == nil {
		t.Error("expected error for invalid JSON arguments, got nil")
	}
}
