package tools

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestGatherFactsValidatePath(t *testing.T) {
	tmpDir := t.TempDir()
	tft := &GatherFactsTool{
		AllowedPlaybookRoots: []string{tmpDir},
	}

	allowedPath := filepath.Join(tmpDir, "hosts.ini")
	if err := tft.ValidatePath(allowedPath); err != nil {
		t.Errorf("expected path %s to be allowed, got: %v", allowedPath, err)
	}

	otherDir := t.TempDir()
	blockedPath := filepath.Join(otherDir, "hosts.ini")
	if err := tft.ValidatePath(blockedPath); err == nil {
		t.Errorf("expected path %s to be blocked, but was allowed", blockedPath)
	}
}

func TestGatherFactsInvalidArgs(t *testing.T) {
	tft := &GatherFactsTool{}
	_, err := tft.Execute(context.Background(), json.RawMessage(`{invalid`))
	if err == nil {
		t.Error("expected error for invalid JSON arguments, got nil")
	}
}
