package cmd

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/outbound"
)

// seedOutboxEvent enqueues one minimal, already-due pending event
// directly against o — standing in for Phase 4's real terminal
// publication path, which does not exist yet.
func seedOutboxEvent(t *testing.T, o *outbound.SQLiteOutbox, workspaceKey, sourceID, webhookName string) {
	t.Helper()
	draft := outbound.EventDraft{
		WorkspaceKey: workspaceKey, SourceID: sourceID, WebhookName: webhookName, WorkflowID: "wf-test",
		Operation: "deploy", Result: "success", Projection: outbound.ProjectionUserHostAccessV1, PayloadMode: "snapshot",
		Authoritative: true, StateAvailable: true, SourceComplete: true,
		TargetSnapshotID: "sha256:test",
		Now:              time.Now(),
		Finalize: func(eventID string, sequence int64) ([]byte, error) {
			return []byte(fmt.Sprintf(`{"event_id":%q,"sequence":%d}`, eventID, sequence)), nil
		},
	}
	if _, err := o.EnqueueBatch(context.Background(), []outbound.EventDraft{draft}); err != nil {
		t.Fatalf("seed EnqueueBatch: %v", err)
	}
}

func writeIntegrationsYAML(t *testing.T, dir, endpoint string) {
	t.Helper()
	content := `
schema_version: 1
source_id: test-source
webhooks:
  - name: test-hook
    enabled: true
    endpoint: ` + endpoint + `
    projection: user_host_access_v1
    events:
      - operation: deploy
        result: success
        payload: snapshot
    auth:
      type: bearer
      secret_env: PILOT_WEBHOOK_TEST_TOKEN
    tls:
      allow_insecure_http: true
`
	if err := os.WriteFile(filepath.Join(dir, "integrations.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func setUpWebhookCLITest(t *testing.T) (workspaceDir string, out *bytes.Buffer, cmd *cobra.Command) {
	t.Helper()
	workspaceDir = t.TempDir()
	dataDirPath := t.TempDir()
	dataDir = dataDirPath
	t.Cleanup(func() { dataDir = "" })
	t.Setenv("PILOT_DATA_DIR", dataDirPath)

	out = &bytes.Buffer{}
	cmd = &cobra.Command{}
	cmd.SetOut(out)
	return workspaceDir, out, cmd
}

func TestWebhookCLI_LintMissingConfig(t *testing.T) {
	dir, out, cmd := setUpWebhookCLITest(t)
	webhookLintDir = dir
	if err := runWebhookLint(cmd, nil); err != nil {
		t.Fatalf("runWebhookLint: %v", err)
	}
	if !strings.Contains(out.String(), "disabled") {
		t.Fatalf("expected a disabled message for a missing integrations.yaml, got %q", out.String())
	}
}

func TestWebhookCLI_LintValidConfigAndMissingSecretWarning(t *testing.T) {
	dir, out, cmd := setUpWebhookCLITest(t)
	writeIntegrationsYAML(t, dir, "https://example.invalid/hook")
	webhookLintDir = dir
	os.Unsetenv("PILOT_WEBHOOK_TEST_TOKEN")

	if err := runWebhookLint(cmd, nil); err != nil {
		t.Fatalf("runWebhookLint: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "integrations.yaml valid") {
		t.Fatalf("expected a valid confirmation, got %q", got)
	}
	if !strings.Contains(got, "PILOT_WEBHOOK_TEST_TOKEN") {
		t.Fatalf("expected a missing-secret-env warning naming the variable, got %q", got)
	}
}

func TestWebhookCLI_StatusShowsZeroCountsForFreshConfig(t *testing.T) {
	dir, out, cmd := setUpWebhookCLITest(t)
	writeIntegrationsYAML(t, dir, "https://example.invalid/hook")
	webhookStatusDir = dir

	if err := runWebhookStatus(cmd, nil); err != nil {
		t.Fatalf("runWebhookStatus: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "test-hook") {
		t.Fatalf("expected test-hook in status output, got %q", got)
	}
	if !strings.Contains(got, "NAME") {
		t.Fatalf("expected a header row, got %q", got)
	}
}

func TestWebhookCLI_FlushDeliversDueEvent(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	dir, out, cmd := setUpWebhookCLITest(t)
	writeIntegrationsYAML(t, dir, server.URL)
	t.Setenv("PILOT_WEBHOOK_TEST_TOKEN", "flush-test-secret")

	webhookFlushDir = dir
	webhookFlushName = ""
	webhookFlushForce = false
	t.Cleanup(func() { webhookFlushName = ""; webhookFlushForce = false })

	// Seed one due event directly via the same outbox this workspace's
	// history.db will use, mirroring what Phase 4's terminal-publication
	// path will eventually do.
	o, cfg, workspaceKey, closeFn, err := openWebhookOutbox(dir)
	if err != nil {
		t.Fatalf("openWebhookOutbox (seed): %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a parsed config")
	}
	seedOutboxEvent(t, o, workspaceKey, cfg.SourceID, "test-hook")
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}

	if err := runWebhookFlush(cmd, nil); err != nil {
		t.Fatalf("runWebhookFlush: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "delivered") {
		t.Fatalf("expected a delivered outcome, got %q", got)
	}
	if receivedAuth != "Bearer flush-test-secret" {
		t.Fatalf("Authorization header = %q, want Bearer flush-test-secret", receivedAuth)
	}

	// Status should now show it as no longer pending.
	out.Reset()
	webhookStatusDir = dir
	if err := runWebhookStatus(cmd, nil); err != nil {
		t.Fatalf("runWebhookStatus: %v", err)
	}
	// The LAST-ACK column legitimately shows the snapshot ID (design
	// spec §34.2's own example) — what must never appear is the actual
	// body/cursor JSON content or the auth secret.
	if strings.Contains(out.String(), "flush-test-secret") || strings.Contains(out.String(), `"event_id"`) {
		t.Fatalf("status output must never print raw snapshot/body JSON or secrets: %q", out.String())
	}
}
