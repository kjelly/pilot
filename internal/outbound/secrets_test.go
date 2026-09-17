package outbound

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// secretSentinels mirrors internal/spec's
// outboundWebhookSecretSentinels (design spec §46.7) — kept as a
// separate literal here deliberately (see that file's own comment):
// production code must never reference a "known secret shape".
var secretSentinels = []string{
	"PILOT-SECRET-NEVER-LEAK-123",
	"ssh-ed25519 AAAA-SECRET-KEY-FIXTURE",
}

// TestOutboundSecrets_S1: a sentinel embedded in a delivered event's
// body never appears anywhere else — outbox body_json is compacted to
// empty on delivery (§22.3), so after a successful delivery, nothing in
// the row (other than the immutable body_sha256 hash) should contain it.
func TestOutboundSecrets_S1(t *testing.T) {
	o := newTestOutbox(t)
	sentinel := secretSentinels[0]
	draft := testDraft("wf1", "ws", "src", "test-hook")
	draft.Finalize = func(eventID string, sequence int64) ([]byte, error) {
		return []byte(`{"event_id":"` + eventID + `","leaked":"` + sentinel + `"}`), nil
	}
	mustEnqueue(t, o, draft)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	claimed := claimOneForDelivery(t, o)
	d := testDispatcher(o, "s3cret")
	outcome := d.DeliverOnce(context.Background(), claimed, testWebhookConfig(server.URL))
	if !outcome.Delivered {
		t.Fatalf("expected delivered, got %+v", outcome)
	}

	var bodyJSON, targetJSON string
	if err := o.db.QueryRow(`SELECT body_json, target_snapshot_json FROM webhook_outbox WHERE event_id=?`, claimed.EventID).Scan(&bodyJSON, &targetJSON); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bodyJSON, sentinel) || strings.Contains(targetJSON, sentinel) {
		t.Fatal("sentinel must not survive terminal payload compaction")
	}
}

// TestOutboundSecrets_S2: an HMAC/bearer secret never appears in
// last_error_text after a failed delivery.
func TestOutboundSecrets_S2(t *testing.T) {
	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	secretValue := "TOP-SECRET-BEARER-TOKEN-XYZ"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	claimed := claimOneForDelivery(t, o)
	cfg := testWebhookConfig(server.URL)
	cfg.Auth = AuthConfig{Type: AuthBearer, SecretEnv: "X"}
	d := testDispatcher(o, secretValue)
	d.DeliverOnce(context.Background(), claimed, cfg)

	var errText string
	if err := o.db.QueryRow(`SELECT last_error_text FROM webhook_outbox WHERE event_id=?`, claimed.EventID).Scan(&errText); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(errText, secretValue) {
		t.Fatalf("last_error_text must never contain the auth secret, got %q", errText)
	}
}

// TestOutboundSecrets_S3: the missing_auth_secret error path names only
// the environment variable, never a value.
func TestOutboundSecrets_S3(t *testing.T) {
	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	claimed := claimOneForDelivery(t, o)
	d := testDispatcher(o, "")
	outcome := d.DeliverOnce(context.Background(), claimed, testWebhookConfig("https://example.invalid/hook"))
	if outcome.ErrorClass != ErrorClassMissingAuthSecret {
		t.Fatalf("expected missing_auth_secret, got %+v", outcome)
	}
	var errText string
	if err := o.db.QueryRow(`SELECT last_error_text FROM webhook_outbox WHERE event_id=?`, claimed.EventID).Scan(&errText); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errText, "TEST_WEBHOOK_SECRET") {
		t.Fatalf("expected the env var NAME in the error text, got %q", errText)
	}
}

// TestOutboundSecrets_S4: last_error_text is bounded (512 bytes, design
// spec §22.2) even for a very long underlying error.
func TestOutboundSecrets_S4(t *testing.T) {
	o := newTestOutbox(t)
	ctx := context.Background()
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "hook"))
	now := time.Now()
	claimed, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: now, Lease: time.Minute})
	if err != nil || claimed == nil {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	longText := strings.Repeat("x", 10000)
	if _, err := o.MarkAttemptFailed(ctx, DeliveryFailure{
		EventID: claimed.EventID, ClaimOwner: claimed.ClaimOwner, Now: now,
		Retryable: true, ErrorClass: ErrorClassNetworkError, ErrorText: longText,
		NextAttemptAt: now.Add(time.Second), ConsumeAttempt: true, MaxAttempts: 10,
	}); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := o.db.QueryRow(`SELECT last_error_text FROM webhook_outbox WHERE event_id=?`, claimed.EventID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) > 512 {
		t.Fatalf("last_error_text is %d bytes, want <= 512", len(stored))
	}
}

// TestOutboundSecrets_S5: the workspace/cursor tables' schema never
// grows a raw-secret-shaped column — a defensive column-name allowlist
// check, so a future migration can't accidentally add one unnoticed.
func TestOutboundSecrets_S5(t *testing.T) {
	o := newTestOutbox(t)
	forbidden := []string{"password", "secret", "token", "private_key", "ssh_key"}
	for _, table := range []string{"webhook_outbox", "webhook_state_cursor", "webhook_workspace_binding"} {
		rows, err := o.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var col string
			if err := rows.Scan(&col); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			lower := strings.ToLower(col)
			for _, f := range forbidden {
				if strings.Contains(lower, f) {
					rows.Close()
					t.Fatalf("table %s has a secret-shaped column %q", table, col)
				}
			}
		}
		rows.Close()
	}
}
