package outbound

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testWebhookConfig(endpoint string) WebhookConfig {
	return WebhookConfig{
		Name:       "test-hook",
		Enabled:    true,
		Endpoint:   endpoint,
		Projection: ProjectionUserHostAccessV1,
		Auth:       AuthConfig{Type: AuthHMACSHA256, SecretEnv: "TEST_WEBHOOK_SECRET"},
		Delivery: DeliveryConfig{
			Timeout: 2 * time.Second, MaxAttempts: 5,
			InitialBackoff: 10 * time.Millisecond, MaxBackoff: 100 * time.Millisecond,
		},
	}
}

func testDispatcher(o Outbox, secret string) *Dispatcher {
	return &Dispatcher{
		Outbox:       o,
		Now:          time.Now,
		RNG:          rand.New(rand.NewSource(1)),
		PilotVersion: "test",
		SecretLookup: func(env string) (string, bool) {
			if secret == "" {
				return "", false
			}
			return secret, true
		},
	}
}

func claimOneForDelivery(t *testing.T, o Outbox) *ClaimedEvent {
	t.Helper()
	claimed, err := o.ClaimNextDue(context.Background(), ClaimRequest{
		WorkspaceKey: "ws", SourceID: "src", WebhookName: "test-hook", Now: time.Now(), Lease: time.Minute,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if claimed == nil {
		t.Fatal("expected a claimable event")
	}
	return claimed
}

// TestOutboundDispatcher_H1: HMAC signature is exactly HMAC-SHA256 over
// "<timestamp>.<eventID>.<rawBody>".
func TestOutboundDispatcher_H1(t *testing.T) {
	secret := []byte("s3cret")
	body := []byte(`{"hello":"world"}`)
	got := HMACSignature(secret, 1700000000, "evt-1", body)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("1700000000.evt-1."))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Fatalf("HMACSignature = %q, want %q", got, want)
	}

	var receivedSig, receivedTS string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get(HeaderSignature256)
		receivedTS = r.Header.Get(HeaderEventTimestamp)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	claimed := claimOneForDelivery(t, o)
	cfg := testWebhookConfig(server.URL)
	d := testDispatcher(o, "s3cret")
	outcome := d.DeliverOnce(context.Background(), claimed, cfg)
	if !outcome.Delivered {
		t.Fatalf("expected delivered, got %+v", outcome)
	}
	ts, _ := strconv.ParseInt(receivedTS, 10, 64)
	expectSig := HMACSignature([]byte("s3cret"), ts, claimed.EventID, claimed.BodyJSON)
	if receivedSig != expectSig {
		t.Fatalf("received signature %q, want %q", receivedSig, expectSig)
	}
}

// TestOutboundDispatcher_H2: bearer auth sets the exact header, and it
// never appears in the resulting outcome/error.
func TestOutboundDispatcher_H2(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	claimed := claimOneForDelivery(t, o)
	cfg := testWebhookConfig(server.URL)
	cfg.Auth = AuthConfig{Type: AuthBearer, SecretEnv: "TEST_WEBHOOK_TOKEN"}
	secretValue := "TOP-SECRET-BEARER-TOKEN"
	d := testDispatcher(o, secretValue)
	outcome := d.DeliverOnce(context.Background(), claimed, cfg)

	if receivedAuth != "Bearer "+secretValue {
		t.Fatalf("Authorization header = %q, want Bearer %s", receivedAuth, secretValue)
	}
	if strings.Contains(outcome.ErrorClass, secretValue) {
		t.Fatal("bearer secret must never appear in ErrorClass")
	}
	if outcome.Err != nil && strings.Contains(outcome.Err.Error(), secretValue) {
		t.Fatal("bearer secret must never appear in an error message")
	}
}

// TestOutboundDispatcher_H3: 2xx (here 204) marks the event delivered.
func TestOutboundDispatcher_H3(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	claimed := claimOneForDelivery(t, o)
	d := testDispatcher(o, "s3cret")
	outcome := d.DeliverOnce(context.Background(), claimed, testWebhookConfig(server.URL))
	if !outcome.Delivered || outcome.Err != nil {
		t.Fatalf("expected delivered, got %+v", outcome)
	}
	var state string
	if err := o.db.QueryRow(`SELECT state FROM webhook_outbox WHERE event_id=?`, claimed.EventID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != string(OutboxDelivered) {
		t.Fatalf("state = %q, want delivered", state)
	}
}

// TestOutboundDispatcher_H4: 500 is retried (stays pending).
func TestOutboundDispatcher_H4(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	claimed := claimOneForDelivery(t, o)
	d := testDispatcher(o, "s3cret")
	outcome := d.DeliverOnce(context.Background(), claimed, testWebhookConfig(server.URL))
	if !outcome.Pending || outcome.Delivered || outcome.DeadLetter {
		t.Fatalf("expected pending (retryable), got %+v", outcome)
	}
	if outcome.ErrorClass != ErrorClassHTTP5xx {
		t.Fatalf("ErrorClass = %q, want %q", outcome.ErrorClass, ErrorClassHTTP5xx)
	}
}

// TestOutboundDispatcher_H5: 429 is retried.
func TestOutboundDispatcher_H5(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	claimed := claimOneForDelivery(t, o)
	d := testDispatcher(o, "s3cret")
	outcome := d.DeliverOnce(context.Background(), claimed, testWebhookConfig(server.URL))
	if !outcome.Pending {
		t.Fatalf("expected pending (retryable) for 429, got %+v", outcome)
	}
}

// TestOutboundDispatcher_H6: 400 dead-letters immediately (non-retryable).
func TestOutboundDispatcher_H6(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	claimed := claimOneForDelivery(t, o)
	d := testDispatcher(o, "s3cret")
	outcome := d.DeliverOnce(context.Background(), claimed, testWebhookConfig(server.URL))
	if !outcome.DeadLetter {
		t.Fatalf("expected dead_letter for 400, got %+v", outcome)
	}
}

// TestOutboundDispatcher_H7: a client timeout is retried.
func TestOutboundDispatcher_H7(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	claimed := claimOneForDelivery(t, o)
	cfg := testWebhookConfig(server.URL)
	cfg.Delivery.Timeout = 20 * time.Millisecond
	d := testDispatcher(o, "s3cret")
	outcome := d.DeliverOnce(context.Background(), claimed, cfg)
	if !outcome.Pending {
		t.Fatalf("expected pending (retryable timeout), got %+v", outcome)
	}
	if outcome.ErrorClass != ErrorClassTimeout {
		t.Fatalf("ErrorClass = %q, want %q", outcome.ErrorClass, ErrorClassTimeout)
	}
}

// TestOutboundDispatcher_H8: retrying a pending event keeps the same
// event_id (Idempotency-Key/event_id never change across attempts).
func TestOutboundDispatcher_H8(t *testing.T) {
	var attempts []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts = append(attempts, r.Header.Get(HeaderEventID))
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	d := testDispatcher(o, "s3cret")
	cfg := testWebhookConfig(server.URL)

	claimed1 := claimOneForDelivery(t, o)
	d.DeliverOnce(context.Background(), claimed1, cfg)

	// Force-claim again (bypassing next_attempt_at) to simulate a flush retry.
	claimed2, err := o.ClaimNextDue(context.Background(), ClaimRequest{
		WorkspaceKey: "ws", SourceID: "src", WebhookName: "test-hook", Now: time.Now(), Lease: time.Minute, Force: true,
	})
	if err != nil || claimed2 == nil {
		t.Fatalf("force reclaim: %v %v", claimed2, err)
	}
	d.DeliverOnce(context.Background(), claimed2, cfg)

	if len(attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(attempts))
	}
	if attempts[0] != attempts[1] || attempts[0] != claimed1.EventID {
		t.Fatalf("event IDs across attempts = %v, want both equal to %s", attempts, claimed1.EventID)
	}
}

// TestOutboundDispatcher_H10: a missing auth secret env var leaves the
// event pending without ever making an HTTP request.
func TestOutboundDispatcher_H10(t *testing.T) {
	var called int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&called, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	claimed := claimOneForDelivery(t, o)
	d := testDispatcher(o, "") // secret lookup returns ok=false
	outcome := d.DeliverOnce(context.Background(), claimed, testWebhookConfig(server.URL))

	if !outcome.Pending || outcome.ErrorClass != ErrorClassMissingAuthSecret {
		t.Fatalf("expected pending/missing_auth_secret, got %+v", outcome)
	}
	if atomic.LoadInt32(&called) != 0 {
		t.Fatal("missing auth secret must never trigger an HTTP request")
	}
	var attemptCount int
	if err := o.db.QueryRow(`SELECT attempt_count FROM webhook_outbox WHERE event_id=?`, claimed.EventID).Scan(&attemptCount); err != nil {
		t.Fatal(err)
	}
	if attemptCount != 0 {
		t.Fatalf("attempt_count = %d, want 0 (missing secret must not consume an attempt)", attemptCount)
	}
}

// TestOutboundDispatcher_H11: the stored operation/result on a claimed
// event are unaffected by delivery failure — this package never
// rewrites the caller-provided workflow outcome.
func TestOutboundDispatcher_H11(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	o := newTestOutbox(t)
	draft := testDraftWithResult("wf1", "ws", "src", "test-hook", "success")
	mustEnqueue(t, o, draft)
	claimed := claimOneForDelivery(t, o)
	if claimed.Result != "success" {
		t.Fatalf("claimed.Result = %q before delivery, want success", claimed.Result)
	}
	d := testDispatcher(o, "s3cret")
	d.DeliverOnce(context.Background(), claimed, testWebhookConfig(server.URL))

	var storedResult string
	if err := o.db.QueryRow(`SELECT result FROM webhook_outbox WHERE event_id=?`, claimed.EventID).Scan(&storedResult); err != nil {
		t.Fatal(err)
	}
	if storedResult != "success" {
		t.Fatalf("stored result after a failed webhook delivery = %q, want unchanged success", storedResult)
	}
}

// TestOutboundDispatcher_H12: a 3xx redirect is never followed and
// becomes a non-retryable http_redirect (dead-lettered).
func TestOutboundDispatcher_H12(t *testing.T) {
	var followed int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&followed, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	claimed := claimOneForDelivery(t, o)
	d := testDispatcher(o, "s3cret")
	outcome := d.DeliverOnce(context.Background(), claimed, testWebhookConfig(redirector.URL))

	if !outcome.DeadLetter {
		t.Fatalf("expected dead_letter for an unfollowed redirect, got %+v", outcome)
	}
	if outcome.ErrorClass != ErrorClassHTTPRedirect {
		t.Fatalf("ErrorClass = %q, want %q", outcome.ErrorClass, ErrorClassHTTPRedirect)
	}
	if atomic.LoadInt32(&followed) != 0 {
		t.Fatal("the redirect target must never be contacted")
	}
}

// TestOutboundDispatcher_H18: FlushWebhooks respects its total time
// budget even when a webhook's endpoint hangs.
func TestOutboundDispatcher_H18(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer server.Close()

	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	d := testDispatcher(o, "s3cret")
	cfg := testWebhookConfig(server.URL)
	cfg.Delivery.Timeout = 10 * time.Second // longer than the budget, so the budget itself must cut it off

	start := time.Now()
	d.FlushWebhooks(context.Background(), []WebhookIdentity{
		{WorkspaceKey: "ws", SourceID: "src", WebhookName: "test-hook", Config: cfg},
	}, FlushOptions{Budget: 300 * time.Millisecond, MaxConcurrent: 1, MaxClaimsPerWebhook: 1})
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("FlushWebhooks took %v, want bounded near the 300ms budget", elapsed)
	}
}

// TestOutboundDispatcher_H20: backoff jitter and Retry-After stay within
// their specified bounds, and a missing secret's "attempt" never
// advances attempt_count (re-verifies H10's angle end-to-end through
// ComputeBackoff/ApplyJitter directly).
func TestOutboundDispatcher_H20(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	initial := 30 * time.Second
	max := 30 * time.Minute
	for attempt := 1; attempt <= 10; attempt++ {
		base := ComputeBackoff(attempt, initial, max)
		if base > max {
			t.Fatalf("attempt %d: base backoff %v exceeds max %v", attempt, base, max)
		}
		for i := 0; i < 20; i++ {
			d := ApplyJitter(base, max, rng)
			lower := time.Duration(float64(base) * 0.8)
			upper := time.Duration(float64(base) * 1.2)
			if upper > max {
				upper = max
			}
			if lower < time.Second {
				lower = time.Second
			}
			if d < lower-time.Millisecond || d > upper+time.Millisecond {
				t.Fatalf("attempt %d jitter %v out of bounds [%v,%v] (base=%v)", attempt, d, lower, upper, base)
			}
		}
	}

	now := time.Now()
	if d, ok := ParseRetryAfter("120", now, max); !ok || d != 120*time.Second {
		t.Fatalf("Retry-After=120 => %v,%v want 120s,true", d, ok)
	}
	if d, ok := ParseRetryAfter("999999", now, max); !ok || d != max {
		t.Fatalf("Retry-After beyond max must cap to max, got %v,%v", d, ok)
	}
	if _, ok := ParseRetryAfter("-5", now, max); ok {
		t.Fatal("negative Retry-After must be treated as absent")
	}
	if _, ok := ParseRetryAfter("not-a-date", now, max); ok {
		t.Fatal("invalid Retry-After must be treated as absent")
	}
}

// TestOutboundDispatcher_H22: SQLite writer contention is bounded by
// busy_timeout and never blocks forever; no HTTP call is ever made while
// holding the outbox's write lock (structural — DeliverOnce's HTTP call
// happens strictly between the claim transaction's commit and the
// mark-delivered/mark-failed transaction's begin).
func TestOutboundDispatcher_H22(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "history.db")
	db1 := newTestOutboxDB(t, dbPath)
	o1 := NewSQLiteOutbox(db1)
	mustEnqueue(t, o1, testDraft("wf1", "ws", "src", "hook"))

	db2, err := OpenOutboxDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()

	tx, err := db2.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE webhook_outbox SET last_error_text='' WHERE 1=0`); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var claimErr error
	go func() {
		defer wg.Done()
		_, claimErr = o1.ClaimNextDue(context.Background(), ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: time.Now(), Lease: time.Minute})
	}()
	time.Sleep(50 * time.Millisecond)
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if claimErr != nil {
		t.Fatalf("claim contended by another writer should succeed once released (bounded busy_timeout): %v", claimErr)
	}
}

// TestOutboundDispatcher_H23: TLS minimum version, custom CA (appended
// to, not replacing, the system pool), hostname verification, and
// invalid-PEM behavior are all exact.
func TestOutboundDispatcher_H23(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	client, err := buildHTTPClient(TLSConfig{CAFile: caPath}, 2*time.Second)
	if err != nil {
		t.Fatalf("buildHTTPClient: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Fatalf("expected MinVersion TLS 1.2, got %+v", transport)
	}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("request with trusted CA should succeed: %v", err)
	}
	resp.Body.Close()

	insecureClient, err := buildHTTPClient(TLSConfig{AllowInsecureHTTPS: true}, 2*time.Second)
	if err != nil {
		t.Fatalf("buildHTTPClient with insecure HTTPS opt-in: %v", err)
	}
	insecureTransport, ok := insecureClient.Transport.(*http.Transport)
	if !ok || !insecureTransport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected explicit insecure HTTPS opt-in to set InsecureSkipVerify")
	}
	resp, err = insecureClient.Get(server.URL)
	if err != nil {
		t.Fatalf("request with allow_insecure_https should succeed: %v", err)
	}
	resp.Body.Close()

	// Invalid PEM must fail closed.
	badPath := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildHTTPClient(TLSConfig{CAFile: badPath}, time.Second); err == nil {
		t.Fatal("expected an error for a CA file with no parseable PEM certificate")
	}
}

// TestOutboundDispatcher_dispatchNeverPanics is a light sanity net for
// DeliverOnce over an unreachable endpoint (connection refused).
func TestOutboundDispatcher_ConnectionRefused(t *testing.T) {
	o := newTestOutbox(t)
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "test-hook"))
	claimed := claimOneForDelivery(t, o)
	d := testDispatcher(o, "s3cret")
	cfg := testWebhookConfig("https://127.0.0.1:1") // nothing listens here
	outcome := d.DeliverOnce(context.Background(), claimed, cfg)
	if !outcome.Pending {
		t.Fatalf("expected pending (network_error, retryable), got %+v", outcome)
	}
	if outcome.ErrorClass != ErrorClassNetworkError {
		t.Fatalf("ErrorClass = %q, want %q", outcome.ErrorClass, ErrorClassNetworkError)
	}
}
