package detection

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// seedOutboxRow creates a firing episode with one due "fire" outbox row —
// the shape persistTransition's ActionCreateWarning/ActionCreateCritical
// path actually produces.
func seedOutboxRow(t *testing.T, s *Store, signalID string, payload string) {
	t.Helper()
	now := time.Now()
	err := s.ApplyTransition(
		EpisodeRecord{
			SignalID: signalID, Fingerprint: "fp-" + signalID, PilotHost: "web-1", Site: "site-a",
			ProfileID: "linux-host-v1", ProfileVersion: 1, State: "firing", Severity: "critical",
			CategoryHint: "cpu", CreatedAt: now, UpdatedAt: now, Revision: 1,
		},
		HistoryRecord{SignalID: signalID, Revision: 1, EventType: "create", PayloadJSON: payload, CreatedAt: now},
		[]OutboxRecord{{ID: "ob-" + signalID, SignalID: signalID, Revision: 1, Sequence: 1, Kind: "fire", PayloadJSON: payload, NextAttemptAt: now}},
	)
	if err != nil {
		t.Fatalf("seedOutboxRow: %v", err)
	}
}

func outboxRowStatus(t *testing.T, s *Store, id string) (status string, attempts int, lastErrorCode string) {
	t.Helper()
	var errCode *string
	if err := s.db.QueryRow(`SELECT status, attempts, last_error_code FROM outbox WHERE id=?`, id).Scan(&status, &attempts, &errCode); err != nil {
		t.Fatalf("query outbox row %s: %v", id, err)
	}
	if errCode != nil {
		lastErrorCode = *errCode
	}
	return status, attempts, lastErrorCode
}

func TestAlertmanagerSender_DrainOutbox_DeliversOnHTTP200(t *testing.T) {
	var gotBody []byte
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := openTestStore(t)
	payload := `{"labels":{"alertname":"PilotAdaptiveAnomaly"},"annotations":{},"startsAt":"2026-08-28T00:00:00Z","endsAt":"2026-08-28T00:03:00Z"}`
	seedOutboxRow(t, s, "sig-1", payload)

	sender := NewAlertmanagerSender(srv.URL, AlertmanagerTimeout)
	delivered, failures, err := sender.DrainOutbox(context.Background(), s, time.Now())
	if err != nil {
		t.Fatalf("DrainOutbox: %v", err)
	}
	if delivered != 1 {
		t.Fatalf("delivered = %d, want 1", delivered)
	}
	if len(failures) != 0 {
		t.Fatalf("failures = %v, want empty", failures)
	}
	if gotPath != "/api/v2/alerts" {
		t.Fatalf("POST path = %q, want /api/v2/alerts", gotPath)
	}

	var arr []map[string]any
	if err := json.Unmarshal(gotBody, &arr); err != nil {
		t.Fatalf("request body is not a JSON array: %v\nbody=%s", err, gotBody)
	}
	if len(arr) != 1 {
		t.Fatalf("request body array length = %d, want 1 (Alertmanager's real API requires an array even for one alert)", len(arr))
	}

	status, attempts, _ := outboxRowStatus(t, s, "ob-sig-1")
	if status != "delivered" {
		t.Fatalf("outbox status = %q, want delivered (attempts=%d)", status, attempts)
	}
}

func TestAlertmanagerSender_DrainOutbox_NetworkErrorRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachable := srv.URL
	srv.Close() // closed listener: connection refused on every attempt

	s := openTestStore(t)
	seedOutboxRow(t, s, "sig-1", `{}`)

	sender := NewAlertmanagerSender(unreachable, 500*time.Millisecond)
	delivered, failures, err := sender.DrainOutbox(context.Background(), s, time.Now())
	if err != nil {
		t.Fatalf("DrainOutbox: %v", err)
	}
	if delivered != 0 {
		t.Fatalf("delivered = %d, want 0", delivered)
	}
	if failures["network_error"] != 1 {
		t.Fatalf("failures = %v, want network_error:1", failures)
	}

	status, attempts, _ := outboxRowStatus(t, s, "ob-sig-1")
	if status != "pending" {
		t.Fatalf("outbox status = %q, want pending (retryable)", status)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestAlertmanagerSender_DrainOutbox_HTTP4xxMarksDead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := openTestStore(t)
	seedOutboxRow(t, s, "sig-1", `{}`)

	sender := NewAlertmanagerSender(srv.URL, AlertmanagerTimeout)
	delivered, failures, err := sender.DrainOutbox(context.Background(), s, time.Now())
	if err != nil {
		t.Fatalf("DrainOutbox: %v", err)
	}
	if delivered != 0 {
		t.Fatalf("delivered = %d, want 0", delivered)
	}
	if failures["http_404"] != 1 {
		t.Fatalf("failures = %v, want http_404:1", failures)
	}

	status, _, lastErrorCode := outboxRowStatus(t, s, "ob-sig-1")
	if status != "dead" {
		t.Fatalf("outbox status = %q, want dead", status)
	}
	if lastErrorCode != "http_404" {
		t.Fatalf("last_error_code = %q, want http_404", lastErrorCode)
	}
}

func TestAlertmanagerSender_DrainOutbox_MultipleRowsDrainedInOnePass(t *testing.T) {
	var postCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := openTestStore(t)
	seedOutboxRow(t, s, "sig-1", `{}`)
	seedOutboxRow(t, s, "sig-2", `{}`)

	sender := NewAlertmanagerSender(srv.URL, AlertmanagerTimeout)
	delivered, failures, err := sender.DrainOutbox(context.Background(), s, time.Now())
	if err != nil {
		t.Fatalf("DrainOutbox: %v", err)
	}
	if delivered != 2 {
		t.Fatalf("delivered = %d, want 2", delivered)
	}
	if len(failures) != 0 {
		t.Fatalf("failures = %v, want empty", failures)
	}
	if postCount != 2 {
		t.Fatalf("postCount = %d, want 2", postCount)
	}
}

func TestAlertmanagerSender_DrainOutbox_NothingEligibleReturnsZero(t *testing.T) {
	s := openTestStore(t)
	sender := NewAlertmanagerSender("http://127.0.0.1:1", AlertmanagerTimeout)
	delivered, failures, err := sender.DrainOutbox(context.Background(), s, time.Now())
	if err != nil {
		t.Fatalf("DrainOutbox: %v", err)
	}
	if delivered != 0 || len(failures) != 0 {
		t.Fatalf("delivered=%d failures=%v, want 0/empty (nothing was ever enqueued, so the sender must never have been dialed)", delivered, failures)
	}
}
