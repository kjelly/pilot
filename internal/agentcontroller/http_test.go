package agentcontroller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestServer(t *testing.T) (*Server, *Store) {
	t.Helper()
	store := newTestStore(t)
	return &Server{
		Store:        store,
		Secret:       []byte("test-secret"),
		MaxBodyBytes: 1 << 16,
	}, store
}

func signedRequest(t *testing.T, secret, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhooks/alertmanager", bytes.NewReader(body))
	req.Header.Set("Authorization", BearerAuthHeader(secret))
	return req
}

func oneAlertWebhookBody(t *testing.T, fingerprint, host, status string) []byte {
	t.Helper()
	return mustJSON(t, alertmanagerWebhook{
		Version:  "4",
		GroupKey: "g",
		Status:   status,
		Alerts: []alertmanagerAlert{{
			Status:      status,
			Fingerprint: fingerprint,
			Labels:      map[string]string{"alertname": "DiskFull", "severity": "critical", "pilot_host": host},
			Annotations: map[string]string{},
			StartsAt:    "2026-09-01T00:00:00Z",
		}},
	})
}

func TestWebhook_ValidSignatureCreatesIncident(t *testing.T) {
	srv, store := newTestServer(t)
	body := oneAlertWebhookBody(t, "fp-1", "web-1", "firing")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, signedRequest(t, srv.Secret, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	open, err := store.CountIncidentsByStatus(StatusOpen)
	if err != nil || open != 1 {
		t.Fatalf("open incidents = %d, err=%v, want 1", open, err)
	}
}

func TestWebhook_InvalidBearerTokenRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	body := oneAlertWebhookBody(t, "fp-1", "web-1", "firing")

	req := httptest.NewRequest(http.MethodPost, "/webhooks/alertmanager", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if srv.AuthFailures.Load() != 1 {
		t.Errorf("AuthFailures = %d, want 1", srv.AuthFailures.Load())
	}
}

func TestWebhook_MissingBearerTokenRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	body := oneAlertWebhookBody(t, "fp-1", "web-1", "firing")
	req := httptest.NewRequest(http.MethodPost, "/webhooks/alertmanager", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestWebhook_OversizedBodyRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.MaxBodyBytes = 16 // tiny, forces rejection
	body := oneAlertWebhookBody(t, "fp-1", "web-1", "firing")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, signedRequest(t, srv.Secret, body))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if srv.OversizeRejections.Load() != 1 {
		t.Errorf("OversizeRejections = %d, want 1", srv.OversizeRejections.Load())
	}
}

func TestWebhook_MalformedBodyRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	body := []byte("{not valid json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, signedRequest(t, srv.Secret, body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestWebhook_ReplayCreatesNoDuplicateIncident(t *testing.T) {
	srv, store := newTestServer(t)
	body := oneAlertWebhookBody(t, "fp-1", "web-1", "firing")

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, signedRequest(t, srv.Secret, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("replay %d: status = %d", i, rec.Code)
		}
	}

	open, err := store.CountIncidentsByStatus(StatusOpen)
	if err != nil || open != 1 {
		t.Fatalf("open incidents after 3x replay = %d, err=%v, want 1", open, err)
	}
}

func TestWebhook_ResolvedClosesSameIncident(t *testing.T) {
	srv, store := newTestServer(t)
	firing := oneAlertWebhookBody(t, "fp-1", "web-1", "firing")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, signedRequest(t, srv.Secret, firing))
	if rec.Code != http.StatusOK {
		t.Fatalf("firing: status = %d", rec.Code)
	}

	resolved := oneAlertWebhookBody(t, "fp-1", "web-1", "resolved")
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, signedRequest(t, srv.Secret, resolved))
	if rec2.Code != http.StatusOK {
		t.Fatalf("resolved: status = %d", rec2.Code)
	}

	open, _ := store.CountIncidentsByStatus(StatusOpen)
	resolvedCount, _ := store.CountIncidentsByStatus(StatusResolvedExternal)
	if open != 0 || resolvedCount != 1 {
		t.Fatalf("open=%d resolved=%d, want open=0 resolved=1", open, resolvedCount)
	}
}

func TestWebhook_MethodNotAllowed(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/webhooks/alertmanager", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestServer_NowOverride(t *testing.T) {
	fixed := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	srv := &Server{Now: func() time.Time { return fixed }}
	if got := srv.now(); !got.Equal(fixed) {
		t.Errorf("now() = %v, want %v", got, fixed)
	}
}
