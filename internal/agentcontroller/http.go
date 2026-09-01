package agentcontroller

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Server is the Alertmanager webhook ingress (spec §5). It is
// intentionally the ONLY externally reachable surface this binary
// exposes — spec §5.2 requires the listener itself to be
// private/network-scoped, which is a deployment (systemd+firewall)
// property this type cannot enforce from inside the process.
//
// Auth is a static shared-secret Bearer token (`Authorization: Bearer
// <secret>`, constant-time compared), NOT a per-request body HMAC
// signature. This is a deliberate adaptation from the phase-1 design
// doc's "HMAC/shared-secret" language, found via a real disposable-VM
// deployment against a real Alertmanager v0.27: Alertmanager's own
// `webhook_configs` sender has no mechanism to COMPUTE an HMAC over its
// own request body — it can only attach a static credential via
// `http_config.authorization` (Bearer) or `http_config.basic_auth`. An
// HMAC-of-body scheme is only usable by a sender the operator controls
// (this repo's own future components), never by stock Alertmanager
// itself, so it is not the AGENTS.md-correct choice here.
type Server struct {
	Store        *Store
	Secret       []byte
	MaxBodyBytes int64
	Now          func() time.Time // overridable for tests; nil = time.Now

	// AuthFailures/OversizeRejections/IngestErrors are the "invalid
	// webhook auth rejected" / "oversized body" evidence counters (spec
	// §15 C3) surfaced via status.go's metrics textfile — never as a log
	// line containing the payload (spec §5.7).
	AuthFailures       atomic.Int64
	OversizeRejections atomic.Int64
	IngestErrors       atomic.Int64
	IngestedEvents     atomic.Int64
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler returns the http.Handler to mount at the webhook path.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhooks/alertmanager", s.recovered(s.handleAlertmanagerWebhook))
	return mux
}

// recovered wraps h so a panic inside it returns 500 instead of crashing
// the process — spec §5.6: controller failure must not take down other
// Alertmanager receivers, which starts with this process staying alive.
func (s *Server) recovered(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.IngestErrors.Add(1)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		h(w, r)
	}
}

func (s *Server) handleAlertmanagerWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.verifyBearerToken(r.Header.Get("Authorization")) {
		s.AuthFailures.Add(1)
		http.Error(w, "invalid or missing bearer token", http.StatusUnauthorized)
		return
	}

	limited := http.MaxBytesReader(w, r.Body, s.MaxBodyBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		s.OversizeRejections.Add(1)
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}

	events, err := ParseAlertmanagerWebhook(body, s.now())
	if err != nil {
		s.IngestErrors.Add(1)
		http.Error(w, fmt.Sprintf("malformed webhook body: %v", err), http.StatusBadRequest)
		return
	}

	// Every event commits durably BEFORE this handler returns 2xx (spec
	// §5.5) — a failure partway through still leaves already-committed
	// incidents intact; Alertmanager will simply redeliver the group on
	// its own retry/resend cadence, and replay is idempotent (spec §7).
	for _, ev := range events {
		if _, err := s.Store.IngestEvent(ev, s.now()); err != nil {
			s.IngestErrors.Add(1)
			http.Error(w, "failed to persist incident", http.StatusInternalServerError)
			return
		}
		s.IngestedEvents.Add(1)
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) verifyBearerToken(header string) bool {
	if len(s.Secret) == 0 {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := []byte(strings.TrimPrefix(header, prefix))
	return len(got) == len(s.Secret) && subtle.ConstantTimeCompare(got, s.Secret) == 1
}

// BearerAuthHeader is the client-side counterpart to verifyBearerToken —
// used by tests and by anything (e.g. a fake Alertmanager fixture in the
// disposable evidence lane) that needs to produce a validly authenticated
// request without going through a real Alertmanager instance.
func BearerAuthHeader(secret []byte) string {
	return "Bearer " + string(secret)
}

// EncodeJSON is a small helper for tests/fixtures building a raw
// Alertmanager webhook body without depending on this package's private
// wire structs.
func EncodeJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}
