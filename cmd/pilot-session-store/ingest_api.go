// ingest_api.go is pilot-session-store's write-only HTTPS ingest API
// (docs/tmp/now/spec.md §28.1): POST /v1/sessions/start,
// POST /v1/sessions/{id}/events, POST /v1/sessions/{id}/finish.
//
// Every request carries a per-session ingest token (PIT1, per-host
// recording spec §16/§21.2) minted by pilot-access-gateway for exactly one
// session. The token binds session id, user, gateway, scope, target, mode,
// policy source and a random jti; this server refuses any request whose
// path, body or stored session disagrees with the token, so a token
// obtained for one session can never write into, reopen, or finish another.
// The ingest credential has no read/replay capability at all; that lives
// behind the separate Unix-socket read API in read_api.go.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/ingesttoken"
	"github.com/kjelly/pilot/internal/sessionstore"
)

type ingestServer struct {
	store    *sessionstore.Store
	verifier *ingesttoken.Verifier
	logger   *slog.Logger
	// metrics, when non-nil, counts requests for the textfile (§31).
	metrics *storeMetrics
}

func newIngestServer(store *sessionstore.Store, verifier *ingesttoken.Verifier, logger *slog.Logger) *ingestServer {
	if logger == nil {
		logger = slog.Default()
	}
	return &ingestServer{store: store, verifier: verifier, logger: logger}
}

func (s *ingestServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions/start", s.counted("start", s.authenticated(s.handleStart)))
	mux.HandleFunc("POST /v1/sessions/{id}/events", s.counted("events", s.authenticated(s.handleEvents)))
	mux.HandleFunc("POST /v1/sessions/{id}/finish", s.counted("finish", s.authenticated(s.handleFinish)))
	return mux
}

type claimsHandler func(http.ResponseWriter, *http.Request, ingesttoken.Claims)

// authenticated verifies the bearer PIT1 token. The token itself is never
// logged; only the fixed rejection reason and the path's session id are.
func (s *ingestServer) authenticated(next claimsHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) {
			s.reject(w, r, http.StatusUnauthorized, "unauthorized", "missing_bearer")
			return
		}
		claims, err := s.verifier.Verify(strings.TrimPrefix(auth, prefix))
		if err != nil {
			reason := ingesttoken.ReasonMalformed
			var te *ingesttoken.Error
			if errors.As(err, &te) {
				reason = te.Reason
			}
			s.reject(w, r, http.StatusUnauthorized, "unauthorized", reason)
			return
		}
		next(w, r, claims)
	}
}

// internalError answers 500 and logs why (e.g. SQLite "database or disk is
// full"): the recorder only sees a retryable failure, so this log line is
// where an operator finds the cause. Never logs a token or payload.
func (s *ingestServer) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error("ingest request failed", "path", r.URL.Path, "session_id", r.PathValue("id"), "error", err)
	writeIngestError(w, http.StatusInternalServerError, "internal error")
}

func (s *ingestServer) reject(w http.ResponseWriter, r *http.Request, status int, message, reason string) {
	s.logger.Warn("ingest request rejected", "path", r.URL.Path, "session_id", r.PathValue("id"), "status", status, "reason", reason)
	s.metrics.authFailure(reason)
	writeIngestError(w, status, message)
}

// sessionMatchesClaims reports whether a stored session belongs to the
// token presenting claims: same identity and the jti recorded at start.
func sessionMatchesClaims(sum sessionstore.SessionSummary, c ingesttoken.Claims) bool {
	return sum.SessionID == c.SessionID && sum.User == c.User && sum.GatewayID == c.Gateway &&
		sum.Scope == c.Scope && sum.Target == c.Target && sum.RecordingMode == c.Mode &&
		sum.IngestJTI == c.JTI
}

// boundSession resolves the path's session for events/finish and checks it
// against the token. It writes the error response and returns false when
// the request must not proceed.
func (s *ingestServer) boundSession(w http.ResponseWriter, r *http.Request, c ingesttoken.Claims) (string, bool) {
	sessionID := r.PathValue("id")
	if sessionID != c.SessionID {
		s.reject(w, r, http.StatusForbidden, "session_id_mismatch", "session_id_mismatch")
		return "", false
	}
	sum, err := s.store.GetSession(r.Context(), sessionID)
	switch {
	case errors.Is(err, sessionstore.ErrUnknownSession):
		writeIngestError(w, http.StatusNotFound, "unknown session")
		return "", false
	case err != nil:
		s.internalError(w, r, err)
		return "", false
	}
	if !sessionMatchesClaims(sum, c) {
		s.reject(w, r, http.StatusForbidden, "claims_mismatch", "claims_mismatch")
		return "", false
	}
	return sessionID, true
}

type sessionStartRequest struct {
	SessionID     string `json:"session_id"`
	User          string `json:"user"`
	DirectoryID   string `json:"directory_id"`
	GatewayID     string `json:"gateway_id"`
	Scope         string `json:"scope"`
	Target        string `json:"target"`
	RecordingMode string `json:"recording_mode"`
	StartedAt     string `json:"started_at"`
}

func (s *ingestServer) handleStart(w http.ResponseWriter, r *http.Request, c ingesttoken.Claims) {
	if err := s.verifier.CheckStartWindow(c); err != nil {
		s.reject(w, r, http.StatusUnauthorized, ingesttoken.ReasonStartWindowClosed, ingesttoken.ReasonStartWindowClosed)
		return
	}
	var req sessionStartRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		writeIngestError(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.DirectoryID != "" {
		// directory_id is not bound by the token, so it cannot be trusted.
		writeIngestError(w, http.StatusBadRequest, "unbound_field")
		return
	}
	if req.SessionID != c.SessionID || req.User != c.User || req.GatewayID != c.Gateway ||
		req.Scope != c.Scope || req.Target != c.Target || req.RecordingMode != c.Mode {
		s.reject(w, r, http.StatusForbidden, "claims_mismatch", "claims_mismatch")
		return
	}
	startedAt := time.Now().UTC()
	if req.StartedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, req.StartedAt); err == nil {
			startedAt = t
		}
	}
	err := s.store.StartSession(r.Context(), sessionstore.SessionStart{
		SessionID: c.SessionID, User: c.User, GatewayID: c.Gateway, Scope: c.Scope, Target: c.Target,
		RecordingMode: c.Mode, StartedAt: startedAt, RecordingPolicySource: c.Source, IngestJTI: c.JTI,
	})
	switch {
	case err == nil:
		w.WriteHeader(http.StatusOK)
	case errors.Is(err, sessionstore.ErrSessionFinished):
		s.metrics.authFailure("session_finished")
		writeIngestError(w, http.StatusConflict, "session_finished")
	case errors.Is(err, sessionstore.ErrSessionConflict):
		writeIngestError(w, http.StatusConflict, "session already started with different metadata")
	default:
		s.internalError(w, r, err)
	}
}

// wireEvent mirrors internal/sessionrecording.TerminalEvent's JSON shape
// exactly, without importing that package — the two sides of this wire
// protocol are deliberately decoupled (see internal/sessionstore.
// IngestEvent's doc comment).
type wireEvent struct {
	SchemaVersion int    `json:"schema_version"`
	SessionID     string `json:"session_id"`
	Seq           uint64 `json:"seq"`
	OffsetNanos   int64  `json:"offset_nanos"`
	Stream        string `json:"stream"`
	DataBase64    string `json:"data_base64,omitempty"`
	Rows          int    `json:"rows,omitempty"`
	Cols          int    `json:"cols,omitempty"`
	RedactedBytes int    `json:"redacted_bytes,omitempty"`
}

type eventsRequest struct {
	Events []wireEvent `json:"events"`
}

func (s *ingestServer) handleEvents(w http.ResponseWriter, r *http.Request, c ingesttoken.Claims) {
	sessionID, ok := s.boundSession(w, r, c)
	if !ok {
		return
	}
	var req eventsRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		writeIngestError(w, http.StatusBadRequest, "bad request")
		return
	}
	events := make([]sessionstore.IngestEvent, 0, len(req.Events))
	for _, ev := range req.Events {
		if ev.SessionID != sessionID {
			writeIngestError(w, http.StatusBadRequest, "event session_id mismatch")
			return
		}
		data, err := base64.StdEncoding.DecodeString(ev.DataBase64)
		if err != nil {
			writeIngestError(w, http.StatusBadRequest, "invalid data_base64")
			return
		}
		events = append(events, sessionstore.IngestEvent{
			Seq: ev.Seq, Stream: ev.Stream, OffsetNanos: ev.OffsetNanos, Data: data,
			Rows: ev.Rows, Cols: ev.Cols, RedactedBytes: ev.RedactedBytes,
		})
	}
	_, err := s.store.IngestEvents(r.Context(), sessionID, events)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusOK)
	case errors.Is(err, sessionstore.ErrUnknownSession):
		writeIngestError(w, http.StatusNotFound, "unknown session")
	case errors.Is(err, sessionstore.ErrSessionFinished):
		s.metrics.authFailure("session_finished")
		writeIngestError(w, http.StatusConflict, "session_finished")
	case errors.Is(err, sessionstore.ErrEventConflict):
		writeIngestError(w, http.StatusConflict, "event payload conflict")
	default:
		s.internalError(w, r, err)
	}
}

// sessionFinishRequest's ended_at and last_seq are both required (per-host
// recording spec §20.1): ended_at is the retry-idempotency key, last_seq
// reveals events lost at the tail.
type sessionFinishRequest struct {
	EndedAt  string  `json:"ended_at"`
	Complete bool    `json:"complete"`
	LastSeq  *uint64 `json:"last_seq"`
}

func (s *ingestServer) handleFinish(w http.ResponseWriter, r *http.Request, c ingesttoken.Claims) {
	sessionID, ok := s.boundSession(w, r, c)
	if !ok {
		return
	}
	var req sessionFinishRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		writeIngestError(w, http.StatusBadRequest, "bad request")
		return
	}
	endedAt, err := time.Parse(time.RFC3339Nano, req.EndedAt)
	if err != nil || req.LastSeq == nil {
		writeIngestError(w, http.StatusBadRequest, "ended_at (RFC3339Nano) and last_seq are required")
		return
	}
	res, err := s.store.FinishSessionResult(r.Context(), sessionID, endedAt, req.Complete, *req.LastSeq)
	switch {
	case err == nil:
		if !res.Repeated {
			s.metrics.sessionFinished(c.Mode, res.Complete, res.GapRanges)
		}
		w.WriteHeader(http.StatusOK)
	case errors.Is(err, sessionstore.ErrUnknownSession):
		writeIngestError(w, http.StatusNotFound, "unknown session")
	case errors.Is(err, sessionstore.ErrSessionFinished):
		s.metrics.authFailure("session_finished")
		writeIngestError(w, http.StatusConflict, "session_finished")
	case errors.Is(err, sessionstore.ErrLastSeqTooLow):
		writeIngestError(w, http.StatusBadRequest, "last_seq below a stored event seq")
	default:
		s.internalError(w, r, err)
	}
}

func decodeStrictJSON[T any](r io.Reader, out *T) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func writeIngestError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
