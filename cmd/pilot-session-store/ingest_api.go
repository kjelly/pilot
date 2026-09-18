// ingest_api.go is pilot-session-store's write-only HTTPS ingest API
// (docs/tmp/now/spec.md §28.1): POST /v1/sessions/start,
// POST /v1/sessions/{id}/events, POST /v1/sessions/{id}/finish. Auth is a
// single dedicated bearer token (spec.md §28.2) — this credential has no
// read/replay capability at all; that lives entirely behind the separate
// Unix-socket read API in read_api.go, a different listener with a
// different trust model (SO_PEERCRED + group membership, not a token).
package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/sessionstore"
)

type ingestServer struct {
	store *sessionstore.Store
	token string
}

func newIngestServer(store *sessionstore.Store, token string) *ingestServer {
	return &ingestServer{store: store, token: token}
}

func (s *ingestServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions/start", s.requireToken(s.handleStart))
	mux.HandleFunc("POST /v1/sessions/{id}/events", s.requireToken(s.handleEvents))
	mux.HandleFunc("POST /v1/sessions/{id}/finish", s.requireToken(s.handleFinish))
	return mux
}

func (s *ingestServer) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) || !tokensEqual(strings.TrimPrefix(auth, prefix), s.token) {
			writeIngestError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// tokensEqual compares in constant time — an ingest token is a bearer
// credential shared by every session on this Gateway (spec.md §28.2), so
// a timing side-channel here is worth closing even though it is not the
// deployment's primary security boundary.
func tokensEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
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

func (s *ingestServer) handleStart(w http.ResponseWriter, r *http.Request) {
	var req sessionStartRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		writeIngestError(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.SessionID == "" {
		writeIngestError(w, http.StatusBadRequest, "session_id required")
		return
	}
	startedAt := time.Now().UTC()
	if req.StartedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, req.StartedAt); err == nil {
			startedAt = t
		}
	}
	err := s.store.StartSession(r.Context(), sessionstore.SessionStart{
		SessionID: req.SessionID, User: req.User, DirectoryID: req.DirectoryID, GatewayID: req.GatewayID,
		Scope: req.Scope, Target: req.Target, RecordingMode: req.RecordingMode, StartedAt: startedAt,
	})
	switch {
	case err == nil:
		w.WriteHeader(http.StatusOK)
	case errors.Is(err, sessionstore.ErrSessionConflict):
		writeIngestError(w, http.StatusConflict, "session already started with different metadata")
	default:
		writeIngestError(w, http.StatusInternalServerError, "internal error")
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

func (s *ingestServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	var req eventsRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		writeIngestError(w, http.StatusBadRequest, "bad request")
		return
	}
	events := make([]sessionstore.IngestEvent, 0, len(req.Events))
	for _, ev := range req.Events {
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
	case errors.Is(err, sessionstore.ErrEventConflict):
		writeIngestError(w, http.StatusConflict, "event payload conflict")
	default:
		writeIngestError(w, http.StatusInternalServerError, "internal error")
	}
}

type sessionFinishRequest struct {
	EndedAt  string `json:"ended_at"`
	Complete bool   `json:"complete"`
}

func (s *ingestServer) handleFinish(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	var req sessionFinishRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		writeIngestError(w, http.StatusBadRequest, "bad request")
		return
	}
	endedAt := time.Now().UTC()
	if req.EndedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, req.EndedAt); err == nil {
			endedAt = t
		}
	}
	err := s.store.FinishSession(r.Context(), sessionID, endedAt, req.Complete)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusOK)
	case errors.Is(err, sessionstore.ErrUnknownSession):
		writeIngestError(w, http.StatusNotFound, "unknown session")
	default:
		writeIngestError(w, http.StatusInternalServerError, "internal error")
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
