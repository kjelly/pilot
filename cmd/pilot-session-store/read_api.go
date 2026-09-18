// read_api.go is pilot-session-store's admin read/replay API (docs/tmp/
// now/spec.md §29): a Unix socket entirely separate from ingest_api.go's
// TLS listener, gated by SO_PEERCRED + auditor-group membership rather
// than a bearer token — mirrors internal/directoryapi/connctx.go's
// pattern exactly (duplicated rather than shared: neither that package
// nor internal/gatewayapi exposes this as a reusable helper, and this
// binary must not depend on either for something this fundamental).
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/kjelly/pilot/internal/identity"
	"github.com/kjelly/pilot/internal/peercred"
	"github.com/kjelly/pilot/internal/sessionstore"
)

type readPeer struct {
	UID      uint32
	Username string
}

type readPeerCtxKey struct{}

func readConnContext(logger *slog.Logger) func(ctx context.Context, c net.Conn) context.Context {
	return func(ctx context.Context, c net.Conn) context.Context {
		uc, ok := c.(*net.UnixConn)
		if !ok {
			logger.Warn("read API connection is not a unix socket; refusing to trust it")
			return ctx
		}
		cred, err := peercred.FromConn(uc)
		if err != nil {
			logger.Warn("SO_PEERCRED failed", "error", err)
			return ctx
		}
		username, err := identity.LookupUsername(ctx, cred.UID)
		if err != nil {
			logger.Warn("getent passwd lookup failed", "uid", cred.UID, "error", err)
			return ctx
		}
		return context.WithValue(ctx, readPeerCtxKey{}, readPeer{UID: cred.UID, Username: username})
	}
}

func readPeerFromContext(ctx context.Context) (readPeer, bool) {
	p, ok := ctx.Value(readPeerCtxKey{}).(readPeer)
	return p, ok
}

// readServer is `pilot session list/show/replay`'s backend — an
// http.Server bound only to a Unix socket, never TCP.
type readServer struct {
	store        *sessionstore.Store
	auditorGroup string
	logger       *slog.Logger
	httpServer   *http.Server
}

func newReadServer(store *sessionstore.Store, auditorGroup string, logger *slog.Logger) *readServer {
	s := &readServer{store: store, auditorGroup: auditorGroup, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sessions", s.handleList)
	mux.HandleFunc("GET /v1/sessions/{id}", s.handleGet)
	mux.HandleFunc("GET /v1/sessions/{id}/replay", s.handleReplay)
	s.httpServer = &http.Server{Handler: mux, ConnContext: readConnContext(logger)}
	return s
}

func (s *readServer) Serve(ln net.Listener) error        { return s.httpServer.Serve(ln) }
func (s *readServer) Shutdown(ctx context.Context) error { return s.httpServer.Shutdown(ctx) }

// authorizedPeer is peerFromContext plus s.auditorGroup membership — the
// same defense-in-depth gate internal/directoryapi.Server.authorizedPeer
// and internal/gatewayapi's identically-named method use, alongside (not
// instead of) the socket file's own group ownership.
func (s *readServer) authorizedPeer(r *http.Request) (readPeer, bool) {
	peer, ok := readPeerFromContext(r.Context())
	if !ok {
		return readPeer{}, false
	}
	if s.auditorGroup == "" {
		return peer, true
	}
	member, err := identity.IsMemberOfGroup(r.Context(), peer.Username, s.auditorGroup)
	if err != nil {
		s.logger.Warn("auditor group check failed", "user", peer.Username, "group", s.auditorGroup, "error", err)
		return readPeer{}, false
	}
	return peer, member
}

func writeReadJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeReadError(w http.ResponseWriter, status int, message string) {
	writeReadJSON(w, status, map[string]string{"error": message})
}

type sessionSummaryJSON struct {
	SessionID     string `json:"session_id"`
	User          string `json:"user"`
	DirectoryID   string `json:"directory_id"`
	GatewayID     string `json:"gateway_id"`
	Scope         string `json:"scope"`
	Target        string `json:"target"`
	RecordingMode string `json:"recording_mode"`
	StartedAt     string `json:"started_at"`
	EndedAt       string `json:"ended_at,omitempty"`
	Complete      bool   `json:"complete"`
	Bytes         int64  `json:"bytes"`
	EventCount    int    `json:"event_count"`
	KeyID         string `json:"key_id"`
}

func toSummaryJSON(sum sessionstore.SessionSummary) sessionSummaryJSON {
	out := sessionSummaryJSON{
		SessionID: sum.SessionID, User: sum.User, DirectoryID: sum.DirectoryID, GatewayID: sum.GatewayID,
		Scope: sum.Scope, Target: sum.Target, RecordingMode: sum.RecordingMode,
		StartedAt: sum.StartedAt.UTC().Format(time.RFC3339Nano), Complete: sum.Complete,
		Bytes: sum.Bytes, EventCount: sum.EventCount, KeyID: sum.KeyID,
	}
	if sum.EndedAt != nil {
		out.EndedAt = sum.EndedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}

func (s *readServer) handleList(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizedPeer(r); !ok {
		writeReadError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	filter := sessionstore.ListFilter{User: r.URL.Query().Get("user")}
	sessions, err := s.store.ListSessions(r.Context(), filter)
	if err != nil {
		writeReadError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]sessionSummaryJSON, 0, len(sessions))
	for _, sum := range sessions {
		out = append(out, toSummaryJSON(sum))
	}
	writeReadJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *readServer) handleGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizedPeer(r); !ok {
		writeReadError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	sum, err := s.store.GetSession(r.Context(), r.PathValue("id"))
	if errors.Is(err, sessionstore.ErrUnknownSession) {
		writeReadError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeReadError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeReadJSON(w, http.StatusOK, toSummaryJSON(sum))
}

type replayEventJSON struct {
	Seq           uint64 `json:"seq"`
	Stream        string `json:"stream"`
	OffsetNanos   int64  `json:"offset_nanos"`
	DataBase64    string `json:"data_base64,omitempty"`
	Rows          int    `json:"rows,omitempty"`
	Cols          int    `json:"cols,omitempty"`
	RedactedBytes int    `json:"redacted_bytes,omitempty"`
}

type gapJSON struct {
	FromSeq uint64 `json:"from_seq"`
	ToSeq   uint64 `json:"to_seq"`
}

// replayResponse.Complete is spec.md §29's "RECORDING INCOMPLETE" signal
// — `pilot session replay` must show it prominently whenever this is
// false, exactly as internal/sessionstore.Store.Replay computes it (never
// re-derived or overridden client-side).
type replayResponse struct {
	SessionID string            `json:"session_id"`
	Complete  bool              `json:"complete"`
	Gaps      []gapJSON         `json:"gaps"`
	Events    []replayEventJSON `json:"events"`
}

func (s *readServer) handleReplay(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizedPeer(r); !ok {
		writeReadError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	sessionID := r.PathValue("id")
	result, err := s.store.Replay(r.Context(), sessionID)
	if errors.Is(err, sessionstore.ErrUnknownSession) {
		writeReadError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeReadError(w, http.StatusInternalServerError, fmt.Sprintf("replay failed: %v", err))
		return
	}
	resp := replayResponse{SessionID: sessionID, Complete: result.Complete, Gaps: []gapJSON{}, Events: []replayEventJSON{}}
	for _, g := range result.Gaps {
		resp.Gaps = append(resp.Gaps, gapJSON{FromSeq: g.FromSeq, ToSeq: g.ToSeq})
	}
	for _, ev := range result.Events {
		resp.Events = append(resp.Events, replayEventJSON{
			Seq: ev.Seq, Stream: ev.Stream, OffsetNanos: ev.OffsetNanos,
			DataBase64: base64.StdEncoding.EncodeToString(ev.Data), Rows: ev.Rows, Cols: ev.Cols, RedactedBytes: ev.RedactedBytes,
		})
	}
	writeReadJSON(w, http.StatusOK, resp)
}
