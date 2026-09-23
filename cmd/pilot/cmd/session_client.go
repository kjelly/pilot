// session_client.go is `pilot session {list,show,replay}`'s HTTP-over-
// Unix-socket client for pilot-session-store's admin read API
// (docs/tmp/now/spec.md §29). It talks to the read socket only — never
// the TLS ingest listener, and it carries no ingest token: this is the
// separate, lower-privilege "read/replay" credential path spec.md §28.2/
// §29 requires to be distinct from write access.
//
// The wire types here are deliberately independent structs, not shared
// with cmd/pilot-session-store's own (unexported, unimportable) response
// types — same decoupling internal/sessionstore.IngestEvent's doc
// comment already establishes for this component.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

type sessionStoreClient struct {
	httpClient *http.Client
}

func newSessionStoreClient(socketPath string) *sessionStoreClient {
	return &sessionStoreClient{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

type sessionStoreErrorResponse struct {
	Error string `json:"error"`
}

func (c *sessionStoreClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pilot-session-store unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read pilot-session-store response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var errResp sessionStoreErrorResponse
		_ = json.Unmarshal(body, &errResp)
		if errResp.Error != "" {
			return fmt.Errorf("%s (HTTP %d)", errResp.Error, resp.StatusCode)
		}
		return fmt.Errorf("pilot-session-store returned HTTP %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode pilot-session-store response: %w", err)
	}
	return nil
}

// sessionSummary is one spec.md §28.3 index row, as returned by
// GET /v1/sessions and GET /v1/sessions/{id}.
type sessionSummary struct {
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

	RecordingPolicySource string `json:"recording_policy_source"`
	LastSeq               uint64 `json:"last_seq"`
}

// listSessionsResponse is GET /v1/sessions's body.
type listSessionsResponse struct {
	Sessions []sessionSummary `json:"sessions"`
}

// replayEvent is one decrypted event, as returned by
// GET /v1/sessions/{id}/replay.
type replayEvent struct {
	Seq           uint64 `json:"seq"`
	Stream        string `json:"stream"`
	OffsetNanos   int64  `json:"offset_nanos"`
	DataBase64    string `json:"data_base64,omitempty"`
	Rows          int    `json:"rows,omitempty"`
	Cols          int    `json:"cols,omitempty"`
	RedactedBytes int    `json:"redacted_bytes,omitempty"`
}

type replayGap struct {
	FromSeq uint64 `json:"from_seq"`
	ToSeq   uint64 `json:"to_seq"`
}

// replayResult is GET /v1/sessions/{id}/replay's body. Complete is
// spec.md §29's "RECORDING INCOMPLETE" signal — false whenever a gap
// exists, regardless of what the recorder itself claimed at finish time.
type replayResult struct {
	SessionID string        `json:"session_id"`
	Complete  bool          `json:"complete"`
	Gaps      []replayGap   `json:"gaps"`
	Events    []replayEvent `json:"events"`
}

// ListSessions is GET /v1/sessions, optionally filtered by user.
func (c *sessionStoreClient) ListSessions(ctx context.Context, user string) (listSessionsResponse, error) {
	path := "/v1/sessions"
	if user != "" {
		path += "?user=" + url.QueryEscape(user)
	}
	var resp listSessionsResponse
	err := c.get(ctx, path, &resp)
	return resp, err
}

// GetSession is GET /v1/sessions/{id}.
func (c *sessionStoreClient) GetSession(ctx context.Context, sessionID string) (sessionSummary, error) {
	var resp sessionSummary
	err := c.get(ctx, "/v1/sessions/"+url.PathEscape(sessionID), &resp)
	return resp, err
}

// Replay fetches a recorded session's events. purpose ("replay" or
// "export") only selects which audit event the store records (per-host
// recording spec §21.5); permissions and the response are the same.
func (c *sessionStoreClient) Replay(ctx context.Context, sessionID, purpose string) (replayResult, error) {
	var resp replayResult
	err := c.get(ctx, "/v1/sessions/"+url.PathEscape(sessionID)+"/replay?purpose="+url.QueryEscape(purpose), &resp)
	return resp, err
}
