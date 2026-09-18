package sessionrecording

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// HTTPSinkConfig configures shipping TerminalEvents to pilot-session-store
// (docs/tmp/now/spec.md §28.1, Phase 8) instead of a local file. BaseURL
// must be an https:// URL — spec.md §28.2 requires TLS mandatory, and
// this type does nothing to enforce that itself (the caller's config
// validation does); an http:// BaseURL here would simply fail to dial a
// TLS-only server rather than silently downgrading.
type HTTPSinkConfig struct {
	BaseURL       string
	IngestToken   string // already resident in memory; never passed as a CLI argument (spec.md §28.2)
	CAFile        string // e.g. /etc/ipa/ca.crt (spec.md §28.2); empty uses the system trust store
	SessionID     string
	User          string
	DirectoryID   string
	GatewayID     string
	Scope         string
	Target        string
	RecordingMode string
	Timeout       time.Duration
}

// HTTPSink is a Sink (sink.go) that ships events over HTTPS to
// pilot-session-store instead of writing them to a local file. It
// implements the exact same Sink interface as FileSink/NullSink — the
// Recorder never knows which one it is writing to.
type HTTPSink struct {
	cfg    HTTPSinkConfig
	client *http.Client

	mu      sync.Mutex
	started bool
}

// NewHTTPSink builds an HTTPSink and eagerly announces session start
// (POST /v1/sessions/start) before returning — a session-store outage or
// auth failure is surfaced here, at Connect time, rather than silently
// on the first recorded keystroke.
func NewHTTPSink(ctx context.Context, cfg HTTPSinkConfig) (*HTTPSink, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("sessionrecording: HTTPSink requires BaseURL")
	}
	if cfg.SessionID == "" {
		return nil, fmt.Errorf("sessionrecording: HTTPSink requires SessionID")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pemBytes, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read session-store CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no certificates found in session-store CA file %s", cfg.CAFile)
		}
		tlsConfig.RootCAs = pool
	}
	sink := &HTTPSink{
		cfg: cfg,
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
	}
	if err := sink.start(ctx); err != nil {
		return nil, err
	}
	return sink, nil
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

func (s *HTTPSink) start(ctx context.Context) error {
	body := sessionStartRequest{
		SessionID: s.cfg.SessionID, User: s.cfg.User, DirectoryID: s.cfg.DirectoryID,
		GatewayID: s.cfg.GatewayID, Scope: s.cfg.Scope, Target: s.cfg.Target,
		RecordingMode: s.cfg.RecordingMode, StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := s.post(ctx, "/v1/sessions/start", body); err != nil {
		return fmt.Errorf("announce session start to session-store: %w", err)
	}
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	return nil
}

type eventsRequest struct {
	Events []TerminalEvent `json:"events"`
}

// Write ships one event to POST /v1/sessions/{id}/events. Batching
// (spec.md §28.1: "Events 可 NDJSON batch") is left as a future
// optimization — one event per call is correct and simple, and the
// Recorder's own bounded queue (recorder.go) already provides
// backpressure regardless of how the Sink batches.
func (s *HTTPSink) Write(ctx context.Context, ev TerminalEvent) error {
	return s.post(ctx, fmt.Sprintf("/v1/sessions/%s/events", s.cfg.SessionID), eventsRequest{Events: []TerminalEvent{ev}})
}

type sessionFinishRequest struct {
	EndedAt  string `json:"ended_at"`
	Complete bool   `json:"complete"`
}

// Close announces session finish. complete is always reported true here
// — internal/sessionstore.Store.Replay independently recomputes
// completeness from sequence continuity actually observed in storage, so
// this claim is advisory only and can never hide a real gap.
func (s *HTTPSink) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
	defer cancel()
	return s.post(ctx, fmt.Sprintf("/v1/sessions/%s/finish", s.cfg.SessionID), sessionFinishRequest{
		EndedAt: time.Now().UTC().Format(time.RFC3339Nano), Complete: true,
	})
}

func (s *HTTPSink) post(ctx context.Context, path string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.cfg.IngestToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("session-store request to %s failed: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("session-store %s returned HTTP %d: %s", path, resp.StatusCode, respBody)
	}
	return nil
}
