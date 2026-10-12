package sessionrecording

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// HTTPSinkConfig configures shipping TerminalEvents to pilot-session-store
// (docs/tmp/now/spec.md §28.1, Phase 8) instead of a local file. BaseURL
// must be an https:// URL — spec.md §28.2 requires TLS mandatory, and
// this type does nothing to enforce that itself (the caller's config
// validation does); an http:// BaseURL here would simply fail to dial a
// TLS-only server rather than silently downgrading.
type HTTPSinkConfig struct {
	BaseURL string
	// IngestToken is the per-session PIT1 token pilot-access-gateway minted
	// for this session (per-host recording spec §16); already in memory,
	// never passed as a CLI argument, never logged.
	IngestToken   string
	CAFile        string // e.g. /etc/ipa/ca.crt (spec.md §28.2); empty uses the system trust store
	SessionID     string
	User          string
	GatewayID     string
	Scope         string
	Target        string
	RecordingMode string
	// Timeout bounds each single HTTP request (default 5s).
	Timeout time.Duration
}

// HTTPSink is a Sink (sink.go) that ships events over HTTPS to
// pilot-session-store. Transient failures (network errors, timeouts, HTTP
// 408/429/5xx) are retried with backoff, re-sending the same batch —
// the store is idempotent per (session_id, seq). Other HTTP errors are
// permanent and wrap ErrSinkPermanent (per-host recording spec §20.2).
type HTTPSink struct {
	cfg    HTTPSinkConfig
	client *http.Client
	// sleep waits between retries; a variable for tests.
	sleep func(ctx context.Context, d time.Duration) error
	// startEndBudget bounds the retries of start and finish.
	startEndBudget time.Duration
}

// ErrSinkPermanent marks a sink error that retrying cannot fix (the store
// rejected the request: bad token, claims mismatch, finished session, …).
var ErrSinkPermanent = errors.New("sessionrecording: permanent session-store error")

const (
	retryBackoffStart = 100 * time.Millisecond
	retryBackoffMax   = 2 * time.Second
	defaultStartEnd   = 5 * time.Second
)

// NewHTTPSink builds the sink and announces the session to the store
// (POST /v1/sessions/start), retrying transient failures for up to 5s. A
// failure here means the caller must not start the target session.
func NewHTTPSink(ctx context.Context, cfg HTTPSinkConfig) (*HTTPSink, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("sessionrecording: HTTPSink requires BaseURL")
	}
	if cfg.SessionID == "" {
		return nil, fmt.Errorf("sessionrecording: HTTPSink requires SessionID")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
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
		sleep:          sleepCtx,
		startEndBudget: defaultStartEnd,
	}
	if err := sink.start(ctx); err != nil {
		return nil, err
	}
	return sink, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
		SessionID: s.cfg.SessionID, User: s.cfg.User,
		GatewayID: s.cfg.GatewayID, Scope: s.cfg.Scope, Target: s.cfg.Target,
		RecordingMode: s.cfg.RecordingMode, StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	ctx, cancel := context.WithTimeout(ctx, s.startEndBudget)
	defer cancel()
	if err := s.postRetrying(ctx, "/v1/sessions/start", body); err != nil {
		return fmt.Errorf("announce session start to session-store: %w", err)
	}
	return nil
}

type eventsRequest struct {
	Events []TerminalEvent `json:"events"`
}

// WriteBatch ships one batch of events, retrying transient failures until
// ctx ends. Every retry re-sends the identical body; the store is
// idempotent per (session_id, seq).
func (s *HTTPSink) WriteBatch(ctx context.Context, events []TerminalEvent) error {
	return s.postRetrying(ctx, fmt.Sprintf("/v1/sessions/%s/events", s.cfg.SessionID), eventsRequest{Events: events})
}

type sessionFinishRequest struct {
	EndedAt  string `json:"ended_at"`
	Complete bool   `json:"complete"`
	LastSeq  uint64 `json:"last_seq"`
}

// Finish reports the end of the session. ended_at is computed once and
// every retry re-sends the identical body, so the store treats a retry
// after a client-side timeout as the same finish.
func (s *HTTPSink) Finish(ctx context.Context, info FinishInfo) error {
	body := sessionFinishRequest{
		EndedAt: time.Now().UTC().Format(time.RFC3339Nano), Complete: info.Complete, LastSeq: info.LastSeq,
	}
	ctx, cancel := context.WithTimeout(ctx, s.startEndBudget)
	defer cancel()
	return s.postRetrying(ctx, fmt.Sprintf("/v1/sessions/%s/finish", s.cfg.SessionID), body)
}

// postRetrying posts body, retrying transient failures with exponential
// backoff until success, a permanent failure, or ctx ends.
func (s *HTTPSink) postRetrying(ctx context.Context, path string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	backoff := retryBackoffStart
	for {
		err := s.post(ctx, path, payload)
		if err == nil || errors.Is(err, ErrSinkPermanent) {
			return err
		}
		if ctx.Err() != nil {
			return fmt.Errorf("%w (giving up: %v)", err, ctx.Err())
		}
		if serr := s.sleep(ctx, backoff); serr != nil {
			return fmt.Errorf("%w (giving up: %v)", err, serr)
		}
		backoff = min(backoff*2, retryBackoffMax)
	}
}

// post sends one request. It never includes the token in an error.
func (s *HTTPSink) post(ctx context.Context, path string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.cfg.IngestToken)

	resp, err := s.client.Do(req)
	if err != nil {
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			// An untrusted server certificate does not fix itself.
			return fmt.Errorf("%w: session-store request to %s: %w", ErrSinkPermanent, path, err)
		}
		return fmt.Errorf("session-store request to %s failed: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 == 2 {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	statusErr := fmt.Errorf("session-store %s returned HTTP %d: %s", path, resp.StatusCode, respBody)
	switch {
	case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return statusErr
	default:
		return fmt.Errorf("%w: %w", ErrSinkPermanent, statusErr)
	}
}
