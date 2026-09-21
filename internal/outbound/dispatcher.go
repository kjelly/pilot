// dispatcher.go implements design spec §21 (TLS), §23 (FIFO delivery
// ordering), §24.4-§24.5 (bounded synchronous publication, no
// background daemon), §25 (HTTP success semantics): the actual HTTP
// delivery of one claimed outbox event, and the bounded flush loop that
// drives claim->deliver->claim across a set of webhooks.
package outbound

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// maxResponseBodyRead bounds how much of a response body the dispatcher
// ever reads (design spec §25): enough for TCP connection reuse,
// without ever writing the body into a log, error, or store field.
const maxResponseBodyRead = 64 * 1024

// DeliverOutcome is one delivery attempt's result, for CLI/status
// reporting — never fed back into the wire payload itself.
type DeliverOutcome struct {
	EventID     string
	WebhookName string
	Delivered   bool
	Pending     bool // retryable failure, still pending
	DeadLetter  bool
	ErrorClass  string
	Err         error
}

// SecretLookup resolves an auth.secret_env name to its runtime value.
// Returning ok=false means the source is unavailable (design spec §20.5):
// missing_auth_secret, not a hard error. auth.secret_file is resolved by
// ResolveAuthSecret and does not call this function.
type SecretLookup func(envVar string) (string, bool)

// Dispatcher delivers claimed outbox events over HTTP.
type Dispatcher struct {
	Outbox       Outbox
	Now          func() time.Time
	RNG          *rand.Rand
	PilotVersion string
	SecretLookup SecretLookup
}

// buildHTTPClient constructs a per-delivery *http.Client honoring design
// spec §7.4/§21: TLS 1.2 minimum, the CA file (if any) appended to the
// OS trust store rather than replacing it, and redirects never followed.
func buildHTTPClient(cfg TLSConfig, timeout time.Duration) (*http.Client, error) {
	// AllowInsecureHTTPS deliberately disables certificate and hostname
	// verification for HTTPS only. TLS encryption remains enabled, but the
	// peer is no longer authenticated; this is an explicit operator opt-in
	// for controlled test environments.
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.AllowInsecureHTTPS, //nolint:gosec // explicit integrations.yaml opt-in
	}
	if cfg.CAFile != "" {
		pemData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read tls.ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("tls.ca_file contains no parseable PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}

// DeliverOnce performs exactly one HTTP delivery attempt for a claimed
// event and reports the outcome to Outbox (MarkDelivered/
// MarkAttemptFailed) — it never mutates the caller-visible deploy/
// reconcile result (INV-2/H11).
func (d *Dispatcher) DeliverOnce(ctx context.Context, claimed *ClaimedEvent, cfg WebhookConfig) DeliverOutcome {
	now := d.Now()
	out := DeliverOutcome{EventID: claimed.EventID, WebhookName: claimed.WebhookName}

	secret, ok := ResolveAuthSecret(cfg.Auth, d.SecretLookup)
	if !ok {
		out.ErrorClass = ErrorClassMissingAuthSecret
		state, err := d.Outbox.MarkAttemptFailed(ctx, DeliveryFailure{
			EventID: claimed.EventID, ClaimOwner: claimed.ClaimOwner, Now: now,
			Retryable: true, ErrorClass: ErrorClassMissingAuthSecret,
			ErrorText:      fmt.Sprintf("%s is not available", AuthSecretSource(cfg.Auth)),
			NextAttemptAt:  now.Add(cfg.Delivery.InitialBackoff),
			ConsumeAttempt: false,
			MaxAttempts:    cfg.Delivery.MaxAttempts,
		})
		out.Err = err
		out.Pending = state == OutboxPending
		out.DeadLetter = state == OutboxDeadLetter
		return out
	}

	client, err := buildHTTPClient(cfg.TLS, cfg.Delivery.Timeout)
	if err != nil {
		out.ErrorClass = ErrorClassNetworkError
		state, markErr := d.Outbox.MarkAttemptFailed(ctx, DeliveryFailure{
			EventID: claimed.EventID, ClaimOwner: claimed.ClaimOwner, Now: now,
			Retryable: true, ErrorClass: ErrorClassNetworkError, ErrorText: err.Error(),
			NextAttemptAt:  now.Add(jitteredBackoff(claimed.AttemptCount+1, cfg.Delivery, d.RNG)),
			ConsumeAttempt: true,
			MaxAttempts:    cfg.Delivery.MaxAttempts,
		})
		out.Err = markErr
		out.Pending = state == OutboxPending
		out.DeadLetter = state == OutboxDeadLetter
		return out
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(claimed.BodyJSON))
	if err != nil {
		out.ErrorClass = ErrorClassNetworkError
		state, markErr := d.Outbox.MarkAttemptFailed(ctx, DeliveryFailure{
			EventID: claimed.EventID, ClaimOwner: claimed.ClaimOwner, Now: now,
			Retryable: true, ErrorClass: ErrorClassNetworkError, ErrorText: err.Error(),
			NextAttemptAt:  now.Add(jitteredBackoff(claimed.AttemptCount+1, cfg.Delivery, d.RNG)),
			ConsumeAttempt: true,
			MaxAttempts:    cfg.Delivery.MaxAttempts,
		})
		out.Err = markErr
		out.Pending = state == OutboxPending
		out.DeadLetter = state == OutboxDeadLetter
		return out
	}
	attempt := claimed.AttemptCount + 1
	ApplyAuthHeaders(req, cfg.Auth, secret, d.PilotVersion, claimed.EventID, attempt, now, claimed.BodyJSON)

	resp, err := client.Do(req)
	if err != nil {
		decision := ClassifyTransportError(isTimeoutErr(err))
		delay := jitteredBackoff(attempt, cfg.Delivery, d.RNG)
		out.ErrorClass = decision.ErrorClass
		state, markErr := d.Outbox.MarkAttemptFailed(ctx, DeliveryFailure{
			EventID: claimed.EventID, ClaimOwner: claimed.ClaimOwner, Now: now,
			Retryable: true, ErrorClass: decision.ErrorClass, ErrorText: err.Error(),
			NextAttemptAt:  now.Add(delay),
			ConsumeAttempt: true,
			MaxAttempts:    cfg.Delivery.MaxAttempts,
		})
		out.Err = markErr
		out.Pending = state == OutboxPending
		out.DeadLetter = state == OutboxDeadLetter
		return out
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, maxResponseBodyRead)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		out.Delivered = true
		out.Err = d.Outbox.MarkDelivered(ctx, DeliveryACK{
			EventID: claimed.EventID, ClaimOwner: claimed.ClaimOwner,
			Authoritative: claimed.Authoritative, StateAvailable: claimed.StateAvailable, SourceComplete: claimed.SourceComplete,
			Now: now,
		})
		return out
	}

	decision := ClassifyHTTPStatus(resp.StatusCode)
	var delay time.Duration
	if decision.Retryable {
		if d2, ok := ParseRetryAfter(resp.Header.Get("Retry-After"), now, cfg.Delivery.MaxBackoff); ok {
			delay = d2
		} else {
			delay = jitteredBackoff(attempt, cfg.Delivery, d.RNG)
		}
	}
	out.ErrorClass = decision.ErrorClass
	state, markErr := d.Outbox.MarkAttemptFailed(ctx, DeliveryFailure{
		EventID: claimed.EventID, ClaimOwner: claimed.ClaimOwner, Now: now,
		Retryable: decision.Retryable, ErrorClass: decision.ErrorClass,
		ErrorText:      fmt.Sprintf("http status %d", resp.StatusCode),
		NextAttemptAt:  now.Add(delay),
		ConsumeAttempt: true,
		MaxAttempts:    cfg.Delivery.MaxAttempts,
	})
	out.Err = markErr
	out.Pending = state == OutboxPending
	out.DeadLetter = state == OutboxDeadLetter
	return out
}

func jitteredBackoff(attempt int, d DeliveryConfig, rng *rand.Rand) time.Duration {
	base := ComputeBackoff(attempt, d.InitialBackoff, d.MaxBackoff)
	return ApplyJitter(base, d.MaxBackoff, rng)
}

// isTimeoutErr reports whether err is (or wraps) a network timeout —
// including context.DeadlineExceeded, which http.Client.Do surfaces
// wrapped in a *url.Error when the client's own Timeout elapses.
func isTimeoutErr(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// FlushOptions bounds one FlushWebhooks call (design spec §24.5).
type FlushOptions struct {
	MaxConcurrent       int
	Budget              time.Duration
	MaxClaimsPerWebhook int
	Lease               time.Duration
	// Force ignores next_attempt_at (design spec §34.3's `pilot webhook
	// flush --force`) — it never steals a live claim or skips a paused
	// webhook (ClaimRequest.Force's own contract already guarantees this).
	Force bool
}

// DefaultFlushOptions returns design spec §24.5's bounds: 4 concurrent
// HTTP attempts, a 30s total budget.
func DefaultFlushOptions() FlushOptions {
	return FlushOptions{MaxConcurrent: 4, Budget: 30 * time.Second, MaxClaimsPerWebhook: 20, Lease: 0}
}

// WebhookIdentity scopes a claim to one logical webhook.
type WebhookIdentity struct {
	WorkspaceKey, SourceID, WebhookName string
	Config                              WebhookConfig
}

// FlushWebhooks claims and delivers due events across webhooks,
// respecting each logical webhook's own strict FIFO (one live claim at a
// time) while allowing different webhooks to proceed in parallel, up to
// opts.MaxConcurrent, within opts.Budget total wall-clock time (design
// spec §24.5). It returns every attempted delivery's outcome.
func (d *Dispatcher) FlushWebhooks(ctx context.Context, webhooks []WebhookIdentity, opts FlushOptions) []DeliverOutcome {
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = 4
	}
	if opts.Budget <= 0 {
		opts.Budget = 30 * time.Second
	}

	budgetCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opts.Budget)
	defer cancel()

	sem := make(chan struct{}, opts.MaxConcurrent)
	var mu sync.Mutex
	var outcomes []DeliverOutcome
	var wg sync.WaitGroup

	for _, wh := range webhooks {
		wh := wh
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			claimsLimit := opts.MaxClaimsPerWebhook
			if claimsLimit <= 0 {
				claimsLimit = 1
			}
			for i := 0; i < claimsLimit; i++ {
				if budgetCtx.Err() != nil {
					return
				}
				claimed, err := d.Outbox.ClaimNextDue(budgetCtx, ClaimRequest{
					WorkspaceKey: wh.WorkspaceKey, SourceID: wh.SourceID, WebhookName: wh.WebhookName,
					Now: d.Now(), Lease: leaseFor(wh.Config, opts.Lease), Force: opts.Force,
				})
				if err != nil || claimed == nil {
					return
				}
				outcome := d.DeliverOnce(budgetCtx, claimed, wh.Config)
				mu.Lock()
				outcomes = append(outcomes, outcome)
				mu.Unlock()
				if outcome.Pending {
					// This webhook's head-of-line event is still pending
					// (durable retry later) — stop, preserving FIFO;
					// don't claim the next sequence out of order.
					return
				}
			}
		}()
	}
	wg.Wait()
	return outcomes
}

// leaseFor returns the per-webhook claim lease: max(2*timeout, 30s)
// (design spec §23.1), unless overridden by a positive fallback.
func leaseFor(cfg WebhookConfig, fallback time.Duration) time.Duration {
	if fallback > 0 {
		return fallback
	}
	lease := 2 * cfg.Delivery.Timeout
	if lease < 30*time.Second {
		lease = 30 * time.Second
	}
	return lease
}
