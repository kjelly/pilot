package detection

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ModelProvider is the boundary spec §28 defines: a pure scorer with no
// tool/shell/Prometheus-query/SSH/Ansible/mutation permission. It receives
// one compact batch request and returns a batch response.
type ModelProvider interface {
	Score(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error)
}

// ProviderErrorKind classifies a Score() error for the retry/circuit-
// breaker wrapper (spec §34).
type ProviderErrorKind int

const (
	// KindNetwork/KindTimeout/KindRateLimited/KindServerError are
	// retryable (max 2: 1s then 2s) and count as circuit health failures.
	KindNetwork ProviderErrorKind = iota
	KindTimeout
	KindRateLimited
	KindServerError
	// KindInvalidStructured (schema/semantic mismatch, or a malformed
	// provider-specific envelope) is NOT retried but DOES count as a
	// circuit health failure ("repeated invalid structured response").
	KindInvalidStructured
	// KindClientError (400/401/403/404) is neither retried nor a health
	// failure: the request/config is wrong, not the provider unhealthy.
	KindClientError
	// KindRefusal and KindProviderRejected (incomplete/failed/cancelled/
	// queued-in-a-synchronous-call/error!=null) are terminal,
	// non-retryable, and explicitly excluded from circuit health failures.
	KindRefusal
	KindProviderRejected
)

// ProviderError wraps an underlying error with its retry/circuit
// classification. Adapters (OpenAI/Ollama) always return this type so
// ManagedProvider never has to guess.
type ProviderError struct {
	Kind ProviderErrorKind
	Err  error
}

func (e *ProviderError) Error() string { return e.Err.Error() }
func (e *ProviderError) Unwrap() error { return e.Err }

func newProviderError(kind ProviderErrorKind, format string, args ...any) *ProviderError {
	return &ProviderError{Kind: kind, Err: fmt.Errorf(format, args...)}
}

// retryable implements spec §34's retry list: network, timeout, 429, 5xx.
// Explicitly excluded: 400/401/403/404, schema mismatch, refusal.
func (k ProviderErrorKind) retryable() bool {
	switch k {
	case KindNetwork, KindTimeout, KindRateLimited, KindServerError:
		return true
	default:
		return false
	}
}

// healthFailure implements spec §34's circuit-breaker health-failure set:
// network, timeout, 429, 5xx, and repeated invalid structured response.
// Refusal and insufficient_data (not an error) are explicitly excluded.
func (k ProviderErrorKind) healthFailure() bool {
	switch k {
	case KindNetwork, KindTimeout, KindRateLimited, KindServerError, KindInvalidStructured:
		return true
	default:
		return false
	}
}

// ErrCircuitOpen is returned by ManagedProvider.Score while the circuit is
// open (spec §34: "open期間: no provider requests, local detector continues").
var ErrCircuitOpen = errors.New("model provider circuit is open")

// retryBackoff implements spec §34: max 2 retries, 1s then 2s.
var retryBackoff = []time.Duration{1 * time.Second, 2 * time.Second}

// Circuit-breaker tuning (spec §34): 5 health failures within a rolling 2m
// window opens the circuit for 5m.
const (
	circuitFailureWindow    = 2 * time.Minute
	circuitFailureThreshold = 5
	circuitOpenDuration     = 5 * time.Minute
)

// ManagedProvider wraps a raw protocol adapter with spec §34's retry,
// circuit breaker, and per-protocol request timeout. Now/Sleep are
// overridable so tests never depend on real wall-clock time.
type ManagedProvider struct {
	Base     ModelProvider
	Protocol string
	Timeout  time.Duration

	Now   func() time.Time
	Sleep func(time.Duration)

	mu           sync.Mutex
	failures     []time.Time // health-failure timestamps within the rolling window
	circuitUntil time.Time   // zero value == closed
}

// NewManagedProvider wraps base with the default protocol timeout (spec
// §34: OpenAI 15s, Ollama 30s — the caller passes the right constant).
func NewManagedProvider(base ModelProvider, protocol string, timeout time.Duration) *ManagedProvider {
	return &ManagedProvider{Base: base, Protocol: protocol, Timeout: timeout, Now: time.Now, Sleep: time.Sleep}
}

func (m *ManagedProvider) circuitOpenLocked(now time.Time) bool {
	return now.Before(m.circuitUntil)
}

func (m *ManagedProvider) recordFailure(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := now.Add(-circuitFailureWindow)
	kept := m.failures[:0]
	for _, t := range m.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	m.failures = kept
	if len(m.failures) >= circuitFailureThreshold {
		m.circuitUntil = now.Add(circuitOpenDuration)
		m.failures = nil
	}
}

// CircuitState reports "open" or "closed" for status.json/metrics (spec
// §37/§38).
func (m *ManagedProvider) CircuitState(now time.Time) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.circuitOpenLocked(now) {
		return "open"
	}
	return "closed"
}

// classify maps a Score() error onto its ProviderErrorKind: adapters
// always return *ProviderError, but a raw context-deadline error (e.g.
// from the timeout this wrapper itself imposed) is recognized as a
// fallback so a misbehaving adapter still degrades safely rather than
// panicking a type assertion.
func classify(err error) ProviderErrorKind {
	var perr *ProviderError
	if errors.As(err, &perr) {
		return perr.Kind
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return KindTimeout
	}
	return KindNetwork
}

// Score implements spec §34 end to end: per-protocol timeout, retry on
// health-failure-eligible errors, and a circuit breaker that skips calling
// the underlying provider entirely while open.
func (m *ManagedProvider) Score(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
	now := m.Now()
	m.mu.Lock()
	open := m.circuitOpenLocked(now)
	m.mu.Unlock()
	if open {
		return ModelBatchResponse{}, ErrCircuitOpen
	}

	var lastErr error
	for attempt := 0; ; attempt++ {
		callCtx := ctx
		var cancel context.CancelFunc
		if m.Timeout > 0 {
			callCtx, cancel = context.WithTimeout(ctx, m.Timeout)
		}
		resp, err := m.Base.Score(callCtx, req)
		if cancel != nil {
			cancel()
		}
		if err == nil {
			return resp, nil
		}
		lastErr = err
		kind := classify(err)

		if kind.healthFailure() {
			m.recordFailure(m.Now())
		}
		if !kind.retryable() || attempt >= len(retryBackoff) {
			return ModelBatchResponse{}, lastErr
		}
		m.Sleep(retryBackoff[attempt])
	}
}
