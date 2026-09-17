// retry.go implements design spec §19 (last_error_class), §24 (retry
// policy: retryable classification, exponential+jitter backoff,
// Retry-After honoring).
package outbound

import (
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Outbox/dispatcher error classes (design spec §19's last_error_class
// enum — distinct from the wire's operation-level FailureInfo.Class and
// state.error_class, per that section's explicit warning against
// sharing one free-form string across all three).
const (
	ErrorClassMissingAuthSecret   = "missing_auth_secret"
	ErrorClassNetworkError        = "network_error"
	ErrorClassTimeout             = "timeout"
	ErrorClassHTTPRedirect        = "http_redirect"
	ErrorClassHTTP4xx             = "http_4xx"
	ErrorClassHTTP5xx             = "http_5xx"
	ErrorClassPayloadTooLarge     = "payload_too_large"
	ErrorClassLocalPersistenceErr = "local_persistence_error"
)

// RetryDecision is ClassifyHTTPStatus's result: whether a completed HTTP
// response should be retried, and which bounded error class to record.
type RetryDecision struct {
	Retryable  bool
	ErrorClass string
}

// ClassifyHTTPStatus classifies a completed (non-2xx) HTTP response
// (design spec §24.1/§24.2). Callers must not call this for a 2xx
// status — that is success, not a failure to classify.
func ClassifyHTTPStatus(status int) RetryDecision {
	switch {
	case status == http.StatusRequestTimeout, status == 425 /* Too Early */, status == http.StatusTooManyRequests:
		return RetryDecision{Retryable: true, ErrorClass: ErrorClassHTTP4xx}
	case status >= 500 && status < 600:
		return RetryDecision{Retryable: true, ErrorClass: ErrorClassHTTP5xx}
	case status >= 300 && status < 400:
		// V1 never follows redirects (design spec §7.4's CheckRedirect ==
		// http.ErrUseLastResponse) — a 3xx therefore always means the
		// dispatcher's own client returned the redirect response itself.
		return RetryDecision{Retryable: false, ErrorClass: ErrorClassHTTPRedirect}
	case status >= 400 && status < 500:
		return RetryDecision{Retryable: false, ErrorClass: ErrorClassHTTP4xx}
	default:
		return RetryDecision{Retryable: false, ErrorClass: ErrorClassHTTP4xx}
	}
}

// ClassifyTransportError classifies a transport-level failure (no HTTP
// response at all): a context deadline is "timeout", anything else
// (connection refused, DNS failure, TLS handshake failure, ...) is
// "network_error". Both are retryable.
func ClassifyTransportError(isTimeout bool) RetryDecision {
	if isTimeout {
		return RetryDecision{Retryable: true, ErrorClass: ErrorClassTimeout}
	}
	return RetryDecision{Retryable: true, ErrorClass: ErrorClassNetworkError}
}

// maxBackoffShift bounds the exponential shift so attempt numbers well
// past any realistic max_attempts (<=100) can never overflow — 2^40 is
// already far larger than any allowed max_backoff (24h), so clamping the
// shift there and letting the normal max_backoff cap take over is exact,
// not approximate.
const maxBackoffShift = 40

// ComputeBackoff returns design spec §24.3's base exponential delay
// after the attemptNumber-th HTTP failure (1-based: the delay to wait
// before the (attemptNumber+1)-th attempt), before jitter:
// min(max_backoff, initial_backoff * 2^(attemptNumber-1)).
func ComputeBackoff(attemptNumber int, initial, max time.Duration) time.Duration {
	if attemptNumber < 1 {
		attemptNumber = 1
	}
	shift := attemptNumber - 1
	if shift > maxBackoffShift {
		return max
	}
	base := initial * time.Duration(int64(1)<<uint(shift))
	if base <= 0 || base > max {
		return max
	}
	return base
}

// ApplyJitter applies design spec §24.3's ±20% bounded jitter to base,
// clamped to [1s, max]. rng is injected so tests are deterministic.
func ApplyJitter(base time.Duration, max time.Duration, rng *rand.Rand) time.Duration {
	factor := 1 + (rng.Float64()*0.4 - 0.2)
	d := time.Duration(float64(base) * factor)
	if d < time.Second {
		d = time.Second
	}
	if d > max {
		d = max
	}
	return d
}

// ParseRetryAfter parses an HTTP Retry-After header value (design spec
// §24.1): either non-negative decimal delay-seconds or an RFC 7231
// HTTP-date. An invalid or past value reports ok=false — "視為沒有
// header" — and the resulting delay is capped to maxBackoff.
func ParseRetryAfter(header string, now time.Time, maxBackoff time.Duration) (delay time.Duration, ok bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, false
	}
	if secs, err := strconv.ParseInt(header, 10, 64); err == nil {
		if secs < 0 {
			return 0, false
		}
		d := time.Duration(secs) * time.Second
		if d > maxBackoff {
			d = maxBackoff
		}
		return d, true
	}
	if t, err := http.ParseTime(header); err == nil {
		d := t.Sub(now)
		if d <= 0 {
			return 0, false
		}
		if d > maxBackoff {
			d = maxBackoff
		}
		return d, true
	}
	return 0, false
}
