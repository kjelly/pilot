// auth.go implements design spec §20: HMAC-SHA256 and bearer webhook
// authentication. Secret values are read only from the environment at
// dispatch time (never persisted — INV-4) and are never logged.
package outbound

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// HeaderEventID, etc. are the fixed webhook request headers (design
// spec §20.3).
const (
	HeaderEventID         = "X-Pilot-Event-ID"
	HeaderEventTimestamp  = "X-Pilot-Event-Timestamp"
	HeaderDeliveryAttempt = "X-Pilot-Delivery-Attempt"
	HeaderIdempotencyKey  = "Idempotency-Key"
	HeaderSignature256    = "X-Pilot-Signature-256"
	ContentTypeJSON       = "application/json"
	UserAgentPrefix       = "pilot/"
)

// HMACSignature computes design spec §20.3's signature: HMAC-SHA256 over
// "<timestamp>.<eventID>.<rawBody>", where timestamp is unix seconds as
// a decimal string. Returns the "sha256=<hex>" header value.
func HMACSignature(secret []byte, timestamp int64, eventID string, rawBody []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write([]byte(eventID))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// ApplyAuthHeaders sets every fixed delivery header plus the auth-mode-
// specific one (HMAC signature or bearer token) on req. now is the
// signing timestamp (injected for determinism in tests); attempt is the
// 1-based delivery attempt number.
func ApplyAuthHeaders(req *http.Request, cfg AuthConfig, secret string, pilotVersion string, eventID string, attempt int, now time.Time, rawBody []byte) {
	req.Header.Set("Content-Type", ContentTypeJSON)
	req.Header.Set("User-Agent", UserAgentPrefix+pilotVersion)
	req.Header.Set(HeaderEventID, eventID)
	req.Header.Set(HeaderEventTimestamp, strconv.FormatInt(now.Unix(), 10))
	req.Header.Set(HeaderDeliveryAttempt, strconv.Itoa(attempt))
	req.Header.Set(HeaderIdempotencyKey, eventID)

	switch cfg.Type {
	case AuthHMACSHA256:
		sig := HMACSignature([]byte(secret), now.Unix(), eventID, rawBody)
		req.Header.Set(HeaderSignature256, sig)
	case AuthBearer:
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", secret))
	}
}
