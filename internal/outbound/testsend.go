// testsend.go implements `pilot webhook send-test`'s one-shot,
// unretried HTTP delivery: the same TLS/auth-header construction a real
// delivery attempt uses (buildHTTPClient/ApplyAuthHeaders), but with no
// outbox row, no claim, no retry, and no cursor advance — for
// exercising config/connectivity/payload shape without touching the
// durable delivery lineage at all.
package outbound

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxTestResponseBodyRead bounds how much of a test endpoint's response
// body this reads back for display — the same order of magnitude as
// dispatcher.go's real maxResponseBodyRead, just not shared verbatim
// since a send-test response is printed to a human, not discarded.
const maxTestResponseBodyRead = 64 * 1024

// TestDeliveryResult is one send-test attempt's outcome.
type TestDeliveryResult struct {
	StatusCode int
	Body       []byte
}

// BuildTestRequest builds the exact HTTP request SendTestEvent sends. It is
// exported so the CLI can display the request before delivery without
// reimplementing the auth/header construction. Callers must treat the
// returned request as sensitive: its Authorization header contains the
// bearer token or HMAC-derived credentials.
func BuildTestRequest(ctx context.Context, cfg WebhookConfig, pilotVersion, secret, eventID string, body []byte, now time.Time) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	ApplyAuthHeaders(req, cfg.Auth, secret, pilotVersion, eventID, 1, now, body)
	return req, nil
}

// SendTestEvent performs exactly one unretried HTTP POST of body to
// cfg.Endpoint, using the same client/header construction a real
// delivery attempt uses. It never touches an Outbox.
func SendTestEvent(ctx context.Context, cfg WebhookConfig, pilotVersion, secret, eventID string, body []byte, now time.Time) (TestDeliveryResult, error) {
	client, err := buildHTTPClient(cfg.TLS, cfg.Delivery.Timeout)
	if err != nil {
		return TestDeliveryResult{}, fmt.Errorf("build HTTP client: %w", err)
	}
	req, err := BuildTestRequest(ctx, cfg, pilotVersion, secret, eventID, body, now)
	if err != nil {
		return TestDeliveryResult{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return TestDeliveryResult{}, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxTestResponseBodyRead))
	return TestDeliveryResult{StatusCode: resp.StatusCode, Body: respBody}, nil
}
