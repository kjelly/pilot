package detection

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"
)

// AlertmanagerTimeout is the per-request timeout for outbox delivery — the
// same budget as the Thanos/Loki clients (spec §27 doesn't specify one).
const AlertmanagerTimeout = QueryTimeout

// AlertmanagerSender delivers outbox rows to Alertmanager's real API
// (spec §22/§27). It never touches the SQLite transaction that created a
// row — delivery always happens strictly after that transaction commits
// (spec §25: "commit前：NO HTTP delivery").
type AlertmanagerSender struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewAlertmanagerSender builds an AlertmanagerSender with the given base
// URL and timeout.
func NewAlertmanagerSender(baseURL string, timeout time.Duration) *AlertmanagerSender {
	return &AlertmanagerSender{BaseURL: baseURL, HTTPClient: &http.Client{Timeout: timeout}}
}

// deliverOutboxOnce claims and attempts delivery of exactly one outbox row
// (spec §27's claim -> POST outside the transaction -> result transaction
// sequence). found=false means nothing was eligible to claim — the drain
// loop's stop condition, not an error. reason is "" on a delivered outcome
// and a finite reason code (spec §38) otherwise.
func (s *AlertmanagerSender) deliverOutboxOnce(ctx context.Context, store *Store, now time.Time) (found bool, reason string, err error) {
	item, err := store.ClaimOutboxItem(now)
	if err != nil {
		return false, "", fmt.Errorf("claim outbox item: %w", err)
	}
	if item == nil {
		return false, "", nil
	}

	// item.PayloadJSON is one AlertmanagerPayload object (buildAlertPayload
	// marshals a single value) — Alertmanager's real POST /api/v2/alerts
	// requires a JSON array body even for one alert.
	body := append(append([]byte("["), []byte(item.PayloadJSON)...), ']')
	req, buildErr := http.NewRequestWithContext(ctx, http.MethodPost, s.BaseURL+"/api/v2/alerts", bytes.NewReader(body))
	if buildErr != nil {
		// An unbuildable request can never succeed on retry either —
		// same "dead, not retry" treatment as a permanent 4xx.
		if compErr := store.CompleteOutboxItem(item.ID, OutcomeDead, now, "build_request_error"); compErr != nil {
			return true, "build_request_error", compErr
		}
		return true, "build_request_error", nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, doErr := s.HTTPClient.Do(req)
	if doErr != nil {
		if compErr := store.CompleteOutboxItem(item.ID, OutcomeRetry, now, "network_error"); compErr != nil {
			return true, "network_error", compErr
		}
		return true, "network_error", nil
	}
	defer resp.Body.Close()

	outcome := ClassifyDeliveryOutcome(resp.StatusCode, false)
	if outcome == OutcomeDelivered {
		if compErr := store.CompleteOutboxItem(item.ID, outcome, now, ""); compErr != nil {
			return true, "", compErr
		}
		return true, "", nil
	}
	reasonCode := fmt.Sprintf("http_%d", resp.StatusCode)
	if compErr := store.CompleteOutboxItem(item.ID, outcome, now, reasonCode); compErr != nil {
		return true, reasonCode, compErr
	}
	return true, reasonCode, nil
}

// maxOutboxDrainPerCycle bounds one drain pass so a pathological backlog
// can never starve the detection cycle scheduler indefinitely.
const maxOutboxDrainPerCycle = 100

// DrainOutbox delivers every currently-eligible outbox row (spec §27),
// stopping when nothing is left to claim or maxOutboxDrainPerCycle is
// reached. It never fails the caller's cycle: a delivery/claim error is
// returned but every row already resolved this pass stays resolved (each
// item's claim+complete is its own transaction pair, spec §25/§27).
func (s *AlertmanagerSender) DrainOutbox(ctx context.Context, store *Store, now time.Time) (delivered int, failures map[string]int64, err error) {
	failures = map[string]int64{}
	for i := 0; i < maxOutboxDrainPerCycle; i++ {
		found, reason, drainErr := s.deliverOutboxOnce(ctx, store, now)
		if drainErr != nil {
			return delivered, failures, drainErr
		}
		if !found {
			break
		}
		if reason == "" {
			delivered++
		} else {
			failures[reason]++
		}
	}
	return delivered, failures, nil
}
