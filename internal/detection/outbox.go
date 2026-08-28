package detection

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"
)

// outboxLeaseDuration is how long a claimed-but-not-yet-completed row
// blocks other claimants before it is considered abandoned (spec §27).
const outboxLeaseDuration = 30 * time.Second

// outboxBackoffSeconds is the exact retry backoff ladder from spec §27,
// capped at its last value for any attempt count beyond its length.
var outboxBackoffSeconds = []int{1, 2, 4, 8, 16, 30, 60, 120, 300}

func outboxBackoff(attempts int) time.Duration {
	idx := attempts - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(outboxBackoffSeconds) {
		idx = len(outboxBackoffSeconds) - 1
	}
	return time.Duration(outboxBackoffSeconds[idx]) * time.Second
}

// DeliveryOutcome is the result of one outbox delivery attempt.
type DeliveryOutcome int

const (
	OutcomeDelivered DeliveryOutcome = iota
	OutcomeRetry
	OutcomeDead
)

// ClassifyDeliveryOutcome implements spec §27's retryable/dead rules.
// networkErr covers connection errors and timeouts. statusCode is ignored
// when networkErr is true.
func ClassifyDeliveryOutcome(statusCode int, networkErr bool) DeliveryOutcome {
	if networkErr {
		return OutcomeRetry
	}
	if statusCode >= 200 && statusCode < 300 {
		return OutcomeDelivered
	}
	if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
		return OutcomeRetry
	}
	if statusCode >= 400 && statusCode < 500 {
		// 400/401/403/404 and any other 4xx except 429 (already handled
		// above) are dead — spec §27.
		return OutcomeDead
	}
	return OutcomeRetry
}

// OutboxItem is one claimed outbox row, ready for delivery.
type OutboxItem struct {
	ID          string
	SignalID    string
	Revision    int
	Sequence    int
	Kind        string
	PayloadJSON string
	Attempts    int
}

// ClaimOutboxItem atomically selects and leases the single lowest-eligible
// outbox row (spec §27's claim step): a row is eligible when it is
// pending and due (next_attempt_at <= now), OR was left "sending" by a
// worker whose lease has since expired (the startup/crash-recovery rule).
// A row with a lower, still-unresolved sequence number for the same
// (signal_id, revision) blocks a higher-sequence row from being claimed at
// all — this is what guarantees warning-resolve is delivered (or dead)
// before critical-fire is even attempted (spec §22.2), independent of
// worker concurrency. Returns (nil, nil) when nothing is eligible.
func (s *Store) ClaimOutboxItem(now time.Time) (item *OutboxItem, err error) {
	tx, txErr := s.db.Begin()
	if txErr != nil {
		return nil, fmt.Errorf("begin claim: %w", txErr)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	nowStr := rfc3339(now)
	row := tx.QueryRow(`
		SELECT id, signal_id, revision, sequence, kind, payload_json, attempts
		FROM outbox o
		WHERE (
			(o.status = 'pending' AND o.next_attempt_at <= ?)
			OR (o.status = 'sending' AND o.lease_until < ?)
		)
		AND NOT EXISTS (
			SELECT 1 FROM outbox blocker
			WHERE blocker.signal_id = o.signal_id
			  AND blocker.revision = o.revision
			  AND blocker.sequence < o.sequence
			  AND blocker.status NOT IN ('delivered', 'dead')
		)
		ORDER BY o.next_attempt_at ASC, o.created_at ASC, o.sequence ASC
		LIMIT 1
	`, nowStr, nowStr)

	var it OutboxItem
	scanErr := row.Scan(&it.ID, &it.SignalID, &it.Revision, &it.Sequence, &it.Kind, &it.PayloadJSON, &it.Attempts)
	if scanErr != nil {
		if scanErr == sql.ErrNoRows {
			if commitErr := tx.Commit(); commitErr != nil {
				err = fmt.Errorf("commit empty claim: %w", commitErr)
				return nil, err
			}
			return nil, nil
		}
		err = fmt.Errorf("scan claimable outbox row: %w", scanErr)
		return nil, err
	}

	leaseUntil := rfc3339(now.Add(outboxLeaseDuration))
	if _, execErr := tx.Exec(`UPDATE outbox SET status='sending', lease_until=?, updated_at=? WHERE id=?`,
		leaseUntil, nowStr, it.ID); execErr != nil {
		err = fmt.Errorf("mark outbox row sending: %w", execErr)
		return nil, err
	}
	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit claim: %w", commitErr)
		return nil, err
	}
	return &it, nil
}

// CompleteOutboxItem records the outcome of one delivery attempt (spec
// §27). errorCode is a finite reason string (spec §38: metrics/labels
// carry finite reasons, never raw error text) and may be empty on success.
func (s *Store) CompleteOutboxItem(id string, outcome DeliveryOutcome, now time.Time, errorCode string) error {
	nowStr := rfc3339(now)
	switch outcome {
	case OutcomeDelivered:
		_, err := s.db.Exec(`UPDATE outbox SET status='delivered', updated_at=? WHERE id=?`, nowStr, id)
		if err != nil {
			return fmt.Errorf("mark outbox delivered: %w", err)
		}
		return nil
	case OutcomeDead:
		_, err := s.db.Exec(`UPDATE outbox SET status='dead', last_error_code=?, updated_at=? WHERE id=?`,
			nullString(errorCode), nowStr, id)
		if err != nil {
			return fmt.Errorf("mark outbox dead: %w", err)
		}
		return nil
	default: // OutcomeRetry
		var attempts int
		if err := s.db.QueryRow(`SELECT attempts FROM outbox WHERE id=?`, id).Scan(&attempts); err != nil {
			return fmt.Errorf("read outbox attempts: %w", err)
		}
		attempts++
		next := rfc3339(now.Add(outboxBackoff(attempts)))
		_, err := s.db.Exec(`UPDATE outbox SET status='pending', attempts=?, next_attempt_at=?, last_error_code=?, updated_at=? WHERE id=?`,
			attempts, next, nullString(errorCode), nowStr, id)
		if err != nil {
			return fmt.Errorf("mark outbox retry: %w", err)
		}
		return nil
	}
}

// OutboxPendingCount returns the number of outbox rows not yet delivered
// or dead — the source of pilot_detection_outbox_pending (spec §38/§39).
func (s *Store) OutboxPendingCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM outbox WHERE status NOT IN ('delivered', 'dead')`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count outbox pending: %w", err)
	}
	return n, nil
}
