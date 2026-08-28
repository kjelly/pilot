package detection

import (
	"net/http"
	"testing"
	"time"
)

func TestOutbox_ExpiredLeaseReturnsToRetry(t *testing.T) {
	s := openTestStore(t)
	seedEpisode(t, s, "sig-1", 1)

	now := time.Now()
	err := s.ApplyTransition(
		EpisodeRecord{SignalID: "sig-1", Fingerprint: "fp-sig-1", PilotHost: "web-1", Site: "site-a",
			ProfileID: "linux-host-v1", ProfileVersion: 1, State: "firing", Severity: "warning",
			CategoryHint: "cpu", CreatedAt: now, UpdatedAt: now, Revision: 1},
		HistoryRecord{SignalID: "sig-1", Revision: 1, EventType: "create", PayloadJSON: "{}", CreatedAt: now},
		[]OutboxRecord{{ID: "ob-1", SignalID: "sig-1", Revision: 1, Sequence: 1, Kind: "fire", PayloadJSON: "{}", NextAttemptAt: now}},
	)
	if err != nil {
		t.Fatal(err)
	}

	item, err := s.ClaimOutboxItem(now)
	if err != nil || item == nil {
		t.Fatalf("first claim: item=%v err=%v", item, err)
	}
	// Simulate a worker crash: the row is stuck "sending" with a lease
	// that will expire in the past relative to a later check.
	expired := now.Add(-1 * time.Minute) // 30s lease, expired long ago
	if _, err := s.db.Exec(`UPDATE outbox SET lease_until=? WHERE id=?`, rfc3339(expired), "ob-1"); err != nil {
		t.Fatal(err)
	}

	reclaimed, err := s.ClaimOutboxItem(now)
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if reclaimed == nil || reclaimed.ID != "ob-1" {
		t.Fatalf("expected the expired-lease row to be reclaimable, got %+v", reclaimed)
	}
}

func TestOutbox_429Retries(t *testing.T) {
	s := openTestStore(t)
	seedEpisode(t, s, "sig-1", 1)
	now := time.Now()
	if err := s.ApplyTransition(
		EpisodeRecord{SignalID: "sig-1", Fingerprint: "fp-sig-1", PilotHost: "web-1", Site: "site-a",
			ProfileID: "linux-host-v1", ProfileVersion: 1, State: "firing", Severity: "warning",
			CategoryHint: "cpu", CreatedAt: now, UpdatedAt: now, Revision: 1},
		HistoryRecord{SignalID: "sig-1", Revision: 1, EventType: "create", PayloadJSON: "{}", CreatedAt: now},
		[]OutboxRecord{{ID: "ob-1", SignalID: "sig-1", Revision: 1, Sequence: 1, Kind: "fire", PayloadJSON: "{}", NextAttemptAt: now}},
	); err != nil {
		t.Fatal(err)
	}

	if outcome := ClassifyDeliveryOutcome(http.StatusTooManyRequests, false); outcome != OutcomeRetry {
		t.Fatalf("429 must classify as retry, got %v", outcome)
	}

	item, err := s.ClaimOutboxItem(now)
	if err != nil || item == nil {
		t.Fatalf("claim: item=%v err=%v", item, err)
	}
	if err := s.CompleteOutboxItem(item.ID, OutcomeRetry, now, "http_429"); err != nil {
		t.Fatal(err)
	}

	var status string
	var attempts int
	var nextAttemptAt string
	if err := s.db.QueryRow(`SELECT status, attempts, next_attempt_at FROM outbox WHERE id=?`, "ob-1").
		Scan(&status, &attempts, &nextAttemptAt); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Errorf("status = %q, want pending (retryable)", status)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
	parsed, err := time.Parse(time.RFC3339, nextAttemptAt)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.After(now) {
		t.Errorf("next_attempt_at = %v, want after now (%v) per the backoff ladder", parsed, now)
	}
}

func TestOutbox_401BecomesDead(t *testing.T) {
	s := openTestStore(t)
	seedEpisode(t, s, "sig-1", 1)
	now := time.Now()
	if err := s.ApplyTransition(
		EpisodeRecord{SignalID: "sig-1", Fingerprint: "fp-sig-1", PilotHost: "web-1", Site: "site-a",
			ProfileID: "linux-host-v1", ProfileVersion: 1, State: "firing", Severity: "warning",
			CategoryHint: "cpu", CreatedAt: now, UpdatedAt: now, Revision: 1},
		HistoryRecord{SignalID: "sig-1", Revision: 1, EventType: "create", PayloadJSON: "{}", CreatedAt: now},
		[]OutboxRecord{{ID: "ob-1", SignalID: "sig-1", Revision: 1, Sequence: 1, Kind: "fire", PayloadJSON: "{}", NextAttemptAt: now}},
	); err != nil {
		t.Fatal(err)
	}

	if outcome := ClassifyDeliveryOutcome(http.StatusUnauthorized, false); outcome != OutcomeDead {
		t.Fatalf("401 must classify as dead, got %v", outcome)
	}

	item, err := s.ClaimOutboxItem(now)
	if err != nil || item == nil {
		t.Fatalf("claim: item=%v err=%v", item, err)
	}
	if err := s.CompleteOutboxItem(item.ID, OutcomeDead, now, "http_401"); err != nil {
		t.Fatal(err)
	}

	var status string
	if err := s.db.QueryRow(`SELECT status FROM outbox WHERE id=?`, "ob-1").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "dead" {
		t.Errorf("status = %q, want dead", status)
	}
}

func TestOutbox_WarningToCriticalOrdersResolveBeforeFire(t *testing.T) {
	s := openTestStore(t)
	seedEpisode(t, s, "sig-1", 1)
	now := time.Now()

	// Both rows belong to the same (signal_id, revision) escalation
	// transaction: sequence 1 resolves the warning alert, sequence 2
	// fires the critical one (spec §22.2).
	if err := s.ApplyTransition(
		EpisodeRecord{SignalID: "sig-1", Fingerprint: "fp-sig-1", PilotHost: "web-1", Site: "site-a",
			ProfileID: "linux-host-v1", ProfileVersion: 1, State: "firing", Severity: "critical",
			CategoryHint: "cpu", CreatedAt: now, UpdatedAt: now, Revision: 2},
		HistoryRecord{SignalID: "sig-1", Revision: 2, EventType: "escalate", PayloadJSON: "{}", CreatedAt: now},
		[]OutboxRecord{
			{ID: "ob-resolve", SignalID: "sig-1", Revision: 2, Sequence: 1, Kind: "resolve_warning", PayloadJSON: "{}", NextAttemptAt: now},
			{ID: "ob-fire", SignalID: "sig-1", Revision: 2, Sequence: 2, Kind: "fire_critical", PayloadJSON: "{}", NextAttemptAt: now},
		},
	); err != nil {
		t.Fatal(err)
	}

	first, err := s.ClaimOutboxItem(now)
	if err != nil {
		t.Fatal(err)
	}
	if first == nil || first.ID != "ob-resolve" {
		t.Fatalf("first claim must be the resolve (sequence 1) row, got %+v", first)
	}

	// ob-resolve is now "sending" (in flight, not yet delivered/dead) —
	// ob-fire must NOT be claimable while it's in that state.
	blocked, err := s.ClaimOutboxItem(now)
	if err != nil {
		t.Fatal(err)
	}
	if blocked != nil {
		t.Fatalf("sequence 2 (fire) must not be claimable while sequence 1 (resolve) is still in flight; got %+v", blocked)
	}

	if err := s.CompleteOutboxItem(first.ID, OutcomeDelivered, now, ""); err != nil {
		t.Fatal(err)
	}

	second, err := s.ClaimOutboxItem(now)
	if err != nil {
		t.Fatal(err)
	}
	if second == nil || second.ID != "ob-fire" {
		t.Fatalf("after resolve is delivered, fire (sequence 2) must become claimable; got %+v", second)
	}
}
