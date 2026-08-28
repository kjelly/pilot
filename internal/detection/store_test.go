package detection

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func seedEpisode(t *testing.T, s *Store, signalID string, revision int) {
	t.Helper()
	err := s.ApplyTransition(
		EpisodeRecord{
			SignalID: signalID, Fingerprint: "fp-" + signalID, PilotHost: "web-1", Site: "site-a",
			ProfileID: "linux-host-v1", ProfileVersion: 1, State: "firing", Severity: "warning",
			CategoryHint: "cpu", CreatedAt: time.Now(), UpdatedAt: time.Now(), Revision: revision,
		},
		HistoryRecord{SignalID: signalID, Revision: revision, EventType: "create", PayloadJSON: "{}", CreatedAt: time.Now()},
		nil,
	)
	if err != nil {
		t.Fatalf("seedEpisode: %v", err)
	}
}

func TestStore_SignalHistoryAndOutboxAreAtomic(t *testing.T) {
	s := openTestStore(t)
	seedEpisode(t, s, "sig-1", 1)

	err := s.ApplyTransition(
		EpisodeRecord{
			SignalID: "sig-1", Fingerprint: "fp-sig-1", PilotHost: "web-1", Site: "site-a",
			ProfileID: "linux-host-v1", ProfileVersion: 1, State: "firing", Severity: "critical",
			CategoryHint: "cpu", CreatedAt: time.Now(), UpdatedAt: time.Now(), Revision: 2,
		},
		HistoryRecord{SignalID: "sig-1", Revision: 2, EventType: "escalate", PayloadJSON: "{}", CreatedAt: time.Now()},
		[]OutboxRecord{{ID: "ob-1", SignalID: "sig-1", Revision: 1, Sequence: 1, Kind: "resolve", PayloadJSON: "{}", NextAttemptAt: time.Now()}},
	)
	if err != nil {
		t.Fatalf("first transition (seeding ob-1) must succeed: %v", err)
	}

	var historyCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM signal_history WHERE signal_id='sig-1'`).Scan(&historyCount); err != nil {
		t.Fatal(err)
	}
	if historyCount != 2 {
		t.Fatalf("history count = %d, want 2 (create + escalate)", historyCount)
	}

	// Second transition reuses outbox id "ob-1" -> UNIQUE PRIMARY KEY
	// violation on the outbox insert. The episode upsert (revision 3) and
	// history insert (event "resolve") that ran earlier IN THE SAME
	// TRANSACTION must be rolled back too.
	err = s.ApplyTransition(
		EpisodeRecord{
			SignalID: "sig-1", Fingerprint: "fp-sig-1", PilotHost: "web-1", Site: "site-a",
			ProfileID: "linux-host-v1", ProfileVersion: 1, State: "resolved", Severity: "",
			CategoryHint: "cpu", CreatedAt: time.Now(), UpdatedAt: time.Now(), Revision: 3,
		},
		HistoryRecord{SignalID: "sig-1", Revision: 3, EventType: "resolve", PayloadJSON: "{}", CreatedAt: time.Now()},
		[]OutboxRecord{{ID: "ob-1", SignalID: "sig-1", Revision: 3, Sequence: 1, Kind: "resolve", PayloadJSON: "{}", NextAttemptAt: time.Now()}},
	)
	if err == nil {
		t.Fatal("expected the duplicate outbox id to fail the whole transaction")
	}

	if err := s.db.QueryRow(`SELECT COUNT(*) FROM signal_history WHERE signal_id='sig-1'`).Scan(&historyCount); err != nil {
		t.Fatal(err)
	}
	if historyCount != 2 {
		t.Fatalf("history count after the FAILED transition = %d, want still 2 (the failed outbox insert must have rolled back the history insert too)", historyCount)
	}

	ep, err := s.GetEpisode("sig-1")
	if err != nil {
		t.Fatal(err)
	}
	if ep.Revision != 2 {
		t.Fatalf("episode revision = %d, want still 2 (the failed transaction must not have advanced it to 3)", ep.Revision)
	}
}

func TestStore_MigrationFailureRollsBack(t *testing.T) {
	s := openTestStore(t)

	broken := migration{
		version: 99,
		sql: []string{
			`CREATE TABLE mig_test_marker (x INTEGER)`,
			`THIS IS NOT VALID SQL`,
		},
	}
	if err := s.applyMigration(broken); err == nil {
		t.Fatal("expected the broken migration to fail")
	}

	var name string
	err := s.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='mig_test_marker'`).Scan(&name)
	if err != sql.ErrNoRows {
		t.Fatalf("mig_test_marker must not exist after a rolled-back migration; QueryRow err=%v", err)
	}

	var version int
	err = s.db.QueryRow(`SELECT version FROM schema_migrations WHERE version=99`).Scan(&version)
	if err != sql.ErrNoRows {
		t.Fatalf("schema_migrations must have no row for the failed migration; err=%v", err)
	}
}
