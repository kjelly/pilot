package detection

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// TestStore_ListActiveEpisodesJSONMarshalsEmptyAsArray guards against the
// classic Go nil-slice gotcha: `pilot-detection-engine signals list --json`
// on a fresh host with no episodes must produce the literal JSON "[]", not
// "null" — found via a real vm-target run (docs/verification/
// detection-engine.md's C10 expects "[]" exactly).
func TestStore_ListActiveEpisodesJSONMarshalsEmptyAsArray(t *testing.T) {
	s := openTestStore(t)
	episodes, err := s.ListActiveEpisodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(episodes) != 0 {
		t.Fatalf("expected zero episodes on a fresh store, got %d", len(episodes))
	}
	data, err := json.Marshal(episodes)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "[]" {
		t.Fatalf("json.Marshal(empty ListActiveEpisodes result) = %q, want \"[]\" (a nil slice marshals to \"null\" instead)", data)
	}
}

// openPreV2TestStore opens a fresh store with ONLY schemaV1 applied
// (never schemaV2), so a test can seed legacy-shaped rows and then apply
// schemaV2 itself to observe the exact backfill/migration behavior (spec
// §9.7, Phase 4 exit gate: "DB migration/backfill PASS").
func openPreV2TestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := applyPragmas(db); err != nil {
		t.Fatalf("applyPragmas: %v", err)
	}
	s := &Store{db: db, path: path}
	if err := s.applyMigrations([]migration{schemaV1}); err != nil {
		t.Fatalf("apply schemaV1: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestSchemaV2_BackfillsSignalEpisodesSubjectIdentity is the Phase 4 exit
// gate's "DB migration/backfill PASS" for signal_episodes: a legacy
// pilot_host-only row must come out of schemaV2 with subject_id/
// subject_kind correctly backfilled, and its pilot_host compatibility
// mirror column untouched.
func TestSchemaV2_BackfillsSignalEpisodesSubjectIdentity(t *testing.T) {
	s := openPreV2TestStore(t)

	now := rfc3339(time.Now())
	if _, err := s.db.Exec(`INSERT INTO signal_episodes (
		signal_id, fingerprint, pilot_host, site, profile_id, profile_version,
		state, category_hint, created_at, updated_at, revision
	) VALUES ('sig-legacy', 'fp-legacy', 'web-1', 'site-a', 'linux-host-v1', 1, 'firing', 'cpu', ?, ?, 1)`, now, now); err != nil {
		t.Fatalf("seed legacy signal_episodes row: %v", err)
	}

	if err := s.applyMigration(schemaV2); err != nil {
		t.Fatalf("apply schemaV2: %v", err)
	}

	var subjectID, subjectKind, pilotHost string
	if err := s.db.QueryRow(`SELECT subject_id, subject_kind, pilot_host FROM signal_episodes WHERE signal_id='sig-legacy'`).
		Scan(&subjectID, &subjectKind, &pilotHost); err != nil {
		t.Fatalf("query backfilled row: %v", err)
	}
	if subjectID != "web-1" {
		t.Errorf("subject_id = %q, want backfilled from pilot_host (web-1)", subjectID)
	}
	if subjectKind != SubjectKindManagedHost {
		t.Errorf("subject_kind = %q, want %q", subjectKind, SubjectKindManagedHost)
	}
	if pilotHost != "web-1" {
		t.Errorf("pilot_host = %q, want unchanged (web-1)", pilotHost)
	}

	// GetEpisode must surface the backfilled columns through the Go API too.
	ep, err := s.GetEpisode("sig-legacy")
	if err != nil {
		t.Fatalf("GetEpisode: %v", err)
	}
	if ep.SubjectID != "web-1" || ep.SubjectKind != SubjectKindManagedHost {
		t.Fatalf("GetEpisode did not surface backfilled subject identity: %+v", ep)
	}
}

// TestSchemaV2_RecreatesBaselineSamplesWithNewPrimaryKey is the Phase 4
// exit gate's "DB migration/backfill PASS" for baseline_samples: a legacy
// row must survive the rename->create->copy->verify->drop recreation with
// its value intact and subject_id/subject_kind correctly backfilled.
func TestSchemaV2_RecreatesBaselineSamplesWithNewPrimaryKey(t *testing.T) {
	s := openPreV2TestStore(t)

	if _, err := s.db.Exec(`INSERT INTO baseline_samples (pilot_host, feature, bucket_ts, value) VALUES ('web-1', 'cpu_utilization', 12345, 0.42)`); err != nil {
		t.Fatalf("seed legacy baseline_samples row: %v", err)
	}

	if err := s.applyMigration(schemaV2); err != nil {
		t.Fatalf("apply schemaV2: %v", err)
	}

	var subjectID, subjectKind, pilotHost, feature string
	var bucketTS int64
	var value float64
	if err := s.db.QueryRow(`SELECT subject_id, subject_kind, pilot_host, feature, bucket_ts, value FROM baseline_samples WHERE subject_id='web-1'`).
		Scan(&subjectID, &subjectKind, &pilotHost, &feature, &bucketTS, &value); err != nil {
		t.Fatalf("query recreated row: %v", err)
	}
	if subjectKind != SubjectKindManagedHost || pilotHost != "web-1" || feature != "cpu_utilization" || bucketTS != 12345 || value != 0.42 {
		t.Fatalf("recreated row lost data: subject_kind=%q pilot_host=%q feature=%q bucket_ts=%d value=%v",
			subjectKind, pilotHost, feature, bucketTS, value)
	}

	var oldTableCount int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='baseline_samples_old'`).Scan(&oldTableCount)
	if err != nil {
		t.Fatal(err)
	}
	if oldTableCount != 0 {
		t.Fatal("baseline_samples_old must be dropped once the recreation is verified")
	}
}

// TestSchemaV2_RequiresBackupBeforeApplying is the Phase 4 exit gate's
// "rollback backup procedure proven": a pre-existing on-disk database must
// get a VACUUM INTO snapshot before schemaV2 (a requiresBackup migration)
// ever runs — the fallback spec §9.7 point 6/8 requires for an operator to
// roll back to the old binary/old schema.
func TestSchemaV2_RequiresBackupBeforeApplying(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	// Build a genuinely pre-Phase-4 database: only schemaV1 ever applied,
	// with a real legacy row in it — exactly what a database upgraded
	// from a pre-Phase-4 binary looks like the first time a Phase-4
	// binary opens it.
	rawDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyPragmas(rawDB); err != nil {
		t.Fatal(err)
	}
	seedStore := &Store{db: rawDB, path: path}
	if err := seedStore.applyMigrations([]migration{schemaV1}); err != nil {
		t.Fatalf("seed schemaV1: %v", err)
	}
	now := rfc3339(time.Now())
	if _, err := rawDB.Exec(`INSERT INTO signal_episodes (
		signal_id, fingerprint, pilot_host, site, profile_id, profile_version,
		state, category_hint, created_at, updated_at, revision
	) VALUES ('sig-1', 'fp-sig-1', 'web-1', 'site-a', 'linux-host-v1', 1, 'firing', 'cpu', ?, ?, 1)`, now, now); err != nil {
		t.Fatalf("seed legacy episode: %v", err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatal(err)
	}

	entriesBefore, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entriesBefore) != 1 {
		t.Fatalf("expected exactly the state.db file before any schemaV2 upgrade, got %d entries", len(entriesBefore))
	}

	second, err := OpenStore(path)
	if err != nil {
		t.Fatalf("second OpenStore (triggers schemaV2): %v", err)
	}
	defer second.Close()

	entriesAfter, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	backups := 0
	for _, e := range entriesAfter {
		if strings.Contains(e.Name(), ".pre-migration-") {
			backups++
		}
	}
	if backups == 0 {
		t.Fatalf("expected at least one .pre-migration-*.bak file after a requiresBackup migration ran, entries=%v", entriesAfter)
	}
}

// TestSchemaV2Migration_BackfillsAndPassesIntegrityCheck is
// docs/verification/snmp-monitoring-integration.md's C8: the SQLite
// migration backfills legacy pilot_host rows into subject_id/subject_kind/
// site (across BOTH tables spec §9.7 names) and the resulting database
// passes PRAGMA integrity_check — all inside the one migration
// transaction schemaV2 already runs under (spec §9.7 point 1/7).
func TestSchemaV2Migration_BackfillsAndPassesIntegrityCheck(t *testing.T) {
	s := openPreV2TestStore(t)

	now := rfc3339(time.Now())
	if _, err := s.db.Exec(`INSERT INTO signal_episodes (
		signal_id, fingerprint, pilot_host, site, profile_id, profile_version,
		state, category_hint, created_at, updated_at, revision
	) VALUES ('sig-legacy', 'fp-legacy', 'web-1', 'site-a', 'linux-host-v1', 1, 'firing', 'cpu', ?, ?, 1)`, now, now); err != nil {
		t.Fatalf("seed legacy signal_episodes row: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO baseline_samples (pilot_host, feature, bucket_ts, value) VALUES ('web-1', 'cpu_utilization', 12345, 0.42)`); err != nil {
		t.Fatalf("seed legacy baseline_samples row: %v", err)
	}

	if err := s.applyMigration(schemaV2); err != nil {
		t.Fatalf("apply schemaV2: %v", err)
	}

	var episodeSubjectID, episodeSubjectKind string
	if err := s.db.QueryRow(`SELECT subject_id, subject_kind FROM signal_episodes WHERE signal_id='sig-legacy'`).Scan(&episodeSubjectID, &episodeSubjectKind); err != nil {
		t.Fatalf("query backfilled signal_episodes: %v", err)
	}
	if episodeSubjectID != "web-1" || episodeSubjectKind != SubjectKindManagedHost {
		t.Fatalf("signal_episodes backfill = (%q, %q), want (web-1, %s)", episodeSubjectID, episodeSubjectKind, SubjectKindManagedHost)
	}

	var baselineSubjectID, baselineSubjectKind string
	if err := s.db.QueryRow(`SELECT subject_id, subject_kind FROM baseline_samples WHERE feature='cpu_utilization'`).Scan(&baselineSubjectID, &baselineSubjectKind); err != nil {
		t.Fatalf("query recreated baseline_samples: %v", err)
	}
	if baselineSubjectID != "web-1" || baselineSubjectKind != SubjectKindManagedHost {
		t.Fatalf("baseline_samples backfill = (%q, %q), want (web-1, %s)", baselineSubjectID, baselineSubjectKind, SubjectKindManagedHost)
	}

	result, err := s.IntegrityCheck()
	if err != nil {
		t.Fatalf("IntegrityCheck: %v", err)
	}
	if result != "ok" {
		t.Fatalf("integrity_check = %q, want ok after schemaV2", result)
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
