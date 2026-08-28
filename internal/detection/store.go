package detection

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store owns the Detection Engine's SQLite state (spec §23-§27): baseline
// history, signal episodes/history, the Alertmanager delivery outbox, and
// model-provider request audit rows.
type Store struct {
	db *sql.DB
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// OpenStore opens (creating if absent) the SQLite database at path,
// applies the required PRAGMAs (spec §23), and runs any pending migrations
// (spec §26).
func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	// Migrations and the outbox worker both rely on single-writer
	// transaction semantics; SQLite only guarantees that with one
	// connection in play at a time.
	db.SetMaxOpenConns(1)
	if err := applyPragmas(db); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// OpenStoreReadOnly is like OpenStore but skips migrations — used by
// read-only CLI subcommands (spec §7's `db check`/`signals list`/`signals
// show`) that must not mutate a possibly-newer-schema database file.
func OpenStoreReadOnly(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	if err := applyPragmas(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func applyPragmas(db *sql.DB) error {
	for _, p := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=FULL;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA busy_timeout=5000;",
	} {
		if _, err := db.Exec(p); err != nil {
			return fmt.Errorf("apply %s: %w", p, err)
		}
	}
	return nil
}

// Close closes the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// IntegrityCheck runs PRAGMA integrity_check and returns its result string
// ("ok" on success) — spec §26/§40's upgrade/backup health gate.
func (s *Store) IntegrityCheck() (string, error) {
	var result string
	if err := s.db.QueryRow("PRAGMA integrity_check;").Scan(&result); err != nil {
		return "", fmt.Errorf("integrity_check: %w", err)
	}
	return result, nil
}

// migration is one schema_migrations entry: an integer version applied as
// a single transaction (spec §26).
type migration struct {
	version int
	sql     []string
}

// schemaV1 is the Detection Engine SQLite schema v1 (spec §24), translated
// to SQLite DDL with equivalent semantics.
var schemaV1 = migration{
	version: 1,
	sql: []string{
		`CREATE TABLE baseline_samples (
			pilot_host TEXT NOT NULL,
			feature TEXT NOT NULL,
			bucket_ts INTEGER NOT NULL,
			value REAL NOT NULL,
			PRIMARY KEY (pilot_host, feature, bucket_ts)
		)`,
		`CREATE TABLE signal_episodes (
			signal_id TEXT PRIMARY KEY,
			fingerprint TEXT NOT NULL,
			pilot_host TEXT NOT NULL,
			site TEXT NOT NULL,
			profile_id TEXT NOT NULL,
			profile_version INTEGER NOT NULL,
			state TEXT NOT NULL,
			severity TEXT,
			category_hint TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			revision INTEGER NOT NULL,
			last_score REAL,
			last_confidence REAL,
			warning_bits INTEGER NOT NULL DEFAULT 0,
			warning_count INTEGER NOT NULL DEFAULT 0,
			critical_streak INTEGER NOT NULL DEFAULT 0,
			recovery_streak INTEGER NOT NULL DEFAULT 0,
			candidate_clear_streak INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE UNIQUE INDEX ux_signal_active_fingerprint
			ON signal_episodes(fingerprint)
			WHERE state <> 'resolved'`,
		`CREATE TABLE signal_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			signal_id TEXT NOT NULL,
			revision INTEGER NOT NULL,
			event_type TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY(signal_id) REFERENCES signal_episodes(signal_id)
		)`,
		`CREATE TABLE outbox (
			id TEXT PRIMARY KEY,
			signal_id TEXT NOT NULL,
			revision INTEGER NOT NULL,
			sequence INTEGER NOT NULL,
			kind TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			status TEXT NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0,
			next_attempt_at TEXT NOT NULL,
			lease_until TEXT,
			last_error_code TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(signal_id, revision, sequence, kind),
			FOREIGN KEY(signal_id) REFERENCES signal_episodes(signal_id)
		)`,
		`CREATE TABLE provider_requests (
			request_id TEXT PRIMARY KEY,
			provider_id TEXT NOT NULL,
			model_id TEXT NOT NULL,
			prompt_version INTEGER NOT NULL,
			candidate_count INTEGER NOT NULL,
			request_hash TEXT NOT NULL,
			status TEXT NOT NULL,
			latency_ms INTEGER,
			input_tokens INTEGER,
			output_tokens INTEGER,
			error_code TEXT,
			created_at TEXT NOT NULL
		)`,
	},
}

var migrations = []migration{schemaV1}

func (s *Store) migrate() error {
	return s.applyMigrations(migrations)
}

// applyMigrations is the version-tracked runner used by both production
// startup and tests (tests inject a deliberately-broken migration to
// exercise the rollback path — spec §26: a failed migration ROLLBACKs and
// leaves no partial schema).
func (s *Store) applyMigrations(list []migration) error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}

	applied := map[int]bool{}
	rows, err := s.db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("scan schema_migrations: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	for _, m := range list {
		if applied[m.version] {
			continue
		}
		if err := s.applyMigration(m); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyMigration(m migration) (err error) {
	tx, txErr := s.db.Begin()
	if txErr != nil {
		return fmt.Errorf("begin migration %d: %w", m.version, txErr)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	for _, stmt := range m.sql {
		if _, execErr := tx.Exec(stmt); execErr != nil {
			err = fmt.Errorf("migration %d: %w", m.version, execErr)
			return err
		}
	}
	if _, execErr := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		m.version, rfc3339(time.Now())); execErr != nil {
		err = fmt.Errorf("migration %d record: %w", m.version, execErr)
		return err
	}
	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit migration %d: %w", m.version, commitErr)
		return err
	}
	return nil
}
