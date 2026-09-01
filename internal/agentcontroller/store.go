package agentcontroller

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store owns the Agent Controller's SQLite state (spec §8): incidents,
// their normalized event history, Agent runs, and Agent evidence.
type Store struct {
	db *sql.DB
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// OpenStore opens (creating if absent) the SQLite database at path,
// applies the required PRAGMAs, and runs any pending migrations.
func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	// Single-writer semantics: migrations and incident ingestion both
	// rely on transaction atomicity, which SQLite only guarantees with
	// one connection in play at a time.
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
// read-only CLI subcommands that must not mutate a possibly-newer-schema
// database file.
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

// IntegrityCheck runs PRAGMA integrity_check and returns its result
// string ("ok" on success).
func (s *Store) IntegrityCheck() (string, error) {
	var result string
	if err := s.db.QueryRow("PRAGMA integrity_check;").Scan(&result); err != nil {
		return "", fmt.Errorf("integrity_check: %w", err)
	}
	return result, nil
}

type migration struct {
	version int
	sql     []string
}

// schemaV1 is the Agent Controller SQLite schema v1 (spec §8).
//
// incidents.status is a superset of spec §7's state machine (adds
// "QUEUED" implicitly via agent_runs, not a separate incidents.status —
// the incident-level status only tracks OPEN/INVESTIGATING/DIAGNOSED/
// RESOLVED_EXTERNAL/AGENT_FAILED/SUPPRESSED/CLOSED; per-attempt
// QUEUED/INVESTIGATING/DIAGNOSED/AGENT_FAILED lives on agent_runs).
var schemaV1 = migration{
	version: 1,
	sql: []string{
		`CREATE TABLE incidents (
			id TEXT PRIMARY KEY,
			source TEXT NOT NULL,
			source_identity TEXT NOT NULL,
			group_key TEXT NOT NULL,
			status TEXT NOT NULL,
			severity TEXT,
			host TEXT,
			site TEXT,
			component TEXT,
			alert_name TEXT NOT NULL,
			opened_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			resolved_at TEXT,
			current_revision INTEGER NOT NULL DEFAULT 1,
			last_body_sha256 TEXT NOT NULL,
			next_dispatch_at TEXT NOT NULL DEFAULT '',
			dispatch_attempts INTEGER NOT NULL DEFAULT 0
		)`,
		// One ACTIVE incident per (source, source_identity) — spec §7's
		// "repeated identical firing payloads do not create concurrent
		// Agent runs" starts here: a second firing webhook for the same
		// identity finds this same row instead of creating a new one.
		`CREATE UNIQUE INDEX ux_incidents_active_identity
			ON incidents(source, source_identity)
			WHERE status NOT IN ('RESOLVED_EXTERNAL', 'CLOSED')`,
		`CREATE TABLE incident_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			incident_id TEXT NOT NULL,
			event_kind TEXT NOT NULL,
			source_revision INTEGER NOT NULL,
			payload_json TEXT NOT NULL,
			payload_sha256 TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY(incident_id) REFERENCES incidents(id)
		)`,
		`CREATE TABLE agent_runs (
			id TEXT PRIMARY KEY,
			incident_id TEXT NOT NULL,
			state TEXT NOT NULL,
			attempt INTEGER NOT NULL DEFAULT 1,
			started_at TEXT,
			finished_at TEXT,
			input_sha256 TEXT NOT NULL,
			output_json TEXT,
			error_class TEXT,
			error_text TEXT,
			created_at TEXT NOT NULL,
			FOREIGN KEY(incident_id) REFERENCES incidents(id)
		)`,
		// "one active Agent run per incident" (spec §7) as a DB-level
		// guarantee rather than an app-logic-only promise.
		`CREATE UNIQUE INDEX ux_agent_runs_active_incident
			ON agent_runs(incident_id)
			WHERE state IN ('QUEUED', 'INVESTIGATING')`,
		`CREATE TABLE agent_evidence (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			source_tool TEXT NOT NULL,
			reference TEXT,
			summary TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY(run_id) REFERENCES agent_runs(id)
		)`,
	},
}

var migrations = []migration{schemaV1}

func (s *Store) migrate() error {
	return s.applyMigrations(migrations)
}

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
