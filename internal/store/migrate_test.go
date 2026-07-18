package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// TestFreshSchemaInstallsAtCurrentVersion creates a brand-new DB
// and verifies that user_version is bumped to SchemaVersion.
func TestFreshSchemaInstallsAtCurrentVersion(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "fresh.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	got, err := readUserVersion(filepath.Join(tmp, "fresh.db"))
	if err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if got != SchemaVersion {
		t.Errorf("user_version = %d, want %d", got, SchemaVersion)
	}
}

// TestMigrateFromEmptyOldDB simulates an old DB without any of the
// new columns by creating one with just the original schema, then
// calling Open again to trigger migration. After Open, the new
// columns must be present and user_version must equal SchemaVersion.
func TestMigrateFromEmptyOldDB(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "old.db")

	oldSchema := `
CREATE TABLE runs (
    id           TEXT PRIMARY KEY,
    started_at   DATETIME NOT NULL,
    finished_at  DATETIME,
    mode         TEXT NOT NULL,
    playbook     TEXT,
    inventory    TEXT,
    model        TEXT NOT NULL,
    status       TEXT NOT NULL
);
CREATE TABLE proposals (
    id           TEXT PRIMARY KEY,
    run_id       TEXT NOT NULL REFERENCES runs(id),
    host         TEXT NOT NULL,
    tool         TEXT NOT NULL,
    args         JSON NOT NULL,
    rationale    TEXT,
    risk_level   TEXT,
    cis_control  TEXT,
    status       TEXT NOT NULL,
    reversible   INTEGER DEFAULT 1,
    created_at   DATETIME NOT NULL,
    reviewed_at  DATETIME,
    applied_at   DATETIME,
    file_path    TEXT
);
`
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(oldSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 0;`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open migrated: %v", err)
	}
	defer func() { _ = s.Close() }()

	// After the 2026-07-17 agent-surface retirement, the final migration
	// DROPs the agent-loop tables the old DB carried — they must be gone,
	// while the mainline spec_checkpoints table must exist.
	for _, tbl := range []string{"runs", "proposals", "proposal_results", "agent_messages", "host_failure_seen", "plans", "embedding_cache"} {
		var name string
		err := s.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, tbl).Scan(&name)
		if err == nil {
			t.Errorf("expected table %s to be dropped after migration, but it exists", tbl)
		}
	}
	var name string
	if err := s.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name = 'spec_checkpoints'`).Scan(&name); err != nil || name != "spec_checkpoints" {
		t.Errorf("expected table spec_checkpoints after migration, got err=%v", err)
	}

	got, err := readUserVersion(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != SchemaVersion {
		t.Errorf("user_version = %d, want %d", got, SchemaVersion)
	}
}

// TestMigrateIsIdempotent verifies that re-opening an already-up-to-date
// DB does not error.
func TestMigrateIsIdempotent(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "idem.db")
	if _, err := Open(dbPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dbPath); err != nil {
		t.Fatalf("re-open: %v", err)
	}
}

// TestMigrateRejectsNewerDatabase verifies the fail-closed behaviour
// when an older binary opens a DB that was last touched by a newer one.
func TestMigrateRejectsNewerDatabase(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "future.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 9999;`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := Open(dbPath); err == nil {
		t.Fatal("expected error opening DB with newer user_version")
	}
}

// readUserVersion is a small helper used by the migration tests.
func readUserVersion(path string) (int, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = db.Close() }()
	var v int
	if err := db.QueryRow(`PRAGMA user_version;`).Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}
