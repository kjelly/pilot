// Package sessionstore is pilot-session-store's encrypted, durable index
// of internal/sessionrecording.TerminalEvent streams (docs/tmp/now/
// spec.md §28-§29, Phase 8). It never sees or trusts the Gateway's
// authorization decision — it is a dumb, append-only recorder of
// already-decided sessions, keyed by session_id.
//
// Storage deviates from spec.md §28.3's suggested layout in one respect:
// event ciphertext lives in the same SQLite database as the index
// (session_events table) rather than in separate
// recordings/<yyyy>/<mm>/<dd>/<session-id>.ndjson.enc files. This repo has
// been bitten before by orphaned temp files surviving process death (see
// the redactFile incident referenced in project memory: 436 orphaned
// files, 76GB, found only by accident) — a single transactional store
// makes "delete the payload" and "update the index" (spec.md §28.5's
// required retention order) one atomic operation with no second
// filesystem-cleanup step that can silently fail. All spec-required
// index columns (§28.3) are still present as real columns, so `pilot
// session list` never needs to touch the payload table.
package sessionstore

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

// SchemaVersion is the current schema version, tracked via PRAGMA
// user_version — same house style as internal/store/sqlite.go. Bump it
// and add a migration step whenever the schema changes shape after this
// package has shipped to any real deployment.
//
// Version 2 (per-host recording spec §21.3) adds recording_policy_source,
// last_seq and ingest_jti to sessions.
const SchemaVersion = 2

const schema = `
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    user            TEXT NOT NULL,
    directory_id    TEXT NOT NULL DEFAULT '',
    gateway_id      TEXT NOT NULL DEFAULT '',
    scope           TEXT NOT NULL DEFAULT '',
    target          TEXT NOT NULL DEFAULT '',
    recording_mode  TEXT NOT NULL DEFAULT '',
    started_at      TEXT NOT NULL,
    ended_at        TEXT NOT NULL DEFAULT '',
    complete        INTEGER NOT NULL DEFAULT 0,
    bytes           INTEGER NOT NULL DEFAULT 0,
    event_count     INTEGER NOT NULL DEFAULT 0,
    key_id          TEXT NOT NULL DEFAULT '',
    recording_policy_source TEXT NOT NULL DEFAULT '',
    last_seq        INTEGER NOT NULL DEFAULT 0,
    ingest_jti      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at);

-- One row per TerminalEvent. ciphertext/nonce hold the AES-256-GCM
-- sealed event payload (spec.md §28.4); payload_sha256 is the plaintext
-- hash used to detect a retried seq's payload matching (no-op success)
-- vs. diverging (conflict) per spec.md §28.1.
CREATE TABLE IF NOT EXISTS session_events (
    session_id     TEXT NOT NULL,
    seq            INTEGER NOT NULL,
    stream         TEXT NOT NULL,
    offset_nanos   INTEGER NOT NULL,
    rows           INTEGER NOT NULL DEFAULT 0,
    cols           INTEGER NOT NULL DEFAULT 0,
    redacted_bytes INTEGER NOT NULL DEFAULT 0,
    nonce          BLOB NOT NULL,
    ciphertext     BLOB NOT NULL,
    payload_sha256 TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    UNIQUE(session_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_session_events_session ON session_events(session_id, seq);

-- Append-only audit trail for retention deletes (spec.md §28.5: "retention
-- delete 產生 audit record"), and available for any other administrative
-- action worth recording later.
CREATE TABLE IF NOT EXISTS retention_events (
    event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL,
    action       TEXT NOT NULL,
    detail       TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_retention_events_session ON retention_events(session_id);
`

// migration is one schema step from version N to N+1.
type migration struct {
	Description string
	SQL         []string
}

// migrateSteps[i] moves the schema from version i+1 to i+2. Fresh
// databases are created in the final shape by schema, so every ALTER
// tolerates "duplicate column" (same convention as internal/store/sqlite.go).
var migrateSteps = []migration{
	{
		Description: "v1 -> v2: per-host recording policy source, last_seq, ingest_jti",
		SQL: []string{
			`ALTER TABLE sessions ADD COLUMN recording_policy_source TEXT NOT NULL DEFAULT '';`,
			`ALTER TABLE sessions ADD COLUMN last_seq INTEGER NOT NULL DEFAULT 0;`,
			`ALTER TABLE sessions ADD COLUMN ingest_jti TEXT NOT NULL DEFAULT '';`,
		},
	},
}

// freeBytesFunc reports the bytes available to unprivileged writers on
// dir's filesystem; a variable so tests can simulate a full disk.
var freeBytesFunc = func(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// backupPath is where openDB snapshots a database before migrating it
// from version installed.
func backupPath(path string, installed int) string {
	return fmt.Sprintf("%s.pre-v%d.bak", path, installed)
}

// backupBeforeMigration snapshots an existing database with VACUUM INTO
// before any migration touches it (per-host recording spec §21.3, D-F). It
// refuses when free space is below twice the database size, and refuses to
// overwrite a previous backup.
func backupBeforeMigration(db *sql.DB, path string, installed int) error {
	dst := backupPath(path, installed)
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("refusing to migrate: backup %s already exists (move it aside after confirming the previous upgrade, see the pilot-session-store runbook)", dst)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat backup %s: %w", dst, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat index database: %w", err)
	}
	need := uint64(info.Size()) * 2
	free, err := freeBytesFunc(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("check free space for migration backup: %w", err)
	}
	if free < need {
		return fmt.Errorf("refusing to migrate: %d bytes free next to %s, need at least %d (2x the database) for the pre-migration backup", free, path, need)
	}
	// VACUUM INTO cannot run inside a transaction; it runs on its own.
	if _, err := db.Exec(`VACUUM INTO ?`, dst); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("pre-migration backup to %s: %w", dst, err)
	}
	if err := os.Chmod(dst, 0o600); err != nil {
		return fmt.Errorf("chmod backup %s: %w", dst, err)
	}
	return nil
}

// migrate applies every step from installed to SchemaVersion, and the
// user_version bump, in one transaction.
func migrate(db *sql.DB, installed int) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for v := installed; v < SchemaVersion; v++ {
		step := migrateSteps[v-1]
		for _, stmt := range step.SQL {
			if _, err := tx.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
				return fmt.Errorf("migration %q: %w", step.Description, err)
			}
		}
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d;`, SchemaVersion)); err != nil {
		return fmt.Errorf("set user_version=%d: %w", SchemaVersion, err)
	}
	return tx.Commit()
}

// Migration describes a schema upgrade that Open performed on an existing
// database, so the caller can log it.
type Migration struct {
	FromVersion int
	ToVersion   int
	// BackupPath is the VACUUM INTO snapshot taken before migrating.
	BackupPath string
}

// openDB opens (or creates) the SQLite index database at path. Schema is
// tracked via PRAGMA user_version, matching internal/store/sqlite.go's
// Open — no errors are swallowed, and a database newer than this binary
// understands fails closed rather than silently truncating writes. An
// existing older database is backed up (VACUUM INTO) before it is migrated;
// the returned Migration is non-nil only then.
func openDB(path string) (*sql.DB, *Migration, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, nil, fmt.Errorf("open sqlite: %w", err)
	}
	var installed int
	if err := db.QueryRow(`PRAGMA user_version;`).Scan(&installed); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("read user_version: %w", err)
	}
	if installed > SchemaVersion {
		_ = db.Close()
		return nil, nil, fmt.Errorf("index database is newer (%d) than this binary supports (%d); upgrade pilot-session-store", installed, SchemaVersion)
	}
	var migration *Migration
	if installed > 0 && installed < SchemaVersion {
		if err := backupBeforeMigration(db, path, installed); err != nil {
			_ = db.Close()
			return nil, nil, err
		}
		if err := migrate(db, installed); err != nil {
			_ = db.Close()
			return nil, nil, err
		}
		migration = &Migration{FromVersion: installed, ToVersion: SchemaVersion, BackupPath: backupPath(path, installed)}
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("init schema: %w", err)
	}
	if installed == 0 {
		if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d;`, SchemaVersion)); err != nil {
			_ = db.Close()
			return nil, nil, fmt.Errorf("set user_version=%d: %w", SchemaVersion, err)
		}
	}
	return db, migration, nil
}
