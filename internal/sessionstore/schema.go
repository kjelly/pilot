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
	"fmt"

	_ "modernc.org/sqlite"
)

// SchemaVersion is the current schema version, tracked via PRAGMA
// user_version — same house style as internal/store/sqlite.go. Bump it
// and add a migration step whenever the schema changes shape after this
// package has shipped to any real deployment.
const SchemaVersion = 1

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
    key_id          TEXT NOT NULL DEFAULT ''
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

// openDB opens (or creates) the SQLite index database at path. Schema is
// tracked via PRAGMA user_version, matching internal/store/sqlite.go's
// Open — no errors are swallowed, and a database newer than this binary
// understands fails closed rather than silently truncating writes.
func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	var installed int
	if err := db.QueryRow(`PRAGMA user_version;`).Scan(&installed); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read user_version: %w", err)
	}
	if installed > SchemaVersion {
		_ = db.Close()
		return nil, fmt.Errorf("index database is newer (%d) than this binary supports (%d); upgrade pilot-session-store", installed, SchemaVersion)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if installed < SchemaVersion {
		if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d;`, SchemaVersion)); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("set user_version=%d: %w", SchemaVersion, err)
		}
	}
	return db, nil
}
