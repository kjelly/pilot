package detection

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

// Store owns the Detection Engine's SQLite state (spec §23-§27): baseline
// history, signal episodes/history, the Alertmanager delivery outbox, and
// model-provider request audit rows.
type Store struct {
	db   *sql.DB
	path string
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
	s := &Store{db: db, path: path}
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
// a single transaction (spec §26). verify/postVerifySQL support the
// rename-recreate-copy-verify-drop pattern spec §9.7 point 1 requires for
// a destructive table recreation: `sql` runs first (rename the old table
// out of the way, create the new shape, copy rows in), then `verify` runs
// (still inside the same transaction, before anything old is dropped) and
// any error it returns rolls the whole migration back, and only then does
// `postVerifySQL` run (the actual DROP of the renamed-away old table).
// requiresBackup marks a migration whose failure would be expensive to
// hand-recover from (spec §9.7 point 6) — OpenStore takes an on-disk
// VACUUM INTO snapshot before applying any pending migration with this set.
type migration struct {
	version        int
	sql            []string
	verify         func(tx *sql.Tx) error
	postVerifySQL  []string
	requiresBackup bool
}

// compareRowCount fails the migration (and thus rolls it back) if newTable
// and oldTable don't hold the same number of rows — spec §9.7 point 1's
// "verify row count" step, run before the old table is ever dropped.
// newTable/oldTable are always fixed string literals from this file, never
// caller/user input, so building the query by concatenation is safe.
func compareRowCount(tx *sql.Tx, newTable, oldTable string) error {
	var n, o int
	if err := tx.QueryRow("SELECT COUNT(*) FROM " + newTable).Scan(&n); err != nil {
		return fmt.Errorf("count %s: %w", newTable, err)
	}
	if err := tx.QueryRow("SELECT COUNT(*) FROM " + oldTable).Scan(&o); err != nil {
		return fmt.Errorf("count %s: %w", oldTable, err)
	}
	if n != o {
		return fmt.Errorf("row count mismatch: %s has %d rows, %s had %d", newTable, n, oldTable, o)
	}
	return nil
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

// schemaV2 generalizes the Detection Engine's persisted identity beyond
// `pilot_host` (spec §9.7, Phase 4). It touches the two tables spec §9.7
// names as persisting host identity:
//
//   - baseline_samples had NO incoming foreign keys, so it is safely
//     rename→create→copy→verify→drop recreated with a NEW primary key of
//     (subject_id, subject_kind, feature, bucket_ts) — the OLD primary key
//     (pilot_host, feature, bucket_ts) would have let two different-kind
//     subjects silently alias each other's history bucket whenever
//     pilot_host is empty for both (SQL NULL/'' does not violate a UNIQUE
//     constraint against another NULL/'', so an ON CONFLICT upsert keyed
//     only on the old columns would never actually deduplicate two
//     distinct non-managed subjects — this was verified empirically
//     against modernc.org/sqlite, not merely assumed).
//
//   - signal_episodes, by contrast, DOES have incoming foreign keys
//     (signal_history, outbox both reference signal_episodes(signal_id)).
//     A real reproduction against modernc.org/sqlite (this package's
//     driver) showed that ALTER TABLE ... RENAME TO silently rewrites
//     those other tables' FOREIGN KEY clauses to point at the RENAMED-AWAY
//     temporary table name — so a rename→recreate→drop on a table with
//     live FK dependents leaves the dependents permanently unable to
//     resolve their FK (confirmed reproducible even with
//     `PRAGMA foreign_keys=OFF` wrapping the transaction: the pragma
//     suppresses enforcement but not the rename's schema-text rewrite).
//     signal_episodes therefore only gets ADDITIVE `ALTER TABLE ADD COLUMN`
//     changes here — its pre-existing `pilot_host` column keeps its
//     original NOT NULL constraint (SQLite cannot relax a column
//     constraint via ALTER TABLE), so going forward a non-managed-host
//     episode's compatibility-mirror `pilot_host` is written as ""
//     (empty string) rather than spec §9.7 point 4's literal NULL — a
//     deliberate, disclosed deviation from the spec text forced by this
//     verified SQLite/driver constraint, not an oversight. See
//     docs/runbooks/detection-engine-subject-generalization.md.
var schemaV2 = migration{
	version:        2,
	requiresBackup: true,
	sql: []string{
		`ALTER TABLE baseline_samples RENAME TO baseline_samples_old`,
		`CREATE TABLE baseline_samples (
			subject_id TEXT NOT NULL,
			subject_kind TEXT NOT NULL,
			site TEXT NOT NULL DEFAULT '',
			pilot_host TEXT,
			feature TEXT NOT NULL,
			bucket_ts INTEGER NOT NULL,
			value REAL NOT NULL,
			PRIMARY KEY (subject_id, subject_kind, feature, bucket_ts)
		)`,
		`INSERT INTO baseline_samples (subject_id, subject_kind, site, pilot_host, feature, bucket_ts, value)
			SELECT pilot_host, 'managed_host', '', pilot_host, feature, bucket_ts, value FROM baseline_samples_old`,

		`ALTER TABLE signal_episodes ADD COLUMN subject_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE signal_episodes ADD COLUMN subject_kind TEXT NOT NULL DEFAULT ''`,
		`UPDATE signal_episodes SET subject_id = pilot_host, subject_kind = 'managed_host'`,
	},
	verify: func(tx *sql.Tx) error {
		return compareRowCount(tx, "baseline_samples", "baseline_samples_old")
	},
	postVerifySQL: []string{
		`DROP TABLE baseline_samples_old`,
	},
}

var migrations = []migration{schemaV1, schemaV2}

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

	var pending []migration
	for _, m := range list {
		if !applied[m.version] {
			pending = append(pending, m)
		}
	}
	// A truly fresh database (no migration ever previously applied) has
	// nothing worth preserving even if its FIRST-ever migration batch
	// happens to include a requiresBackup entry — only a database that
	// already had at least one migration recorded is a real upgrade with
	// pre-existing state to protect.
	if len(applied) > 0 && needsBackup(pending) {
		if _, err := s.backupBeforeMigration(); err != nil {
			return fmt.Errorf("pre-migration backup: %w", err)
		}
	}
	for _, m := range pending {
		if err := s.applyMigration(m); err != nil {
			return err
		}
	}
	return nil
}

func needsBackup(pending []migration) bool {
	for _, m := range pending {
		if m.requiresBackup {
			return true
		}
	}
	return false
}

// backupBeforeMigration writes a consistent VACUUM INTO snapshot of the
// pre-migration database next to it (spec §9.7 point 6) before a
// requiresBackup migration runs — the fallback an operator needs to roll
// back to the old binary/old schema, since spec §9.7 point 8 is explicit
// that a rolled-back old binary cannot simply read the new schema. A
// brand-new (not-yet-existing, e.g. in-memory or first-run) database has
// nothing worth preserving, so this is a no-op for it.
func (s *Store) backupBeforeMigration() (string, error) {
	if s.path == "" || s.path == ":memory:" {
		return "", nil
	}
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		return "", nil
	}
	backupPath := fmt.Sprintf("%s.pre-migration-%d.bak", s.path, time.Now().Unix())
	if _, err := s.db.Exec("VACUUM INTO ?", backupPath); err != nil {
		return "", fmt.Errorf("vacuum into %s: %w", backupPath, err)
	}
	return backupPath, nil
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
	if m.verify != nil {
		if verifyErr := m.verify(tx); verifyErr != nil {
			err = fmt.Errorf("migration %d verify: %w", m.version, verifyErr)
			return err
		}
	}
	for _, stmt := range m.postVerifySQL {
		if _, execErr := tx.Exec(stmt); execErr != nil {
			err = fmt.Errorf("migration %d (post-verify): %w", m.version, execErr)
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
