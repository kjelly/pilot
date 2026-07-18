package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

// SchemaVersion is the current schema version. Bump it whenever a
// migration is added to migrateSteps. PRAGMA user_version is used to
// record the installed version on disk so that startup is idempotent
// and free of swallowed errors.
const SchemaVersion = 13

const schema = `
-- The base schema is the FINAL shape only. The agent-loop tables that
-- used to live here (runs, proposals, agent_messages, host_failure_seen)
-- were retired 2026-07-17; keeping them in the base schema would
-- resurrect them on every Open right after the drop migration removed
-- them. Legacy DBs converge on this shape via migrateSteps; brand-new
-- DBs get it directly and fast-forward user_version (see Open).

CREATE TABLE IF NOT EXISTS spec_checkpoints (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    spec_path     TEXT NOT NULL,
    row_id        TEXT NOT NULL,
    run_id        TEXT NOT NULL,
    proposal_id   TEXT DEFAULT '',
    task_index    INTEGER NOT NULL DEFAULT 0,
    module        TEXT DEFAULT '',
    param_hash    TEXT DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'compiled',
    verified_at   DATETIME,
    verify_detail TEXT DEFAULT '',
    created_at    DATETIME NOT NULL,
    UNIQUE(spec_path, row_id)
);
CREATE INDEX IF NOT EXISTS idx_checkpoints_spec ON spec_checkpoints(spec_path, row_id);
CREATE INDEX IF NOT EXISTS idx_checkpoints_run ON spec_checkpoints(run_id);
CREATE INDEX IF NOT EXISTS idx_checkpoints_proposal ON spec_checkpoints(proposal_id);

CREATE TABLE IF NOT EXISTS delivery_events (
    event_id     INTEGER PRIMARY KEY,
    run_id       TEXT NOT NULL,
    seq          INTEGER NOT NULL,
    operation_id TEXT NOT NULL,
    type         TEXT NOT NULL,
    step         TEXT,
    payload_json TEXT NOT NULL,
    exit_code    INTEGER,
    created_at   TEXT NOT NULL,
    UNIQUE(run_id, seq),
    UNIQUE(run_id, operation_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_delivery_events_one_start
    ON delivery_events(run_id) WHERE type = 'run_started';
CREATE UNIQUE INDEX IF NOT EXISTS idx_delivery_events_one_finish
    ON delivery_events(run_id) WHERE type = 'run_finished';
CREATE INDEX IF NOT EXISTS idx_delivery_events_run_seq ON delivery_events(run_id, seq);

CREATE TABLE IF NOT EXISTS verify_evidence (
    evidence_id         INTEGER PRIMARY KEY,
    run_id              TEXT NOT NULL,
    spec_path           TEXT NOT NULL,
    row_id              TEXT NOT NULL,
    host                TEXT NOT NULL,
    attempt             INTEGER NOT NULL,
    operation_id        TEXT NOT NULL,
    content_hash        TEXT NOT NULL,
    command             TEXT NOT NULL,
    expected            TEXT NOT NULL,
    stdout              TEXT,
    stderr              TEXT,
    exit_code           INTEGER,
    probe_status        TEXT NOT NULL,
    verdict             TEXT NOT NULL,
    redacted            INTEGER NOT NULL,
    stdout_truncated    INTEGER NOT NULL,
    stderr_truncated    INTEGER NOT NULL,
    started_at          TEXT NOT NULL,
    finished_at         TEXT NOT NULL,
    UNIQUE(run_id, spec_path, row_id, host, attempt),
    UNIQUE(run_id, operation_id)
);
CREATE INDEX IF NOT EXISTS idx_verify_evidence_run ON verify_evidence(run_id, spec_path, row_id, host);

CREATE VIEW IF NOT EXISTS delivery_runs AS
SELECT s.run_id,
       s.created_at AS started_at,
       (SELECT MAX(h.created_at) FROM delivery_events h WHERE h.run_id=s.run_id AND h.type='run_heartbeat') AS last_heartbeat_at,
       (SELECT f.created_at FROM delivery_events f WHERE f.run_id=s.run_id AND f.type='run_finished') AS finished_at,
       (SELECT json_extract(f.payload_json, '$.outcome') FROM delivery_events f WHERE f.run_id=s.run_id AND f.type='run_finished') AS outcome,
       (SELECT f.exit_code FROM delivery_events f WHERE f.run_id=s.run_id AND f.type='run_finished') AS exit_code
FROM delivery_events s WHERE s.type='run_started';

CREATE TRIGGER IF NOT EXISTS delivery_events_no_update
BEFORE UPDATE ON delivery_events BEGIN SELECT RAISE(ABORT, 'delivery_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS delivery_events_no_delete
BEFORE DELETE ON delivery_events BEGIN SELECT RAISE(ABORT, 'delivery_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS verify_evidence_no_update
BEFORE UPDATE ON verify_evidence BEGIN SELECT RAISE(ABORT, 'verify_evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS verify_evidence_no_delete
BEFORE DELETE ON verify_evidence BEGIN SELECT RAISE(ABORT, 'verify_evidence is append-only'); END;
`

// migration is one ALTER TABLE statement. Bump SchemaVersion when
// adding entries; the migration runner compares user_version to
// SchemaVersion and applies only the steps it still needs.
type migration struct {
	Description string
	SQL         string
}

// migrateSteps lists the migrations applied in order. Each step moves
// the schema from version N to version N+1.
//
// Each entry is run idempotently: the runner tolerates "duplicate
// column" errors (which happen when the schema's CREATE TABLE
// statements already include the column on fresh installs) so that
// legacy and new installs converge on the same PRAGMA user_version.
var migrateSteps = []migration{
	{
		Description: "add runs.batch_id",
		SQL:         `ALTER TABLE runs ADD COLUMN batch_id TEXT;`,
	},
	{
		Description: "add runs.dry_run",
		SQL:         `ALTER TABLE runs ADD COLUMN dry_run INTEGER DEFAULT 0;`,
	},
	{
		Description: "add runs.error",
		SQL:         `ALTER TABLE runs ADD COLUMN error TEXT;`,
	},
	{
		Description: "add proposals.dry_run",
		SQL:         `ALTER TABLE proposals ADD COLUMN dry_run INTEGER DEFAULT 0;`,
	},
	{
		Description: "create plans table",
		SQL: `CREATE TABLE IF NOT EXISTS plans (
			id TEXT PRIMARY KEY,
			run_id TEXT DEFAULT '',
			title TEXT NOT NULL,
			summary TEXT NOT NULL,
			operations JSON NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			created_at DATETIME NOT NULL,
			reviewed_at DATETIME,
			executed_at DATETIME,
			notes TEXT DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_plans_run ON plans(run_id);
		CREATE INDEX IF NOT EXISTS idx_plans_status ON plans(status);`,
	},
	{
		Description: "create embedding_cache table",
		SQL: `CREATE TABLE IF NOT EXISTS embedding_cache (
			text_hash    TEXT PRIMARY KEY,
			model        TEXT NOT NULL,
			vector       TEXT NOT NULL,
			created_at   DATETIME NOT NULL
		);`,
	},
	{
		Description: "add runs.sandbox_image (sandbox mode audit trail)",
		SQL:         `ALTER TABLE runs ADD COLUMN sandbox_image TEXT DEFAULT '';`,
	},
	{
		Description: "add spec traceability (proposals.spec_id/row_id + spec_checkpoints + proposal_results)",
		SQL: `ALTER TABLE proposals ADD COLUMN spec_id TEXT DEFAULT '';
		      ALTER TABLE proposals ADD COLUMN row_id TEXT DEFAULT '';
		      CREATE INDEX IF NOT EXISTS idx_proposals_spec ON proposals(spec_id, row_id);
		      CREATE TABLE IF NOT EXISTS spec_checkpoints (
				id            INTEGER PRIMARY KEY AUTOINCREMENT,
				spec_path     TEXT NOT NULL,
				row_id        TEXT NOT NULL,
				run_id        TEXT NOT NULL,
				proposal_id   TEXT DEFAULT '',
				task_index    INTEGER NOT NULL DEFAULT 0,
				module        TEXT DEFAULT '',
				param_hash    TEXT DEFAULT '',
				status        TEXT NOT NULL DEFAULT 'compiled',
				verified_at   DATETIME,
				verify_detail TEXT DEFAULT '',
				created_at    DATETIME NOT NULL,
				UNIQUE(spec_path, row_id, run_id)
			);
			CREATE INDEX IF NOT EXISTS idx_checkpoints_spec ON spec_checkpoints(spec_path, row_id);
			CREATE INDEX IF NOT EXISTS idx_checkpoints_run ON spec_checkpoints(run_id);
			CREATE INDEX IF NOT EXISTS idx_checkpoints_proposal ON spec_checkpoints(proposal_id);
			CREATE TABLE IF NOT EXISTS proposal_results (
				id           INTEGER PRIMARY KEY AUTOINCREMENT,
				proposal_id  TEXT NOT NULL,
				check_id     TEXT NOT NULL,
				host         TEXT NOT NULL DEFAULT '',
				status       TEXT NOT NULL,
				detail       TEXT DEFAULT '',
				recorded_at  DATETIME NOT NULL,
				UNIQUE(proposal_id, check_id)
			);
			CREATE INDEX IF NOT EXISTS idx_presults_proposal ON proposal_results(proposal_id);`,
	},
	{
		// Rebuild spec_checkpoints with UNIQUE(spec_path, row_id) instead
		// of UNIQUE(spec_path, row_id, run_id). A checkpoint is the
		// canonical state of ONE requirement advancing through
		// compiled → applied → verified-*; including run_id in the key
		// meant `pilot verify` (which used a different run_id than
		// `pilot spec --generate`) inserted a parallel row instead of
		// flipping the existing one, double-counting coverage. The
		// INSERT collapses any pre-existing duplicate (spec_path,row_id)
		// rows: MAX(module/task_index/param_hash) keeps the non-empty
		// compile-time values, and the status ranking keeps the most
		// advanced state.
		Description: "spec_checkpoints: unique on (spec_path,row_id), collapse dup rows",
		SQL: `CREATE TABLE spec_checkpoints_new (
				id            INTEGER PRIMARY KEY AUTOINCREMENT,
				spec_path     TEXT NOT NULL,
				row_id        TEXT NOT NULL,
				run_id        TEXT NOT NULL,
				proposal_id   TEXT DEFAULT '',
				task_index    INTEGER NOT NULL DEFAULT 0,
				module        TEXT DEFAULT '',
				param_hash    TEXT DEFAULT '',
				status        TEXT NOT NULL DEFAULT 'compiled',
				verified_at   DATETIME,
				verify_detail TEXT DEFAULT '',
				created_at    DATETIME NOT NULL,
				UNIQUE(spec_path, row_id)
			);
			INSERT INTO spec_checkpoints_new
				(spec_path, row_id, run_id, proposal_id, task_index, module, param_hash, status, verified_at, verify_detail, created_at)
			SELECT a.spec_path, a.row_id,
				(SELECT run_id FROM spec_checkpoints b WHERE b.spec_path=a.spec_path AND b.row_id=a.row_id ORDER BY id DESC LIMIT 1),
				MAX(a.proposal_id), MAX(a.task_index), MAX(a.module), MAX(a.param_hash),
				(SELECT status FROM spec_checkpoints c WHERE c.spec_path=a.spec_path AND c.row_id=a.row_id
					ORDER BY CASE status
						WHEN 'verified-fail' THEN 4
						WHEN 'verified-pass' THEN 3
						WHEN 'applied' THEN 2
						WHEN 'compiled' THEN 1
						ELSE 0 END DESC, id DESC LIMIT 1),
				MAX(a.verified_at), MAX(a.verify_detail), MIN(a.created_at)
			FROM spec_checkpoints a
			GROUP BY a.spec_path, a.row_id;
			DROP TABLE spec_checkpoints;
			ALTER TABLE spec_checkpoints_new RENAME TO spec_checkpoints;
			CREATE INDEX IF NOT EXISTS idx_checkpoints_spec ON spec_checkpoints(spec_path, row_id);
			CREATE INDEX IF NOT EXISTS idx_checkpoints_run ON spec_checkpoints(run_id);
			CREATE INDEX IF NOT EXISTS idx_checkpoints_proposal ON spec_checkpoints(proposal_id);`,
	},
	{
		// plans and embedding_cache were deprecated 2026-07-17: plans was only
		// ever written through a tool hardwired to a nil store, and the
		// embedding cache belonged to an abandoned vector-RAG design (search
		// is BM25/bleve now). Both tables held no production data.
		Description: "drop deprecated plans and embedding_cache tables",
		SQL: `DROP INDEX IF EXISTS idx_plans_run;
		      DROP INDEX IF EXISTS idx_plans_status;
		      DROP TABLE IF EXISTS plans;
		      DROP TABLE IF EXISTS embedding_cache;`,
	},

	{
		// The LLM-agent surface was retired 2026-07-17; these tables were
		// only ever written by the agent loop (runs/proposals/agent_messages/
		// host_failure_seen) or by verify --proposal-id (proposal_results),
		// and nothing in the spec->verify->apply mainline reads them.
		Description: "drop agent-loop tables (runs, proposals, proposal_results, agent_messages, host_failure_seen)",
		SQL: `DROP TABLE IF EXISTS proposal_results;
		      DROP TABLE IF EXISTS agent_messages;
		      DROP TABLE IF EXISTS host_failure_seen;
		      DROP TABLE IF EXISTS proposals;
		      DROP TABLE IF EXISTS runs;`,
	},
	{
		// Replay of the previous step: binaries built before the base
		// schema stopped CREATE-ing the agent tables resurrected them on
		// the very next Open after the v11 drop. Any DB that passed
		// through such a binary sits at user_version=11 WITH zombie
		// tables; this step sweeps them again. Fresh DBs never run it
		// (they fast-forward), clean v11 DBs no-op on IF EXISTS.
		Description: "re-drop agent-loop tables resurrected by pre-fix base schema",
		SQL: `DROP TABLE IF EXISTS proposal_results;
		      DROP TABLE IF EXISTS agent_messages;
		      DROP TABLE IF EXISTS host_failure_seen;
		      DROP TABLE IF EXISTS proposals;
		      DROP TABLE IF EXISTS runs;`,
	},
	{
		Description: "create append-only delivery evidence stream",
		SQL: `CREATE TABLE IF NOT EXISTS delivery_events (
				event_id INTEGER PRIMARY KEY, run_id TEXT NOT NULL, seq INTEGER NOT NULL,
				operation_id TEXT NOT NULL, type TEXT NOT NULL, step TEXT, payload_json TEXT NOT NULL,
				exit_code INTEGER, created_at TEXT NOT NULL, UNIQUE(run_id, seq), UNIQUE(run_id, operation_id));
			CREATE UNIQUE INDEX IF NOT EXISTS idx_delivery_events_one_start ON delivery_events(run_id) WHERE type = 'run_started';
			CREATE UNIQUE INDEX IF NOT EXISTS idx_delivery_events_one_finish ON delivery_events(run_id) WHERE type = 'run_finished';
			CREATE INDEX IF NOT EXISTS idx_delivery_events_run_seq ON delivery_events(run_id, seq);
			CREATE TABLE IF NOT EXISTS verify_evidence (
				evidence_id INTEGER PRIMARY KEY, run_id TEXT NOT NULL, spec_path TEXT NOT NULL, row_id TEXT NOT NULL,
				host TEXT NOT NULL, attempt INTEGER NOT NULL, operation_id TEXT NOT NULL, content_hash TEXT NOT NULL,
				command TEXT NOT NULL, expected TEXT NOT NULL, stdout TEXT, stderr TEXT, exit_code INTEGER,
				probe_status TEXT NOT NULL, verdict TEXT NOT NULL, redacted INTEGER NOT NULL,
				stdout_truncated INTEGER NOT NULL, stderr_truncated INTEGER NOT NULL,
				started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
				UNIQUE(run_id, spec_path, row_id, host, attempt), UNIQUE(run_id, operation_id));
			CREATE INDEX IF NOT EXISTS idx_verify_evidence_run ON verify_evidence(run_id, spec_path, row_id, host);
			CREATE VIEW IF NOT EXISTS delivery_runs AS
			SELECT s.run_id, s.created_at AS started_at,
				(SELECT MAX(h.created_at) FROM delivery_events h WHERE h.run_id=s.run_id AND h.type='run_heartbeat') AS last_heartbeat_at,
				(SELECT f.created_at FROM delivery_events f WHERE f.run_id=s.run_id AND f.type='run_finished') AS finished_at,
				(SELECT json_extract(f.payload_json, '$.outcome') FROM delivery_events f WHERE f.run_id=s.run_id AND f.type='run_finished') AS outcome,
				(SELECT f.exit_code FROM delivery_events f WHERE f.run_id=s.run_id AND f.type='run_finished') AS exit_code
			FROM delivery_events s WHERE s.type='run_started';
			CREATE TRIGGER IF NOT EXISTS delivery_events_no_update BEFORE UPDATE ON delivery_events BEGIN SELECT RAISE(ABORT, 'delivery_events is append-only'); END;
			CREATE TRIGGER IF NOT EXISTS delivery_events_no_delete BEFORE DELETE ON delivery_events BEGIN SELECT RAISE(ABORT, 'delivery_events is append-only'); END;
			CREATE TRIGGER IF NOT EXISTS verify_evidence_no_update BEFORE UPDATE ON verify_evidence BEGIN SELECT RAISE(ABORT, 'verify_evidence is append-only'); END;
			CREATE TRIGGER IF NOT EXISTS verify_evidence_no_delete BEFORE DELETE ON verify_evidence BEGIN SELECT RAISE(ABORT, 'verify_evidence is append-only'); END;`,
	},
}

// Open opens (or creates) the SQLite database at path and applies any
// pending migrations. Schema is tracked via PRAGMA user_version — no
// errors are swallowed.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// A brand-new DB gets the final base schema directly and fast-forwards
	// user_version — the migration chain only exists to walk LEGACY DBs
	// (which still carry the retired agent-loop tables its ALTER steps
	// target) up to the same shape.
	var objects, installed int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master;`).Scan(&objects); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("inspect sqlite_master: %w", err)
	}
	if err := db.QueryRow(`PRAGMA user_version;`).Scan(&installed); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read user_version: %w", err)
	}
	if installed > SchemaVersion {
		_ = db.Close()
		return nil, fmt.Errorf("database is newer (%d) than this binary supports (%d); upgrade pilot", installed, SchemaVersion)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if objects == 0 && installed == 0 {
		if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d;`, SchemaVersion)); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("fast-forward user_version: %w", err)
		}
		return &Store{db: db}, nil
	}
	if err := applyMigrations(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// applyMigrations inspects PRAGMA user_version and applies any
// migrations whose version is greater than what is installed. Each
// successful migration bumps user_version atomically.
func applyMigrations(db *sql.DB) error {
	var installed int
	if err := db.QueryRow(`PRAGMA user_version;`).Scan(&installed); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	if installed > SchemaVersion {
		return fmt.Errorf("database is newer (%d) than this binary supports (%d); upgrade pilot", installed, SchemaVersion)
	}
	for v := installed; v < SchemaVersion; v++ {
		step := migrateSteps[v]
		if _, err := db.Exec(step.SQL); err != nil {
			// SQLite signals "column already exists" with a specific
			// wording. This happens when the legacy CREATE TABLE in
			// the base schema already includes the column. Treat that
			// as success and continue, but keep the PRAGMA bump so
			// user_version converges.
			if !isDuplicateColumnErr(err) {
				return fmt.Errorf("migration %d (%s) failed: %w", v+1, step.Description, err)
			}
		}
		if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d;`, v+1)); err != nil {
			return fmt.Errorf("set user_version=%d: %w", v+1, err)
		}
	}

	// After all migrations, create indexes that may reference columns
	// added by migrations.
	return nil
}

// isDuplicateColumnErr returns true for the SQLite error that arises
// when ALTER TABLE ADD COLUMN targets a name that already exists.
func isDuplicateColumnErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "duplicate column name") || contains(msg, "already exists")
}

func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func (s *Store) Close() error { return s.db.Close() }

// --- spec traceability (apply → verify closure) -----------------------

// Checkpoint is the persisted (spec_path, row_id, run_id, proposal_id)
// mapping. It lets auditors answer "where in run X did requirement
// C2.5.1 land?" and "have all spec rows been verified?".
type Checkpoint struct {
	ID           int64
	SpecPath     string
	RowID        string
	RunID        string
	ProposalID   string
	TaskIndex    int
	Module       string
	ParamHash    string
	Status       string // compiled | applied | verified-pass | verified-fail
	VerifiedAt   *time.Time
	VerifyDetail string
	CreatedAt    time.Time
}

// UpsertCheckpoint inserts or updates the canonical checkpoint for a
// (spec_path, row_id) requirement. Used by `pilot spec --generate` to
// record the (spec → task → proposal) linkage, and by `pilot verify`
// to flip Status to verified-pass / verified-fail on the SAME row.
// The update preserves compile-time fields (module/task_index/
// param_hash/proposal_id) when the caller passes empty values, so a
// verify pass doesn't wipe the linkage recorded at generate time.
func (s *Store) UpsertCheckpoint(cp *Checkpoint) error {
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO spec_checkpoints
		 (spec_path, row_id, run_id, proposal_id, task_index, module, param_hash, status, verified_at, verify_detail, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(spec_path, row_id) DO UPDATE SET
			run_id = excluded.run_id,
			proposal_id = CASE WHEN excluded.proposal_id <> '' THEN excluded.proposal_id ELSE spec_checkpoints.proposal_id END,
			task_index  = CASE WHEN excluded.task_index <> 0  THEN excluded.task_index  ELSE spec_checkpoints.task_index END,
			module      = CASE WHEN excluded.module <> ''      THEN excluded.module      ELSE spec_checkpoints.module END,
			param_hash  = CASE WHEN excluded.param_hash <> ''  THEN excluded.param_hash  ELSE spec_checkpoints.param_hash END,
			status = excluded.status,
			verified_at = excluded.verified_at,
			verify_detail = excluded.verify_detail`,
		cp.SpecPath, cp.RowID, cp.RunID, cp.ProposalID, cp.TaskIndex, cp.Module, cp.ParamHash,
		cp.Status, cp.VerifiedAt, cp.VerifyDetail, cp.CreatedAt,
	)
	return err
}

// ListCheckpoints returns every checkpoint for a given spec path.
// Used by `pilot spec --status` and by Coverage rolls.
func (s *Store) ListCheckpoints(specPath string) ([]*Checkpoint, error) {
	rows, err := s.db.Query(`SELECT id, spec_path, row_id, run_id, proposal_id, task_index, module, param_hash, status, verified_at, verify_detail, created_at FROM spec_checkpoints WHERE spec_path = ? ORDER BY row_id`, specPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Checkpoint
	for rows.Next() {
		var cp Checkpoint
		var verifiedAt sql.NullTime
		if err := rows.Scan(&cp.ID, &cp.SpecPath, &cp.RowID, &cp.RunID, &cp.ProposalID, &cp.TaskIndex, &cp.Module, &cp.ParamHash, &cp.Status, &verifiedAt, &cp.VerifyDetail, &cp.CreatedAt); err != nil {
			return nil, err
		}
		if verifiedAt.Valid {
			t := verifiedAt.Time
			cp.VerifiedAt = &t
		}
		out = append(out, &cp)
	}
	return out, rows.Err()
}
