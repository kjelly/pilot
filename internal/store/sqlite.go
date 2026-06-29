package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Run struct {
	ID           string
	StartedAt    time.Time
	FinishedAt   *time.Time
	Mode         string
	Playbook     string
	Inventory    string
	Model        string
	Status       string
	BatchID      string // groups runs from a single batch (e.g. --from-stdin invocation)
	DryRun       bool   // true if --dry-run-all was set
	Error        string // last error (e.g. syntax-check failure)
	SandboxImage string // docker image when sandbox mode was used (empty = local)
}

type Proposal struct {
	ID         string          `json:"id"`
	RunID      string          `json:"run_id"`
	Host       string          `json:"host"`
	Tool       string          `json:"tool"`
	Args       json.RawMessage `json:"args"`
	Rationale  string          `json:"rationale"`
	RiskLevel  string          `json:"risk_level"`
	CISControl string          `json:"cis_control,omitempty"`
	SpecID     string          `json:"spec_id,omitempty"`
	RowID      string          `json:"row_id,omitempty"`
	Status     string          `json:"status"`
	Reversible bool            `json:"reversible"`
	DryRun     bool            `json:"dry_run,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	ReviewedAt *time.Time      `json:"reviewed_at,omitempty"`
	AppliedAt  *time.Time      `json:"applied_at,omitempty"`
	FilePath   string          `json:"file_path,omitempty"`
}

// PlanOperation is one step inside a Plan. A plan can be approved in
// bulk; each approved operation is then executed individually with
// auto-approval (the human already saw the whole list).
type PlanOperation struct {
	Tool       string          `json:"tool"`
	Args       json.RawMessage `json:"args"`
	Host       string          `json:"host,omitempty"`
	Rationale  string          `json:"rationale"`
	RiskLevel  string          `json:"risk_level"`
	CISControl string          `json:"cis_control,omitempty"`
}

// Plan is a batch of operations submitted by the model for
// human-in-the-loop approval as a group.
type Plan struct {
	ID          string
	RunID       string
	Title       string
	Summary     string
	Operations  []PlanOperation
	Status      string // pending | approved | rejected | executed | failed
	CreatedAt   time.Time
	ReviewedAt  *time.Time
	ExecutedAt  *time.Time
	Notes       string // human comments
}

type AgentMessage struct {
	ID        int64
	RunID     string
	Role      string
	Content   string
	ToolCalls json.RawMessage
	CreatedAt time.Time
}

type Store struct {
	db *sql.DB
}

// SchemaVersion is the current schema version. Bump it whenever a
// migration is added to migrateSteps. PRAGMA user_version is used to
// record the installed version on disk so that startup is idempotent
// and free of swallowed errors.
const SchemaVersion = 8

const schema = `
CREATE TABLE IF NOT EXISTS runs (
    id           TEXT PRIMARY KEY,
    started_at   DATETIME NOT NULL,
    finished_at  DATETIME,
    mode         TEXT NOT NULL,
    playbook     TEXT,
    inventory    TEXT,
    model        TEXT NOT NULL,
    status       TEXT NOT NULL,
    batch_id     TEXT,
    dry_run      INTEGER DEFAULT 0,
    error        TEXT,
    sandbox_image TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS proposals (
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
    file_path    TEXT,
    dry_run      INTEGER DEFAULT 0
);

-- Indexes that reference columns added by migrations are created
-- after migrations run (see applyMigrations).

CREATE TABLE IF NOT EXISTS host_failure_seen (
    run_id       TEXT NOT NULL,
    host         TEXT NOT NULL,
    first_seen   DATETIME NOT NULL,
    PRIMARY KEY (run_id, host)
);

CREATE TABLE IF NOT EXISTS agent_messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL,
    role         TEXT NOT NULL,
    content      TEXT,
    tool_calls   JSON,
    created_at   DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_proposals_run ON proposals(run_id);
CREATE INDEX IF NOT EXISTS idx_proposals_status ON proposals(status);

CREATE INDEX IF NOT EXISTS idx_messages_run ON agent_messages(run_id);

CREATE TABLE IF NOT EXISTS plans (
	id            TEXT PRIMARY KEY,
	run_id        TEXT DEFAULT '',
	title         TEXT NOT NULL,
	summary       TEXT NOT NULL,
	operations    JSON NOT NULL,
	status        TEXT NOT NULL DEFAULT 'pending',
	created_at    DATETIME NOT NULL,
	reviewed_at   DATETIME,
	executed_at   DATETIME,
	notes         TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_plans_run ON plans(run_id);
CREATE INDEX IF NOT EXISTS idx_plans_status ON plans(status);
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
		SQL:         `CREATE TABLE IF NOT EXISTS plans (
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
}

// Open opens (or creates) the SQLite database at path and applies any
// pending migrations. Schema is tracked via PRAGMA user_version — no
// errors are swallowed.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if err := applyMigrations(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Auto-clean stale runs: any run in 'running' status for more than 2 hours is marked as aborted
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	_, _ = db.Exec(
		`UPDATE runs SET status = 'aborted', finished_at = ? WHERE status = 'running' AND started_at < ?`,
		time.Now(), twoHoursAgo,
	)
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
	for _, idx := range []string{
		`CREATE INDEX IF NOT EXISTS idx_runs_batch ON runs(batch_id)`,
	} {
		if _, err := db.Exec(idx); err != nil {
			if !contains(err.Error(), "no such column") {
				return fmt.Errorf("create index: %w", err)
			}
		}
	}
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

// ListRuns returns runs ordered by started_at DESC, capped at limit
// (0 means no cap). batchID, when non-empty, filters to that batch.
func (s *Store) ListRuns(batchID string, limit int) ([]*Run, error) {
	q := `SELECT id, started_at, finished_at, mode, playbook, inventory, model, status, batch_id, dry_run, error, sandbox_image FROM runs`
	var args []any
	if batchID != "" {
		q += ` WHERE batch_id = ?`
		args = append(args, batchID)
	}
	q += ` ORDER BY started_at DESC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Run
	for rows.Next() {
		var r Run
		var finishedAt sql.NullTime
		var batchID, errMsg, sandboxImage sql.NullString
		var dryRun int
		if err := rows.Scan(&r.ID, &r.StartedAt, &finishedAt, &r.Mode, &r.Playbook, &r.Inventory, &r.Model, &r.Status, &batchID, &dryRun, &errMsg, &sandboxImage); err != nil {
			return nil, err
		}
		if finishedAt.Valid {
			r.FinishedAt = &finishedAt.Time
		}
		if batchID.Valid {
			r.BatchID = batchID.String
		}
		if errMsg.Valid {
			r.Error = errMsg.String
		}
		if sandboxImage.Valid {
			r.SandboxImage = sandboxImage.String
		}
		r.DryRun = dryRun == 1
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *Store) CreateRun(r *Run) error {
	dryRun := 0
	if r.DryRun {
		dryRun = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO runs (id, started_at, mode, playbook, inventory, model, status, batch_id, dry_run, error, sandbox_image)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.StartedAt, r.Mode, r.Playbook, r.Inventory, r.Model, r.Status, r.BatchID, dryRun, r.Error, r.SandboxImage,
	)
	return err
}

// GetRun returns a single run by ID. Returns (nil, nil) if not found.
func (s *Store) GetRun(id string) (*Run, error) {
	row := s.db.QueryRow(`SELECT id, started_at, finished_at, mode, playbook, inventory, model, status, batch_id, dry_run, error, sandbox_image FROM runs WHERE id = ?`, id)
	var r Run
	var dryRun int
	var sandboxImage sql.NullString
	if err := row.Scan(&r.ID, &r.StartedAt, &r.FinishedAt, &r.Mode, &r.Playbook, &r.Inventory, &r.Model, &r.Status, &r.BatchID, &dryRun, &r.Error, &sandboxImage); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	r.DryRun = dryRun == 1
	if sandboxImage.Valid {
		r.SandboxImage = sandboxImage.String
	}
	return &r, nil
}

func (s *Store) FinishRun(id, status string) error {
	_, err := s.db.Exec(
		`UPDATE runs SET finished_at = ?, status = ? WHERE id = ?`,
		time.Now(), status, id,
	)
	return err
}

func (s *Store) SetRunError(id, errMsg string) error {
	_, err := s.db.Exec(
		`UPDATE runs SET error = ? WHERE id = ?`,
		errMsg, id,
	)
	return err
}

func (s *Store) SaveProposal(p *Proposal) error {
	reversible := 0
	if p.Reversible {
		reversible = 1
	}
	dryRun := 0
	if p.DryRun {
		dryRun = 1
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO proposals
		 (id, run_id, host, tool, args, rationale, risk_level, cis_control, status, reversible, created_at, reviewed_at, applied_at, file_path, dry_run)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.RunID, p.Host, p.Tool, string(p.Args), p.Rationale, p.RiskLevel,
		p.CISControl, p.Status, reversible, p.CreatedAt, p.ReviewedAt, p.AppliedAt, p.FilePath, dryRun,
	)
	return err
}

func (s *Store) UpdateProposalStatus(id, status string) error {
	now := time.Now()
	switch status {
	case "approved", "rejected":
		_, err := s.db.Exec(`UPDATE proposals SET status = ?, reviewed_at = ? WHERE id = ?`, status, now, id)
		return err
	case "applied":
		_, err := s.db.Exec(`UPDATE proposals SET status = ?, applied_at = ? WHERE id = ?`, status, now, id)
		return err
	default:
		_, err := s.db.Exec(`UPDATE proposals SET status = ? WHERE id = ?`, status, id)
		return err
	}
}

func (s *Store) GetProposal(id string) (*Proposal, error) {
	row := s.db.QueryRow(`SELECT id, run_id, host, tool, args, rationale, risk_level, cis_control, spec_id, row_id, status, reversible, created_at, reviewed_at, applied_at, file_path, dry_run FROM proposals WHERE id = ?`, id)
	var p Proposal
	var argsStr string
	var reversible, dryRun int
	if err := row.Scan(&p.ID, &p.RunID, &p.Host, &p.Tool, &argsStr, &p.Rationale, &p.RiskLevel, &p.CISControl, &p.Status, &reversible, &p.CreatedAt, &p.ReviewedAt, &p.AppliedAt, &p.FilePath, &dryRun); err != nil {
		return nil, err
	}
	p.Args = json.RawMessage(argsStr)
	p.Reversible = reversible == 1
	p.DryRun = dryRun == 1
	return &p, nil
}

func (s *Store) ListProposals(runID string) ([]*Proposal, error) {
	rows, err := s.db.Query(`SELECT id, run_id, host, tool, args, rationale, risk_level, cis_control, spec_id, row_id, status, reversible, created_at, reviewed_at, applied_at, file_path, dry_run FROM proposals WHERE run_id = ? ORDER BY created_at`, runID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Proposal
	for rows.Next() {
		var p Proposal
		var argsStr string
		var reversible, dryRun int
		if err := rows.Scan(&p.ID, &p.RunID, &p.Host, &p.Tool, &argsStr, &p.Rationale, &p.RiskLevel, &p.CISControl, &p.SpecID, &p.RowID, &p.Status, &reversible, &p.CreatedAt, &p.ReviewedAt, &p.AppliedAt, &p.FilePath, &dryRun); err != nil {
			return nil, err
		}
		p.Args = json.RawMessage(argsStr)
		p.Reversible = reversible == 1
		p.DryRun = dryRun == 1
		out = append(out, &p)
	}
	return out, rows.Err()
}

// ListBatchRuns returns all runs that share a batch_id, ordered by
// started_at. Used for batch summary printing.
func (s *Store) ListBatchRuns(batchID string) ([]*Run, error) {
	rows, err := s.db.Query(`SELECT id, started_at, finished_at, mode, playbook, inventory, model, status, batch_id, dry_run, error FROM runs WHERE batch_id = ? ORDER BY started_at`, batchID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Run
	for rows.Next() {
		var r Run
		var finishedAt sql.NullTime
		var batchID, errMsg sql.NullString
		var dryRun int
		if err := rows.Scan(&r.ID, &r.StartedAt, &finishedAt, &r.Mode, &r.Playbook, &r.Inventory, &r.Model, &r.Status, &batchID, &dryRun, &errMsg); err != nil {
			return nil, err
		}
		if finishedAt.Valid {
			r.FinishedAt = &finishedAt.Time
		}
		if batchID.Valid {
			r.BatchID = batchID.String
		}
		if errMsg.Valid {
			r.Error = errMsg.String
		}
		r.DryRun = dryRun == 1
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *Store) MarkFailureSeen(runID, host string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO host_failure_seen (run_id, host, first_seen) VALUES (?, ?, ?)`,
		runID, host, time.Now(),
	)
	return err
}

func (s *Store) HasFailureBeenSeen(runID, host string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM host_failure_seen WHERE run_id = ? AND host = ?`,
		runID, host,
	).Scan(&count)
	return count > 0, err
}

func (s *Store) SaveAgentMessage(m *AgentMessage) error {
	_, err := s.db.Exec(
		`INSERT INTO agent_messages (run_id, role, content, tool_calls, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		m.RunID, m.Role, m.Content, string(m.ToolCalls), m.CreatedAt,
	)
	return err
}

func (s *Store) ListAgentMessages(runID string) ([]*AgentMessage, error) {
	rows, err := s.db.Query(`SELECT id, run_id, role, content, tool_calls, created_at FROM agent_messages WHERE run_id = ? ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*AgentMessage
	for rows.Next() {
		var m AgentMessage
		var toolCalls sql.NullString
		if err := rows.Scan(&m.ID, &m.RunID, &m.Role, &m.Content, &toolCalls, &m.CreatedAt); err != nil {
			return nil, err
		}
		if toolCalls.Valid {
			m.ToolCalls = json.RawMessage(toolCalls.String)
		}
		out = append(out, &m)
	}
	return out, rows.Err()
}

// CreatePlan persists a new Plan in status=pending.
func (s *Store) CreatePlan(p *Plan) error {
	ops, err := json.Marshal(p.Operations)
	if err != nil {
		return fmt.Errorf("marshal operations: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO plans (id, run_id, title, summary, operations, status, created_at, notes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.RunID, p.Title, p.Summary, string(ops), p.Status, p.CreatedAt, p.Notes,
	)
	return err
}

// GetPlan loads a Plan by ID.
func (s *Store) GetPlan(id string) (*Plan, error) {
	row := s.db.QueryRow(`SELECT id, run_id, title, summary, operations, status, created_at, reviewed_at, executed_at, notes FROM plans WHERE id = ?`, id)
	var p Plan
	var ops string
	var reviewedAt, executedAt sql.NullTime
	if err := row.Scan(&p.ID, &p.RunID, &p.Title, &p.Summary, &ops, &p.Status, &p.CreatedAt, &reviewedAt, &executedAt, &p.Notes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(ops), &p.Operations); err != nil {
		return nil, fmt.Errorf("unmarshal operations: %w", err)
	}
	if reviewedAt.Valid {
		reviewed := reviewedAt.Time
		p.ReviewedAt = &reviewed
	}
	if executedAt.Valid {
		executed := executedAt.Time
		p.ExecutedAt = &executed
	}
	return &p, nil
}

// ListPlans returns plans for a run, optionally filtered by status.
// Newest first. limit=0 means no cap.
func (s *Store) ListPlans(runID, status string, limit int) ([]*Plan, error) {
	q := `SELECT id, run_id, title, summary, operations, status, created_at, reviewed_at, executed_at, notes FROM plans`
	var args []any
	var conds []string
	if runID != "" {
		conds = append(conds, "run_id = ?")
		args = append(args, runID)
	}
	if status != "" {
		conds = append(conds, "status = ?")
		args = append(args, status)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY created_at DESC"
	if limit > 0 {
		q += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Plan
	for rows.Next() {
		var p Plan
		var ops string
		var reviewedAt, executedAt sql.NullTime
		if err := rows.Scan(&p.ID, &p.RunID, &p.Title, &p.Summary, &ops, &p.Status, &p.CreatedAt, &reviewedAt, &executedAt, &p.Notes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(ops), &p.Operations); err != nil {
			return nil, err
		}
		if reviewedAt.Valid {
			reviewed := reviewedAt.Time
			p.ReviewedAt = &reviewed
		}
		if executedAt.Valid {
			executed := executedAt.Time
			p.ExecutedAt = &executed
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

// UpdatePlanStatus mutates the status (and timestamps) of a Plan.
func (s *Store) UpdatePlanStatus(id, status string) error {
	now := time.Now()
	var err error
	switch status {
	case "approved", "rejected":
		_, err = s.db.Exec(`UPDATE plans SET status = ?, reviewed_at = ? WHERE id = ?`, status, now, id)
	case "executed":
		_, err = s.db.Exec(`UPDATE plans SET status = ?, executed_at = ? WHERE id = ?`, status, now, id)
	default:
		_, err = s.db.Exec(`UPDATE plans SET status = ? WHERE id = ?`, status, id)
	}
	return err
}

func (s *Store) SaveEmbedding(textHash, model string, vector []float32) error {
	vecBytes, err := json.Marshal(vector)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO embedding_cache (text_hash, model, vector, created_at) VALUES (?, ?, ?, ?)`,
		textHash, model, string(vecBytes), time.Now(),
	)
	return err
}

func (s *Store) GetEmbedding(textHash, model string) ([]float32, error) {
	var vecStr string
	err := s.db.QueryRow(
		`SELECT vector FROM embedding_cache WHERE text_hash = ? AND model = ?`,
		textHash, model,
	).Scan(&vecStr)
	if err != nil {
		return nil, err
	}
	var vec []float32
	if err := json.Unmarshal([]byte(vecStr), &vec); err != nil {
		return nil, err
	}
	return vec, nil
}

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

// UpsertCheckpoint inserts or updates a (spec_path, row_id, run_id)
// checkpoint. Used by `pilot spec --generate` to record the
// (spec → task → proposal) linkage, and by `pilot verify` to flip
// Status to verified-pass / verified-fail.
func (s *Store) UpsertCheckpoint(cp *Checkpoint) error {
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO spec_checkpoints
		 (spec_path, row_id, run_id, proposal_id, task_index, module, param_hash, status, verified_at, verify_detail, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(spec_path, row_id, run_id) DO UPDATE SET
			proposal_id = excluded.proposal_id,
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

// ProposalResult is one row of the verify report tied back to the
// proposal that produced the change.
type ProposalResult struct {
	ID         int64
	ProposalID string
	CheckID    string
	Host       string
	Status     string // pass | fail | skip
	Detail     string
	RecordedAt time.Time
}

// RecordProposalResult stores one {proposal, check_id, status} triple.
// Re-recording the same (proposal, check_id) updates the previous row,
// so a re-run reflects the latest outcome.
func (s *Store) RecordProposalResult(r *ProposalResult) error {
	if r.RecordedAt.IsZero() {
		r.RecordedAt = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO proposal_results (proposal_id, check_id, host, status, detail, recorded_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(proposal_id, check_id) DO UPDATE SET
			status = excluded.status,
			detail = excluded.detail,
			recorded_at = excluded.recorded_at`,
		r.ProposalID, r.CheckID, r.Host, r.Status, r.Detail, r.RecordedAt,
	)
	return err
}

// ListProposalResults returns every verify result for one proposal.
func (s *Store) ListProposalResults(proposalID string) ([]*ProposalResult, error) {
	rows, err := s.db.Query(`SELECT id, proposal_id, check_id, host, status, detail, recorded_at FROM proposal_results WHERE proposal_id = ? ORDER BY check_id`, proposalID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*ProposalResult
	for rows.Next() {
		var r ProposalResult
		if err := rows.Scan(&r.ID, &r.ProposalID, &r.CheckID, &r.Host, &r.Status, &r.Detail, &r.RecordedAt); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}
