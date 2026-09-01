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

// schemaV2 adds Agent Monitoring Phase 3's remediation persistence
// (design doc §10). remediation_plans mirrors internal/repair.Plan
// exactly, plus its own state; approvals binds a decision to
// (plan_id, plan_hash) so an approval can never silently carry over to
// a plan whose executable content later changed; remediation_runs
// records the terminal outcome of exactly one execution attempt per
// plan — "replay of an already executed approved plan must fail" (spec
// §10) is enforced structurally by ux_remediation_runs_plan below, not
// just by application logic.
var schemaV2 = migration{
	version: 2,
	sql: []string{
		`CREATE TABLE remediation_plans (
			id TEXT PRIMARY KEY,
			incident_id TEXT NOT NULL,
			host TEXT NOT NULL,
			component TEXT NOT NULL,
			action TEXT NOT NULL,
			risk TEXT NOT NULL,
			executor_kind TEXT NOT NULL,
			executor_target TEXT NOT NULL,
			verification_spec TEXT NOT NULL,
			inventory_revision TEXT NOT NULL,
			contract_hash TEXT NOT NULL,
			plan_hash TEXT NOT NULL,
			state TEXT NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			FOREIGN KEY(incident_id) REFERENCES incidents(id)
		)`,
		`CREATE TABLE approvals (
			id TEXT PRIMARY KEY,
			plan_id TEXT NOT NULL,
			plan_hash TEXT NOT NULL,
			decision TEXT NOT NULL,
			actor TEXT NOT NULL,
			reason TEXT,
			created_at TEXT NOT NULL,
			FOREIGN KEY(plan_id) REFERENCES remediation_plans(id)
		)`,
		`CREATE TABLE remediation_runs (
			id TEXT PRIMARY KEY,
			plan_id TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT,
			result TEXT NOT NULL,
			audit_ref TEXT,
			verify_ref TEXT,
			FOREIGN KEY(plan_id) REFERENCES remediation_plans(id)
		)`,
		// At most one run per plan, ever — a second EnqueueRemediationRun
		// for the same plan_id fails at the DB level, not just by a
		// caller remembering to check first.
		`CREATE UNIQUE INDEX ux_remediation_runs_plan ON remediation_runs(plan_id)`,
	},
}

// schemaV3 adds Agent Monitoring Phase 4's policy persistence (design
// doc §11). Deliberately omits the doc's suggested action_budgets
// ledger table: budget/cooldown counts are instead DERIVED from
// approvals+remediation_plans, which already durably and atomically
// record every executed/approved action (Store.Approve's own
// transaction is the "atomic reservation" — see gatherPolicyFacts in
// policy_gather.go). A second ledger table would just be a second
// source of truth that could drift from the approvals it's meant to be
// counting; deriving avoids that class of bug entirely.
var schemaV3 = migration{
	version: 3,
	sql: []string{
		`CREATE TABLE policy_decisions (
			id TEXT PRIMARY KEY,
			incident_id TEXT NOT NULL,
			plan_id TEXT NOT NULL,
			plan_hash TEXT NOT NULL,
			decision TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			policy_version TEXT NOT NULL,
			reasons_json TEXT NOT NULL,
			mode TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY(plan_id) REFERENCES remediation_plans(id)
		)`,
		`CREATE INDEX ix_policy_decisions_plan ON policy_decisions(plan_id)`,
		`CREATE TABLE circuit_breakers (
			scope TEXT PRIMARY KEY,
			state TEXT NOT NULL,
			reason TEXT,
			tripped_at TEXT,
			reset_at TEXT,
			reset_actor TEXT
		)`,
		// Singleton row holding the operator-controlled autonomy mode
		// (disabled|shadow|enforced, design doc §9) — DB state, not a
		// static config file, because `autonomy enable/disable` must take
		// effect on the NEXT auto-execute invocation without an operator
		// hand-editing YAML. The CHECK(id=1) makes "exactly one row"
		// a schema-level guarantee, not just an application convention.
		`CREATE TABLE autonomy_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			mode TEXT NOT NULL,
			actor TEXT,
			reason TEXT,
			updated_at TEXT NOT NULL
		)`,
		`INSERT INTO autonomy_state (id, mode, actor, reason, updated_at)
			VALUES (1, 'disabled', NULL, 'initial state — fresh deployment', datetime('now'))`,
	},
}

// schemaV4 adds Agent Monitoring Phase 5's R2 canonical-apply reapply
// persistence — a SEPARATE table family from remediation_plans/
// approvals/remediation_runs (R1), not an extension of them: an R1
// approval can never authorize R2 (design doc §12), and giving R2 its
// own tables makes that boundary structural rather than a matter of
// application-logic discipline. There is deliberately no "policy actor"
// path anywhere in this table family — internal/policy's EvaluatePolicy
// already hard-denies any risk != R1 (design doc §13's guard), and this
// package adds no auto-approve entry point for reapply_approvals at
// all, so R2 staying human-only is enforced by the ABSENCE of a code
// path, not just a runtime check.
var schemaV4 = migration{
	version: 4,
	sql: []string{
		`CREATE TABLE reapply_plans (
			id TEXT PRIMARY KEY,
			incident_id TEXT NOT NULL,
			host TEXT NOT NULL,
			component TEXT NOT NULL,
			action TEXT NOT NULL,
			risk TEXT NOT NULL,
			playbook_path TEXT NOT NULL,
			playbook_hash TEXT NOT NULL,
			stage TEXT NOT NULL,
			resolved_input_keys_json TEXT NOT NULL,
			secret_reference_keys_json TEXT NOT NULL,
			dependency_snapshot_json TEXT NOT NULL,
			preview_ref TEXT NOT NULL,
			preview_supported INTEGER NOT NULL,
			preview_summary TEXT,
			preview_estimated_changed INTEGER NOT NULL,
			preview_unsupported_reason TEXT,
			verification_spec TEXT NOT NULL,
			inventory_revision TEXT NOT NULL,
			contract_hash TEXT NOT NULL,
			plan_hash TEXT NOT NULL,
			state TEXT NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			FOREIGN KEY(incident_id) REFERENCES incidents(id)
		)`,
		`CREATE TABLE reapply_approvals (
			id TEXT PRIMARY KEY,
			plan_id TEXT NOT NULL,
			plan_hash TEXT NOT NULL,
			decision TEXT NOT NULL,
			actor TEXT NOT NULL,
			reason TEXT,
			created_at TEXT NOT NULL,
			FOREIGN KEY(plan_id) REFERENCES reapply_plans(id)
		)`,
		`CREATE TABLE reapply_runs (
			id TEXT PRIMARY KEY,
			plan_id TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT,
			result TEXT NOT NULL,
			changed INTEGER NOT NULL DEFAULT -1,
			audit_ref TEXT,
			verify_ref TEXT,
			FOREIGN KEY(plan_id) REFERENCES reapply_plans(id)
		)`,
		// At most one run per plan, ever — same "replay of an already
		// executed approved plan must fail" structural guarantee R1's
		// remediation_runs already has.
		`CREATE UNIQUE INDEX ux_reapply_runs_plan ON reapply_runs(plan_id)`,
	},
}

var migrations = []migration{schemaV1, schemaV2, schemaV3, schemaV4}

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
