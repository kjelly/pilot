package store

import (
	"database/sql"
	"path/filepath"
	"sort"
	"testing"

	_ "modernc.org/sqlite"
)

// v15BaseSchema is the real internal/store schema at SchemaVersion 15
// (design spec docs/tmp/now/spec.md §22.2: "測試必須從真實 v15 fixture
// upgrade、close、reopen"), copied verbatim from this file's own history
// (commit 892db3d, the last commit before the webhook_outbox/
// webhook_state_cursor/webhook_workspace_binding migration landed) —
// not a synthetic simplified schema.
const v15BaseSchema = `
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

CREATE TABLE IF NOT EXISTS evidence_admin_events (
    event_id     TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_admin_events_type ON evidence_admin_events(type, created_at);
CREATE TABLE IF NOT EXISTS evidence_admin_mode (enabled INTEGER NOT NULL);

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
BEFORE DELETE ON delivery_events
WHEN NOT EXISTS (SELECT 1 FROM evidence_admin_mode WHERE enabled=1)
BEGIN SELECT RAISE(ABORT, 'delivery_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS verify_evidence_no_update
BEFORE UPDATE ON verify_evidence BEGIN SELECT RAISE(ABORT, 'verify_evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS verify_evidence_no_delete
BEFORE DELETE ON verify_evidence
WHEN NOT EXISTS (SELECT 1 FROM evidence_admin_mode WHERE enabled=1)
BEGIN SELECT RAISE(ABORT, 'verify_evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_admin_events_no_update
BEFORE UPDATE ON evidence_admin_events BEGIN SELECT RAISE(ABORT, 'evidence_admin_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_admin_events_no_delete
BEFORE DELETE ON evidence_admin_events BEGIN SELECT RAISE(ABORT, 'evidence_admin_events is append-only'); END;

CREATE TABLE IF NOT EXISTS host_decommission_plans (
    id                  TEXT PRIMARY KEY,
    host                TEXT NOT NULL,
    fqdn                TEXT NOT NULL DEFAULT '',
    environment         TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL,
    plan_hash           TEXT NOT NULL,
    inventory_revision  TEXT NOT NULL,
    plan_json           TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    completed_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_host_decommission_plans_host ON host_decommission_plans(host);

CREATE TABLE IF NOT EXISTS host_decommission_steps (
    id              TEXT PRIMARY KEY,
    plan_id         TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    component       TEXT NOT NULL DEFAULT '',
    provider        TEXT NOT NULL DEFAULT '',
    phase           TEXT NOT NULL DEFAULT '',
    action          TEXT NOT NULL DEFAULT '',
    target_identity TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    started_at      TEXT,
    finished_at     TEXT,
    error_class     TEXT,
    error_text      TEXT,
    result_json     TEXT,
    UNIQUE(plan_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_host_decommission_steps_plan ON host_decommission_steps(plan_id);

CREATE TABLE IF NOT EXISTS host_decommission_approvals (
    id         TEXT PRIMARY KEY,
    plan_id    TEXT NOT NULL,
    plan_hash  TEXT NOT NULL,
    actor      TEXT NOT NULL,
    decision   TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_host_decommission_approvals_plan ON host_decommission_approvals(plan_id, plan_hash);

CREATE TABLE IF NOT EXISTS retired_hosts (
    host                     TEXT PRIMARY KEY,
    fqdn                     TEXT NOT NULL DEFAULT '',
    decommission_id          TEXT NOT NULL,
    reason                   TEXT NOT NULL DEFAULT '',
    retired_at               TEXT NOT NULL,
    final_inventory_revision TEXT NOT NULL DEFAULT ''
);
`

func webhookOutboxObjectNames(t *testing.T, dbPath string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE name LIKE 'webhook_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	return names
}

// TestWebhookOutboxSchemaMigration (design spec §22.2, C20): a real v15
// DB migrates additively to v16, ending up with exactly the same
// webhook_* schema objects a fresh install gets directly, and a pending
// outbox row survives a close+reopen (durability across process
// restart, INV-2's "durable from enqueue transaction success").
func TestWebhookOutboxSchemaMigration(t *testing.T) {
	tmp := t.TempDir()

	legacyPath := filepath.Join(tmp, "legacy.db")
	legacyDB, err := sql.Open("sqlite", legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.Exec(v15BaseSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.Exec(`PRAGMA user_version = 15;`); err != nil {
		t.Fatal(err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(legacyPath)
	if err != nil {
		t.Fatalf("Open (migrate v15->v16): %v", err)
	}
	insertTestOutboxRow(t, s, "evt-1")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	gotVersion, err := readUserVersion(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if gotVersion != SchemaVersion {
		t.Fatalf("user_version after migration = %d, want %d", gotVersion, SchemaVersion)
	}

	freshPath := filepath.Join(tmp, "fresh.db")
	freshStore, err := Open(freshPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = freshStore.Close() }()

	legacyObjects := webhookOutboxObjectNames(t, legacyPath)
	freshObjects := webhookOutboxObjectNames(t, freshPath)
	sort.Strings(legacyObjects)
	sort.Strings(freshObjects)
	if len(legacyObjects) == 0 {
		t.Fatal("migrated DB has no webhook_* schema objects")
	}
	for _, want := range []string{"webhook_outbox", "webhook_state_cursor", "webhook_workspace_binding"} {
		found := false
		for _, got := range legacyObjects {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("migrated DB missing expected table %q (got %v)", want, legacyObjects)
		}
	}
	if len(legacyObjects) != len(freshObjects) {
		t.Fatalf("migrated DB webhook_* objects = %v, fresh DB has %v — base schema and migrateSteps have diverged", legacyObjects, freshObjects)
	}
	for i := range legacyObjects {
		if legacyObjects[i] != freshObjects[i] {
			t.Fatalf("migrated DB webhook_* objects = %v, want exactly %v (fresh install's own set)", legacyObjects, freshObjects)
		}
	}

	// Restart persistence: reopen the migrated DB and confirm the pending
	// row inserted before Close is still there.
	reopened, err := Open(legacyPath)
	if err != nil {
		t.Fatalf("reopen migrated DB: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	var count int
	if err := reopened.db.QueryRow(`SELECT COUNT(*) FROM webhook_outbox WHERE event_id = ?`, "evt-1").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("pending outbox row did not survive close+reopen: count=%d", count)
	}
}

// insertTestOutboxRow inserts one minimal, schema-valid webhook_outbox
// row directly (this test predates internal/outbound's own Outbox
// implementation — Phase 3 adds real Enqueue/Claim tests there against
// this same table).
func insertTestOutboxRow(t *testing.T, s *Store, eventID string) {
	t.Helper()
	_, err := s.db.Exec(`INSERT INTO webhook_outbox (
		event_id, workspace_key, source_id, webhook_name, sequence,
		workflow_id, operation, result, projection, payload_mode,
		authoritative, state_available, source_complete,
		body_json, body_sha256, state, created_at
	) VALUES (?, 'ws1', 'src1', 'hook1', 1, 'wf1', 'deploy', 'success', 'user_host_access_v1', 'snapshot',
		1, 1, 1, '{}', 'deadbeef', 'pending', '2026-01-01T00:00:00Z')`, eventID)
	if err != nil {
		t.Fatal(err)
	}
}
