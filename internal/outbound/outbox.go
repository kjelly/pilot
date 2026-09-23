// outbox.go implements design spec §22-§24, §40: a durable SQLite-backed
// outbox and the cross-process claim lease that keeps one logical
// webhook's deliveries strictly FIFO across multiple Pilot processes.
//
// SQLite's own single-writer model does the heavy lifting here: a
// BEGIN IMMEDIATE transaction takes an exclusive write lock for the
// whole file for its duration, so two processes racing to claim the
// same row are already serialized by SQLite itself — there is no need
// for an additional optimistic-concurrency UPDATE...WHERE guard beyond
// matching on event_id, since only one BEGIN IMMEDIATE transaction can
// be reading-then-writing a row at a time process-wide.
package outbound

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OutboxRowState is a webhook_outbox row's lifecycle state (design spec
// §22.2).
type OutboxRowState string

const (
	OutboxPending             OutboxRowState = "pending"
	OutboxDelivering          OutboxRowState = "delivering"
	OutboxDelivered           OutboxRowState = "delivered"
	OutboxDeadLetter          OutboxRowState = "dead_letter"
	OutboxBlockedBaseMismatch OutboxRowState = "blocked_base_mismatch"
	OutboxOrphanedConfig      OutboxRowState = "orphaned_config"
	OutboxPausedConfig        OutboxRowState = "paused_config"
)

// EventDraft is one not-yet-sequenced webhook event. Finalize is called
// exactly once, inside the enqueue transaction, once this event's
// sequence is known (design spec §22.2: sequence allocation and the
// final deterministic JSON marshal/hash happen in the same BEGIN
// IMMEDIATE transaction as the insert — the snapshot/diff JSON
// themselves must already be built before EnqueueBatch is called).
// Finalize must be deterministic and must not perform I/O.
type EventDraft struct {
	WorkspaceKey       string
	SourceID           string
	WebhookName        string
	WorkflowID         string
	Operation          string
	Result             string
	Projection         string
	PayloadMode        string
	Authoritative      bool
	StateAvailable     bool
	SourceComplete     bool
	BaseSnapshotID     string
	TargetSnapshotID   string
	TargetSnapshotJSON string
	// Now is the injected creation timestamp (used for created_at and
	// the initial next_attempt_at) — never time.Now() internally, so
	// EnqueueBatch stays deterministic and testable like every other
	// clock-driven decision in this package.
	Now      time.Time
	Finalize func(eventID string, sequence int64) (bodyJSON []byte, err error)
}

// EnqueuedEvent is EnqueueBatch's per-draft result.
type EnqueuedEvent struct {
	EventID    string
	Sequence   int64
	BodySHA256 string
}

// ClaimedEvent is one outbox row claimed for delivery.
type ClaimedEvent struct {
	EventID            string
	WorkspaceKey       string
	SourceID           string
	WebhookName        string
	Sequence           int64
	WorkflowID         string
	Operation          string
	Result             string
	Projection         string
	PayloadMode        string
	Authoritative      bool
	StateAvailable     bool
	SourceComplete     bool
	BaseSnapshotID     string
	TargetSnapshotID   string
	TargetSnapshotJSON string
	BodyJSON           []byte
	BodySHA256         string
	AttemptCount       int
	ClaimOwner         string
	ClaimUntil         time.Time
}

// ClaimRequest scopes ClaimNextDue to one logical webhook.
type ClaimRequest struct {
	WorkspaceKey string
	SourceID     string
	WebhookName  string
	Now          time.Time
	Lease        time.Duration
	// Force ignores next_attempt_at (a pending row not yet due becomes
	// claimable) but never steals a live claim or skips a paused webhook
	// (design spec §34.3).
	Force bool
}

// DeliveryACK marks a claimed event delivered (2xx).
type DeliveryACK struct {
	EventID        string
	ClaimOwner     string
	Authoritative  bool
	StateAvailable bool
	SourceComplete bool
	Now            time.Time
}

// DeliveryFailure records one failed delivery attempt's outcome.
type DeliveryFailure struct {
	EventID        string
	ClaimOwner     string
	Now            time.Time
	Retryable      bool
	ErrorClass     string
	ErrorText      string
	NextAttemptAt  time.Time // ignored when !Retryable
	ConsumeAttempt bool      // false for missing_auth_secret (design spec §24.3)
	MaxAttempts    int       // dead-letter once AttemptCount (after this failure) >= MaxAttempts
}

// Outbox is the durable event store's transactional surface.
type Outbox interface {
	EnqueueBatch(ctx context.Context, drafts []EventDraft) ([]EnqueuedEvent, error)
	ClaimNextDue(ctx context.Context, req ClaimRequest) (*ClaimedEvent, error)
	MarkDelivered(ctx context.Context, ack DeliveryACK) error
	// MarkAttemptFailed returns the row's resulting state
	// (OutboxPending if it will retry, OutboxDeadLetter if not) so
	// callers can report the real outcome rather than re-deriving it.
	MarkAttemptFailed(ctx context.Context, fail DeliveryFailure) (OutboxRowState, error)
}

// SQLiteOutbox is Outbox backed by internal/store's webhook_outbox
// table. It opens its own *sql.DB (see OpenOutboxDB) with
// _txlock=immediate so every BeginTx below actually takes SQLite's
// write lock at BEGIN time rather than deferring it to the first write
// — the property the cross-process claim lease depends on.
type SQLiteOutbox struct {
	db *sql.DB
}

// NewSQLiteOutbox wraps an already-open *sql.DB (see OpenOutboxDB).
func NewSQLiteOutbox(db *sql.DB) *SQLiteOutbox {
	return &SQLiteOutbox{db: db}
}

// OpenOutboxDB opens a dedicated connection to the workspace's
// history.db for outbox transactions, with _txlock=immediate (see this
// file's package doc) and a bounded busy_timeout (design spec §40).
// Callers MUST call store.Open(path) first (and Close it) so the
// webhook_* schema exists — this function does not run migrations
// itself.
func OpenOutboxDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("open outbox db: %w", err)
	}
	return db, nil
}

func (o *SQLiteOutbox) EnqueueBatch(ctx context.Context, drafts []EventDraft) ([]EnqueuedEvent, error) {
	if len(drafts) == 0 {
		return nil, nil
	}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("outbox: begin enqueue tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	results := make([]EnqueuedEvent, 0, len(drafts))
	for _, d := range drafts {
		// Idempotency (design spec §31): the exact same
		// (workspace_key, source_id, webhook_name, workflow_id) MUST NOT
		// insert a second row. If the resulting body hashes identically
		// to what's already stored, this is a safe retry of the same
		// enqueue call — return the existing event, don't touch it. If
		// it hashes differently, something is trying to rewrite an
		// immutable event — fail closed rather than silently overwrite.
		var existingEventID, existingSHA256 string
		var existingSeq int64
		err := tx.QueryRowContext(ctx,
			`SELECT event_id, sequence, body_sha256 FROM webhook_outbox WHERE workspace_key=? AND source_id=? AND webhook_name=? AND workflow_id=?`,
			d.WorkspaceKey, d.SourceID, d.WebhookName, d.WorkflowID).Scan(&existingEventID, &existingSeq, &existingSHA256)
		if err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("outbox: check existing workflow event: %w", err)
		}
		if err == nil {
			body, ferr := d.Finalize(existingEventID, existingSeq)
			if ferr != nil {
				return nil, fmt.Errorf("outbox: finalize event body: %w", ferr)
			}
			sum := sha256Hex(body)
			if sum != existingSHA256 {
				return nil, fmt.Errorf("outbox: conflict for workflow %s webhook %s: existing event %s has a different body hash — refusing to overwrite an immutable event",
					d.WorkflowID, d.WebhookName, existingEventID)
			}
			results = append(results, EnqueuedEvent{EventID: existingEventID, Sequence: existingSeq, BodySHA256: sum})
			continue
		}

		var maxSeq sql.NullInt64
		err = tx.QueryRowContext(ctx,
			`SELECT MAX(sequence) FROM webhook_outbox WHERE workspace_key=? AND source_id=? AND webhook_name=?`,
			d.WorkspaceKey, d.SourceID, d.WebhookName).Scan(&maxSeq)
		if err != nil {
			return nil, fmt.Errorf("outbox: allocate sequence: %w", err)
		}
		sequence := int64(1)
		if maxSeq.Valid {
			sequence = maxSeq.Int64 + 1
		}

		eventID := uuid.NewString()
		body, err := d.Finalize(eventID, sequence)
		if err != nil {
			return nil, fmt.Errorf("outbox: finalize event body: %w", err)
		}
		sum := sha256Hex(body)

		now := d.Now.UTC().Format(time.RFC3339Nano)
		_, err = tx.ExecContext(ctx, `INSERT INTO webhook_outbox (
			event_id, workspace_key, source_id, webhook_name, sequence,
			workflow_id, operation, result, projection, payload_mode,
			authoritative, state_available, source_complete,
			base_snapshot_id, target_snapshot_id,
			body_json, body_sha256, target_snapshot_json,
			state, attempt_count, next_attempt_at,
			created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?)`,
			eventID, d.WorkspaceKey, d.SourceID, d.WebhookName, sequence,
			d.WorkflowID, d.Operation, d.Result, d.Projection, d.PayloadMode,
			boolToInt(d.Authoritative), boolToInt(d.StateAvailable), boolToInt(d.SourceComplete),
			d.BaseSnapshotID, d.TargetSnapshotID,
			string(body), sum, d.TargetSnapshotJSON,
			now, now,
		)
		if err != nil {
			return nil, fmt.Errorf("outbox: insert event %s: %w", eventID, err)
		}
		results = append(results, EnqueuedEvent{EventID: eventID, Sequence: sequence, BodySHA256: sum})
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("outbox: commit enqueue tx: %w", err)
	}
	return results, nil
}

func (o *SQLiteOutbox) ClaimNextDue(ctx context.Context, req ClaimRequest) (*ClaimedEvent, error) {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("outbox: begin claim tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, `SELECT
		event_id, sequence, workflow_id, operation, result, projection, payload_mode,
		authoritative, state_available, source_complete, base_snapshot_id, target_snapshot_id,
		body_json, body_sha256, target_snapshot_json, state, attempt_count, next_attempt_at, claim_until
		FROM webhook_outbox
		WHERE workspace_key=? AND source_id=? AND webhook_name=?
		AND state NOT IN ('delivered','dead_letter','blocked_base_mismatch','orphaned_config')
		ORDER BY sequence ASC LIMIT 1`,
		req.WorkspaceKey, req.SourceID, req.WebhookName)

	var (
		eventID, workflowID, operation, result, projection, payloadMode string
		sequence                                                        int64
		authoritative, stateAvailable, sourceComplete                   int
		baseSnapshotID, targetSnapshotID, bodyJSON, bodySHA256          string
		targetSnapshotJSON, state                                       string
		attemptCount                                                    int
		nextAttemptAt, claimUntil                                       sql.NullString
	)
	err = row.Scan(&eventID, &sequence, &workflowID, &operation, &result, &projection, &payloadMode,
		&authoritative, &stateAvailable, &sourceComplete, &baseSnapshotID, &targetSnapshotID,
		&bodyJSON, &bodySHA256, &targetSnapshotJSON, &state, &attemptCount, &nextAttemptAt, &claimUntil)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("outbox: scan claim candidate: %w", err)
	}

	claimable, err := isClaimable(OutboxRowState(state), nextAttemptAt, claimUntil, req.Now, req.Force)
	if err != nil {
		return nil, err
	}
	if !claimable {
		return nil, nil
	}

	// Dead-letter base-mismatch safety (design spec §14.8): a diff-only
	// event whose base no longer matches the current cursor can never
	// be safely applied by a consumer (its predecessor never ACKed, so
	// the consumer's local state isn't where this diff assumes it is).
	// `both` events are exempt — their self-contained snapshot lets a
	// consumer recover via atomic replace regardless of the diff's base.
	if payloadMode == string(PayloadDiff) {
		var cursorSnapshotID sql.NullString
		cerr := tx.QueryRowContext(ctx, `SELECT snapshot_id FROM webhook_state_cursor WHERE workspace_key=? AND source_id=? AND webhook_name=? AND projection=?`,
			req.WorkspaceKey, req.SourceID, req.WebhookName, projection).Scan(&cursorSnapshotID)
		if cerr != nil && cerr != sql.ErrNoRows {
			return nil, fmt.Errorf("outbox: read cursor for base-mismatch check: %w", cerr)
		}
		cursorID := ""
		if cursorSnapshotID.Valid {
			cursorID = cursorSnapshotID.String
		}
		if baseSnapshotID != cursorID {
			if _, err := tx.ExecContext(ctx, `UPDATE webhook_outbox SET
				state='blocked_base_mismatch', claim_owner='', claim_until=NULL, next_attempt_at=NULL,
				body_json='', target_snapshot_json=''
				WHERE event_id=?`, eventID); err != nil {
				return nil, fmt.Errorf("outbox: mark blocked_base_mismatch %s: %w", eventID, err)
			}
			if err := tx.Commit(); err != nil {
				return nil, fmt.Errorf("outbox: commit blocked_base_mismatch tx: %w", err)
			}
			return nil, nil
		}
	}

	claimOwner := uuid.NewString()
	claimUntilNew := req.Now.Add(req.Lease).UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx,
		`UPDATE webhook_outbox SET state='delivering', claim_owner=?, claim_until=? WHERE event_id=?`,
		claimOwner, claimUntilNew, eventID)
	if err != nil {
		return nil, fmt.Errorf("outbox: claim event %s: %w", eventID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, fmt.Errorf("outbox: claim event %s affected %d rows, want 1", eventID, n)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("outbox: commit claim tx: %w", err)
	}

	claimUntilParsed, _ := time.Parse(time.RFC3339Nano, claimUntilNew)
	return &ClaimedEvent{
		EventID:            eventID,
		WorkspaceKey:       req.WorkspaceKey,
		SourceID:           req.SourceID,
		WebhookName:        req.WebhookName,
		Sequence:           sequence,
		WorkflowID:         workflowID,
		Operation:          operation,
		Result:             result,
		Projection:         projection,
		PayloadMode:        payloadMode,
		Authoritative:      authoritative != 0,
		StateAvailable:     stateAvailable != 0,
		SourceComplete:     sourceComplete != 0,
		BaseSnapshotID:     baseSnapshotID,
		TargetSnapshotID:   targetSnapshotID,
		TargetSnapshotJSON: targetSnapshotJSON,
		BodyJSON:           []byte(bodyJSON),
		BodySHA256:         bodySHA256,
		AttemptCount:       attemptCount,
		ClaimOwner:         claimOwner,
		ClaimUntil:         claimUntilParsed,
	}, nil
}

// isClaimable implements design spec §23.1's FIFO blocking rule for the
// single head-of-line row ClaimNextDue reads. A caller must never look
// past this row even if it isn't claimable — that IS the FIFO guarantee.
func isClaimable(state OutboxRowState, nextAttemptAt, claimUntil sql.NullString, now time.Time, force bool) (bool, error) {
	switch state {
	case OutboxPending:
		if force || !nextAttemptAt.Valid || nextAttemptAt.String == "" {
			return true, nil
		}
		due, err := time.Parse(time.RFC3339Nano, nextAttemptAt.String)
		if err != nil {
			return false, fmt.Errorf("outbox: parse next_attempt_at %q: %w", nextAttemptAt.String, err)
		}
		return !now.Before(due), nil
	case OutboxDelivering:
		if !claimUntil.Valid || claimUntil.String == "" {
			return true, nil
		}
		until, err := time.Parse(time.RFC3339Nano, claimUntil.String)
		if err != nil {
			return false, fmt.Errorf("outbox: parse claim_until %q: %w", claimUntil.String, err)
		}
		return !now.Before(until), nil
	case OutboxPausedConfig:
		return false, nil
	default:
		return false, nil
	}
}

func (o *SQLiteOutbox) MarkDelivered(ctx context.Context, ack DeliveryACK) error {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("outbox: begin mark-delivered tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	advanceCursor := ack.Authoritative && ack.StateAvailable && ack.SourceComplete

	var targetSnapshotID, targetSnapshotJSON, projection, workspaceKey, sourceID, webhookName string
	err = tx.QueryRowContext(ctx, `SELECT target_snapshot_id, target_snapshot_json, projection, workspace_key, source_id, webhook_name
		FROM webhook_outbox WHERE event_id=? AND claim_owner=?`, ack.EventID, ack.ClaimOwner).
		Scan(&targetSnapshotID, &targetSnapshotJSON, &projection, &workspaceKey, &sourceID, &webhookName)
	if err == sql.ErrNoRows {
		return fmt.Errorf("outbox: mark-delivered %s: stale claim owner %s (no matching live claim)", ack.EventID, ack.ClaimOwner)
	}
	if err != nil {
		return fmt.Errorf("outbox: mark-delivered lookup: %w", err)
	}

	nowStr := ack.Now.UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `UPDATE webhook_outbox SET
		state='delivered', delivered_at=?, claim_owner='', claim_until=NULL, next_attempt_at=NULL,
		body_json='', target_snapshot_json=''
		WHERE event_id=? AND claim_owner=?`, nowStr, ack.EventID, ack.ClaimOwner)
	if err != nil {
		return fmt.Errorf("outbox: mark-delivered update: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("outbox: mark-delivered %s: stale claim owner %s", ack.EventID, ack.ClaimOwner)
	}

	if advanceCursor {
		_, err = tx.ExecContext(ctx, `INSERT INTO webhook_state_cursor
			(workspace_key, source_id, webhook_name, projection, snapshot_id, snapshot_json, last_event_id, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(workspace_key, source_id, webhook_name, projection) DO UPDATE SET
				snapshot_id=excluded.snapshot_id, snapshot_json=excluded.snapshot_json,
				last_event_id=excluded.last_event_id, updated_at=excluded.updated_at`,
			workspaceKey, sourceID, webhookName, projection, targetSnapshotID, targetSnapshotJSON, ack.EventID, nowStr)
		if err != nil {
			return fmt.Errorf("outbox: advance cursor: %w", err)
		}
	}

	return tx.Commit()
}

func (o *SQLiteOutbox) MarkAttemptFailed(ctx context.Context, fail DeliveryFailure) (OutboxRowState, error) {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("outbox: begin mark-failed tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var attemptCount int
	err = tx.QueryRowContext(ctx, `SELECT attempt_count FROM webhook_outbox WHERE event_id=? AND claim_owner=?`,
		fail.EventID, fail.ClaimOwner).Scan(&attemptCount)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("outbox: mark-failed %s: stale claim owner %s", fail.EventID, fail.ClaimOwner)
	}
	if err != nil {
		return "", fmt.Errorf("outbox: mark-failed lookup: %w", err)
	}

	newAttemptCount := attemptCount
	if fail.ConsumeAttempt {
		newAttemptCount++
	}

	finalState := OutboxPending
	var res sql.Result
	if !fail.Retryable || (fail.ConsumeAttempt && newAttemptCount >= fail.MaxAttempts) {
		finalState = OutboxDeadLetter
		// Terminal payload compaction (design spec §22.3): dead_letter is
		// a terminal state, so body_json/target_snapshot_json are
		// cleared here too, not just on delivered — body_sha256 and
		// every other column remain for audit.
		res, err = tx.ExecContext(ctx, `UPDATE webhook_outbox SET
			state='dead_letter', attempt_count=?, claim_owner='', claim_until=NULL, next_attempt_at=NULL,
			last_error_class=?, last_error_text=?, body_json='', target_snapshot_json=''
			WHERE event_id=? AND claim_owner=?`,
			newAttemptCount, fail.ErrorClass, boundedErrorText(fail.ErrorText), fail.EventID, fail.ClaimOwner)
	} else {
		res, err = tx.ExecContext(ctx, `UPDATE webhook_outbox SET
			state='pending', attempt_count=?, claim_owner='', claim_until=NULL,
			next_attempt_at=?, last_error_class=?, last_error_text=?
			WHERE event_id=? AND claim_owner=?`,
			newAttemptCount, fail.NextAttemptAt.UTC().Format(time.RFC3339Nano),
			fail.ErrorClass, boundedErrorText(fail.ErrorText), fail.EventID, fail.ClaimOwner)
	}
	if err != nil {
		return "", fmt.Errorf("outbox: mark-failed update: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", fmt.Errorf("outbox: mark-failed %s: stale claim owner %s", fail.EventID, fail.ClaimOwner)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("outbox: commit mark-failed tx: %w", err)
	}
	return finalState, nil
}

// boundedErrorText enforces design spec §22.2's 512-byte bound on
// last_error_text.
func boundedErrorText(s string) string {
	const max = 512
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// sha256Hex returns the lowercase hex SHA-256 of body — design spec
// §22.2's body_sha256, with no "sha256:" prefix (unlike SnapshotID).
func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CheckWorkspaceBinding enforces design spec §7.4.1: a source_id may be
// bound to at most one workspace at a time. It upserts
// workspace_key -> current_source_id (a workspace MAY move to a new
// source_id — that's an intentional rebind, reconciled by
// ReconcileWebhookConfig's orphan step) but fails closed if sourceID is
// already bound to a DIFFERENT workspace_key, which would otherwise mix
// two unrelated publication lineages' sequence/cursor identity.
func (o *SQLiteOutbox) CheckWorkspaceBinding(ctx context.Context, workspaceKey, sourceID string, now time.Time) error {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("outbox: begin workspace-binding tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var boundWorkspace string
	err = tx.QueryRowContext(ctx, `SELECT workspace_key FROM webhook_workspace_binding WHERE current_source_id=?`, sourceID).Scan(&boundWorkspace)
	switch {
	case err == nil && boundWorkspace != workspaceKey:
		return fmt.Errorf("outbox: source_id %q is already bound to a different workspace (workspace_key=%s, this workspace=%s) — use a new source_id, or flush/clean the original workspace first",
			sourceID, boundWorkspace, workspaceKey)
	case err != nil && err != sql.ErrNoRows:
		return fmt.Errorf("outbox: check workspace binding: %w", err)
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO webhook_workspace_binding (workspace_key, current_source_id, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(workspace_key) DO UPDATE SET current_source_id=excluded.current_source_id, updated_at=excluded.updated_at`,
		workspaceKey, sourceID, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("outbox: bind workspace: %w", err)
	}
	return tx.Commit()
}

// ReconcileWebhookConfig applies design spec §7.4.1's config-state
// reconciliation, exactly once per config load, before any
// operation/flush begins: a non-terminal row whose (source_id,
// webhook_name) no longer matches any entry in cfg becomes
// orphaned_config (terminal payload compaction applied, and its cursor
// snapshot deleted — it can never become an authoritative chain
// predecessor again); a row for a currently-configured but disabled
// webhook becomes paused_config; a paused_config row whose webhook is
// now enabled reverts to pending, preserving attempt_count/
// next_attempt_at untouched (so it is immediately due if that deadline
// already passed while paused). Terminal rows already in
// delivered/dead_letter/blocked_base_mismatch/orphaned_config are never
// touched.
func (o *SQLiteOutbox) ReconcileWebhookConfig(ctx context.Context, workspaceKey string, cfg *Config) error {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("outbox: begin reconcile tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	enabledByName := make(map[string]bool, len(cfg.Webhooks))
	for _, w := range cfg.Webhooks {
		enabledByName[w.Name] = w.Enabled
	}

	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT source_id, webhook_name FROM webhook_outbox
		WHERE workspace_key=? AND state NOT IN ('delivered','dead_letter','blocked_base_mismatch','orphaned_config')`, workspaceKey)
	if err != nil {
		return fmt.Errorf("outbox: reconcile: list identities: %w", err)
	}
	type identity struct{ sourceID, webhookName string }
	var toOrphan []identity
	for rows.Next() {
		var id identity
		if err := rows.Scan(&id.sourceID, &id.webhookName); err != nil {
			_ = rows.Close()
			return fmt.Errorf("outbox: reconcile: scan identity: %w", err)
		}
		if id.sourceID != cfg.SourceID {
			toOrphan = append(toOrphan, id)
			continue
		}
		if _, known := enabledByName[id.webhookName]; !known {
			toOrphan = append(toOrphan, id)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("outbox: reconcile: iterate identities: %w", err)
	}
	_ = rows.Close()

	for _, id := range toOrphan {
		if _, err := tx.ExecContext(ctx, `UPDATE webhook_outbox SET
			state='orphaned_config', claim_owner='', claim_until=NULL, next_attempt_at=NULL,
			body_json='', target_snapshot_json=''
			WHERE workspace_key=? AND source_id=? AND webhook_name=?
			AND state NOT IN ('delivered','dead_letter','blocked_base_mismatch','orphaned_config')`,
			workspaceKey, id.sourceID, id.webhookName); err != nil {
			return fmt.Errorf("outbox: reconcile: orphan %s/%s: %w", id.sourceID, id.webhookName, err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM webhook_state_cursor WHERE workspace_key=? AND source_id=? AND webhook_name=?`,
			workspaceKey, id.sourceID, id.webhookName); err != nil {
			return fmt.Errorf("outbox: reconcile: delete cursor for %s/%s: %w", id.sourceID, id.webhookName, err)
		}
	}

	for name, enabled := range enabledByName {
		if enabled {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE webhook_outbox SET state='paused_config', claim_owner='', claim_until=NULL
			WHERE workspace_key=? AND source_id=? AND webhook_name=?
			AND state NOT IN ('delivered','dead_letter','blocked_base_mismatch','orphaned_config','paused_config')`,
			workspaceKey, cfg.SourceID, name); err != nil {
			return fmt.Errorf("outbox: reconcile: pause %s: %w", name, err)
		}
	}
	for name, enabled := range enabledByName {
		if !enabled {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE webhook_outbox SET state='pending'
			WHERE workspace_key=? AND source_id=? AND webhook_name=? AND state='paused_config'`,
			workspaceKey, cfg.SourceID, name); err != nil {
			return fmt.Errorf("outbox: reconcile: resume %s: %w", name, err)
		}
	}

	return tx.Commit()
}

// StatusCounts is `pilot webhook status`'s per-webhook aggregate
// (design spec §34.2) — never includes body/cursor JSON.
type StatusCounts struct {
	Pending     int
	Delivering  int
	Paused      int
	Dead        int
	Blocked     int
	Orphaned    int
	LastAckedID string
}

// StatusCounts aggregates one logical webhook's outbox row states plus
// its last-acked cursor snapshot ID (design spec §34.2). It never
// returns body_json/cursor JSON — only counts and the snapshot ID.
func (o *SQLiteOutbox) StatusCounts(ctx context.Context, workspaceKey, sourceID, webhookName string) (StatusCounts, error) {
	var c StatusCounts
	rows, err := o.db.QueryContext(ctx, `SELECT state, COUNT(*) FROM webhook_outbox
		WHERE workspace_key=? AND source_id=? AND webhook_name=? GROUP BY state`,
		workspaceKey, sourceID, webhookName)
	if err != nil {
		return c, fmt.Errorf("outbox: status counts: %w", err)
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var state string
		var n int
		if err := rows.Scan(&state, &n); err != nil {
			return c, fmt.Errorf("outbox: scan status counts: %w", err)
		}
		switch OutboxRowState(state) {
		case OutboxPending:
			c.Pending = n
		case OutboxDelivering:
			c.Delivering = n
		case OutboxPausedConfig:
			c.Paused = n
		case OutboxDeadLetter:
			c.Dead = n
		case OutboxBlockedBaseMismatch:
			c.Blocked = n
		case OutboxOrphanedConfig:
			c.Orphaned = n
		}
	}
	if err := rows.Err(); err != nil {
		return c, fmt.Errorf("outbox: iterate status counts: %w", err)
	}

	var snapshotID string
	err = o.db.QueryRowContext(ctx, `SELECT snapshot_id FROM webhook_state_cursor WHERE workspace_key=? AND source_id=? AND webhook_name=?`,
		workspaceKey, sourceID, webhookName).Scan(&snapshotID)
	if err != nil && err != sql.ErrNoRows {
		return c, fmt.Errorf("outbox: read cursor for status: %w", err)
	}
	c.LastAckedID = snapshotID
	return c, nil
}

// EffectiveBase implements design spec §14.7 for a caller that is about
// to enqueue a new event for (workspaceKey, sourceID, webhookName,
// projection): the base a new diff should chain from is this webhook's
// last not-yet-ACKed authoritative target snapshot if one is still
// pending, else the current cursor snapshot, else bootstrap.
func (o *SQLiteOutbox) EffectiveBase(ctx context.Context, workspaceKey, sourceID, webhookName, projection string) (base SnapshotRef, bootstrap bool, err error) {
	var pendingID, pendingJSON string
	perr := o.db.QueryRowContext(ctx, `SELECT target_snapshot_id, target_snapshot_json FROM webhook_outbox
		WHERE workspace_key=? AND source_id=? AND webhook_name=? AND projection=? AND authoritative=1
		AND state NOT IN ('delivered','dead_letter','blocked_base_mismatch','orphaned_config')
		ORDER BY sequence DESC LIMIT 1`,
		workspaceKey, sourceID, webhookName, projection).Scan(&pendingID, &pendingJSON)
	if perr != nil && perr != sql.ErrNoRows {
		return SnapshotRef{}, false, fmt.Errorf("outbox: read pending authoritative target: %w", perr)
	}
	var pendingRef *SnapshotRef
	if perr == nil {
		pendingRef = &SnapshotRef{ID: pendingID, JSON: json.RawMessage(pendingJSON)}
	}

	var cursorID, cursorJSON string
	cerr := o.db.QueryRowContext(ctx, `SELECT snapshot_id, snapshot_json FROM webhook_state_cursor
		WHERE workspace_key=? AND source_id=? AND webhook_name=? AND projection=?`,
		workspaceKey, sourceID, webhookName, projection).Scan(&cursorID, &cursorJSON)
	if cerr != nil && cerr != sql.ErrNoRows {
		return SnapshotRef{}, false, fmt.Errorf("outbox: read cursor: %w", cerr)
	}
	var cursorRef *SnapshotRef
	if cerr == nil {
		cursorRef = &SnapshotRef{ID: cursorID, JSON: json.RawMessage(cursorJSON)}
	}

	base, bootstrap = ResolveEffectiveBase(pendingRef, cursorRef)
	return base, bootstrap, nil
}
