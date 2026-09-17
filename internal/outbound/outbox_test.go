package outbound

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/store"
)

// newTestOutboxDB opens a fresh history.db (schema ensured via
// store.Open, then a dedicated _txlock=immediate connection via
// OpenOutboxDB — see outbox.go's package doc) at dbPath.
func newTestOutboxDB(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := OpenOutboxDB(dbPath)
	if err != nil {
		t.Fatalf("OpenOutboxDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newTestOutbox(t *testing.T) *SQLiteOutbox {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "history.db")
	return NewSQLiteOutbox(newTestOutboxDB(t, dbPath))
}

func testDraft(workflowID, workspaceKey, sourceID, webhookName string) EventDraft {
	return testDraftWithResult(workflowID, workspaceKey, sourceID, webhookName, "success")
}

func testDraftWithResult(workflowID, workspaceKey, sourceID, webhookName, result string) EventDraft {
	return EventDraft{
		WorkspaceKey: workspaceKey, SourceID: sourceID, WebhookName: webhookName, WorkflowID: workflowID,
		Operation: "deploy", Result: result, Projection: ProjectionUserHostAccessV1, PayloadMode: "snapshot",
		Authoritative: true, StateAvailable: true, SourceComplete: true,
		TargetSnapshotID: "sha256:abc",
		Now:              time.Now(),
		Finalize: func(eventID string, sequence int64) ([]byte, error) {
			return []byte(fmt.Sprintf(`{"event_id":%q,"sequence":%d,"workflow_id":%q,"result":%q}`, eventID, sequence, workflowID, result)), nil
		},
	}
}

func mustEnqueue(t *testing.T, o *SQLiteOutbox, draft EventDraft) EnqueuedEvent {
	t.Helper()
	enq, err := o.EnqueueBatch(context.Background(), []EventDraft{draft})
	if err != nil {
		t.Fatalf("EnqueueBatch: %v", err)
	}
	if len(enq) != 1 {
		t.Fatalf("EnqueueBatch returned %d events, want 1", len(enq))
	}
	return enq[0]
}

// TestOutboundDispatcher_H9: sequences are claimed in strict ascending
// order.
func TestOutboundDispatcher_H9(t *testing.T) {
	o := newTestOutbox(t)
	ctx := context.Background()
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "hook"))
	mustEnqueue(t, o, testDraft("wf2", "ws", "src", "hook"))
	mustEnqueue(t, o, testDraft("wf3", "ws", "src", "hook"))

	now := time.Now()
	for i, want := range []int64{1, 2, 3} {
		claimed, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: now, Lease: time.Minute})
		if err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
		if claimed == nil || claimed.Sequence != want {
			t.Fatalf("claim %d: sequence = %+v, want %d", i, claimed, want)
		}
		if err := o.MarkDelivered(ctx, DeliveryACK{EventID: claimed.EventID, ClaimOwner: claimed.ClaimOwner, Authoritative: true, StateAvailable: true, SourceComplete: true, Now: now}); err != nil {
			t.Fatalf("mark delivered %d: %v", i, err)
		}
	}
}

// TestOutboundDispatcher_H13: two independent connections to the same
// DB file cannot both claim the same sequence — SQLite's own
// single-writer serialization (via _txlock=immediate) is the mutex.
func TestOutboundDispatcher_H13(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "history.db")
	db1 := newTestOutboxDB(t, dbPath)
	o1 := NewSQLiteOutbox(db1)
	db2, err := OpenOutboxDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	o2 := NewSQLiteOutbox(db2)

	mustEnqueue(t, o1, testDraft("wf1", "ws", "src", "hook"))

	now := time.Now()
	var wg sync.WaitGroup
	results := make([]*ClaimedEvent, 2)
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		results[0], errs[0] = o1.ClaimNextDue(context.Background(), ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: now, Lease: time.Minute})
	}()
	go func() {
		defer wg.Done()
		results[1], errs[1] = o2.ClaimNextDue(context.Background(), ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: now, Lease: time.Minute})
	}()
	wg.Wait()

	claimedCount := 0
	for i, r := range results {
		if errs[i] != nil {
			t.Fatalf("claim %d error: %v", i, errs[i])
		}
		if r != nil {
			claimedCount++
		}
	}
	if claimedCount != 1 {
		t.Fatalf("expected exactly one process to claim the single row, got %d", claimedCount)
	}
}

// TestOutboundDispatcher_H14: an expired lease can be reclaimed; the
// stale claim owner can no longer mark it delivered.
func TestOutboundDispatcher_H14(t *testing.T) {
	o := newTestOutbox(t)
	ctx := context.Background()
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "hook"))

	now := time.Now()
	first, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: now, Lease: time.Second})
	if err != nil || first == nil {
		t.Fatalf("first claim: %v %v", first, err)
	}

	later := now.Add(2 * time.Second) // past the 1s lease
	second, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: later, Lease: time.Minute})
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if second == nil || second.EventID != first.EventID {
		t.Fatalf("expected reclaim of the same event after lease expiry, got %+v", second)
	}
	if second.ClaimOwner == first.ClaimOwner {
		t.Fatal("reclaim must assign a fresh claim owner")
	}

	if err := o.MarkDelivered(ctx, DeliveryACK{EventID: first.EventID, ClaimOwner: first.ClaimOwner, Authoritative: true, StateAvailable: true, SourceComplete: true, Now: later}); err == nil {
		t.Fatal("stale claim owner must not be able to mark delivered")
	}
	if err := o.MarkDelivered(ctx, DeliveryACK{EventID: second.EventID, ClaimOwner: second.ClaimOwner, Authoritative: true, StateAvailable: true, SourceComplete: true, Now: later}); err != nil {
		t.Fatalf("current claim owner should be able to mark delivered: %v", err)
	}
}

// TestOutboundDispatcher_H15: event N+1 cannot be claimed while N has a
// live claim (strict FIFO — a later sequence never overtakes a blocked
// head-of-line row).
func TestOutboundDispatcher_H15(t *testing.T) {
	o := newTestOutbox(t)
	ctx := context.Background()
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "hook"))
	mustEnqueue(t, o, testDraft("wf2", "ws", "src", "hook"))

	now := time.Now()
	first, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: now, Lease: time.Minute})
	if err != nil || first == nil || first.Sequence != 1 {
		t.Fatalf("expected to claim sequence 1, got %+v (err=%v)", first, err)
	}

	second, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: now, Lease: time.Minute})
	if err != nil {
		t.Fatalf("claim while blocked: %v", err)
	}
	if second != nil {
		t.Fatalf("expected no claimable event while sequence 1 has a live claim, got %+v", second)
	}
}

// TestOutboundDispatcher_H17: EnqueueBatch is idempotent for the same
// (workspace_key, source_id, webhook_name, workflow_id, body hash), and
// fails closed on a hash conflict rather than overwriting.
func TestOutboundDispatcher_H17(t *testing.T) {
	o := newTestOutbox(t)
	draft := testDraft("wf1", "ws", "src", "hook")
	first := mustEnqueue(t, o, draft)
	second := mustEnqueue(t, o, draft) // identical draft, safe retry
	if first.EventID != second.EventID || first.Sequence != second.Sequence {
		t.Fatalf("idempotent re-enqueue produced a different event: first=%+v second=%+v", first, second)
	}

	conflicting := testDraftWithResult("wf1", "ws", "src", "hook", "failure")
	if _, err := o.EnqueueBatch(context.Background(), []EventDraft{conflicting}); err == nil {
		t.Fatal("expected a conflict error for a different body under the same (workspace,source,webhook,workflow) identity")
	}
}

// TestOutboundDispatcher_H19: reaching max_attempts on a retryable
// failure atomically dead-letters the row and clears its claim.
func TestOutboundDispatcher_H19(t *testing.T) {
	o := newTestOutbox(t)
	ctx := context.Background()
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "hook"))
	now := time.Now()

	claimed, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: now, Lease: time.Minute})
	if err != nil || claimed == nil {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	state, err := o.MarkAttemptFailed(ctx, DeliveryFailure{
		EventID: claimed.EventID, ClaimOwner: claimed.ClaimOwner, Now: now,
		Retryable: true, ErrorClass: ErrorClassHTTP5xx, ErrorText: "http status 503",
		NextAttemptAt: now.Add(time.Second), ConsumeAttempt: true, MaxAttempts: 1,
	})
	if err != nil {
		t.Fatalf("MarkAttemptFailed: %v", err)
	}
	if state != OutboxDeadLetter {
		t.Fatalf("state = %q, want dead_letter (attempt_count reached max_attempts=1)", state)
	}

	// The claim must be fully cleared: a stale MarkDelivered/MarkAttemptFailed
	// with the old claim owner must fail.
	if _, err := o.MarkAttemptFailed(ctx, DeliveryFailure{EventID: claimed.EventID, ClaimOwner: claimed.ClaimOwner, Now: now, Retryable: true, ErrorClass: ErrorClassHTTP5xx, ConsumeAttempt: true, MaxAttempts: 100}); err == nil {
		t.Fatal("expected stale claim owner to be rejected after dead-letter")
	}
}

// TestOutboundDispatcher_H21: terminal payload compaction is atomic —
// once a row reaches delivered or dead_letter, body_json and
// target_snapshot_json are cleared, but body_sha256 (audit) remains.
func TestOutboundDispatcher_H21(t *testing.T) {
	o := newTestOutbox(t)
	ctx := context.Background()
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "hook"))
	now := time.Now()

	claimed, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: now, Lease: time.Minute})
	if err != nil || claimed == nil {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if err := o.MarkDelivered(ctx, DeliveryACK{EventID: claimed.EventID, ClaimOwner: claimed.ClaimOwner, Authoritative: true, StateAvailable: true, SourceComplete: true, Now: now}); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}

	var bodyJSON, sha string
	if err := o.db.QueryRow(`SELECT body_json, body_sha256 FROM webhook_outbox WHERE event_id=?`, claimed.EventID).Scan(&bodyJSON, &sha); err != nil {
		t.Fatal(err)
	}
	if bodyJSON != "" {
		t.Fatalf("body_json = %q, want empty after terminal compaction", bodyJSON)
	}
	if sha == "" {
		t.Fatal("body_sha256 must survive compaction for audit")
	}
}

// TestOutboundConfig_CFG14 (design spec CFG14, deferred from Phase 1):
// a webhook removed from config becomes orphaned_config; a disabled
// webhook's pending row becomes paused_config and later resumes to
// pending when re-enabled.
func TestOutboundConfig_CFG14(t *testing.T) {
	o := newTestOutbox(t)
	ctx := context.Background()
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "keep-me"))
	mustEnqueue(t, o, testDraft("wf2", "ws", "src", "remove-me"))

	cfgWithBoth := &Config{SourceID: "src", Webhooks: []WebhookConfig{
		{Name: "keep-me", Enabled: false},
	}}
	if err := o.ReconcileWebhookConfig(ctx, "ws", cfgWithBoth); err != nil {
		t.Fatalf("ReconcileWebhookConfig: %v", err)
	}

	var keepState, removeState string
	if err := o.db.QueryRow(`SELECT state FROM webhook_outbox WHERE webhook_name='keep-me'`).Scan(&keepState); err != nil {
		t.Fatal(err)
	}
	if err := o.db.QueryRow(`SELECT state FROM webhook_outbox WHERE webhook_name='remove-me'`).Scan(&removeState); err != nil {
		t.Fatal(err)
	}
	if keepState != string(OutboxPausedConfig) {
		t.Fatalf("keep-me (disabled) state = %q, want paused_config", keepState)
	}
	if removeState != string(OutboxOrphanedConfig) {
		t.Fatalf("remove-me (absent from config) state = %q, want orphaned_config", removeState)
	}

	// Re-enable keep-me: it must resume to pending.
	cfgResumed := &Config{SourceID: "src", Webhooks: []WebhookConfig{
		{Name: "keep-me", Enabled: true},
	}}
	if err := o.ReconcileWebhookConfig(ctx, "ws", cfgResumed); err != nil {
		t.Fatalf("ReconcileWebhookConfig (resume): %v", err)
	}
	if err := o.db.QueryRow(`SELECT state FROM webhook_outbox WHERE webhook_name='keep-me'`).Scan(&keepState); err != nil {
		t.Fatal(err)
	}
	if keepState != string(OutboxPending) {
		t.Fatalf("keep-me after re-enable state = %q, want pending", keepState)
	}

	// Reintroducing remove-me's config does NOT resurrect the orphaned row.
	cfgReintroduced := &Config{SourceID: "src", Webhooks: []WebhookConfig{
		{Name: "keep-me", Enabled: true},
		{Name: "remove-me", Enabled: true},
	}}
	if err := o.ReconcileWebhookConfig(ctx, "ws", cfgReintroduced); err != nil {
		t.Fatalf("ReconcileWebhookConfig (reintroduce): %v", err)
	}
	if err := o.db.QueryRow(`SELECT state FROM webhook_outbox WHERE webhook_name='remove-me'`).Scan(&removeState); err != nil {
		t.Fatal(err)
	}
	if removeState != string(OutboxOrphanedConfig) {
		t.Fatalf("remove-me must stay orphaned_config even after its name reappears in config, got %q", removeState)
	}
}

// TestOutboundDispatcher_H24 (design spec §7.4.1, §30): a shared
// data-dir isolates workspace_key rows, and a source_id already bound to
// a different workspace fails closed.
func TestOutboundDispatcher_H24(t *testing.T) {
	o := newTestOutbox(t)
	ctx := context.Background()
	now := time.Now()

	if err := o.CheckWorkspaceBinding(ctx, "ws-a", "shared-source", now); err != nil {
		t.Fatalf("bind ws-a: %v", err)
	}
	if err := o.CheckWorkspaceBinding(ctx, "ws-a", "shared-source", now); err != nil {
		t.Fatalf("rebind same workspace/source must be a no-op: %v", err)
	}
	if err := o.CheckWorkspaceBinding(ctx, "ws-b", "shared-source", now); err == nil {
		t.Fatal("expected fail-closed: source_id already bound to a different workspace_key")
	}

	// ws-a and ws-b each enqueue against the same source_id/webhook_name
	// string but distinct workspace_key — must not collide/interleave.
	mustEnqueue(t, o, testDraft("wf-a", "ws-a", "shared-source", "hook"))
	mustEnqueue(t, o, testDraft("wf-b", "ws-b", "shared-source", "hook"))
	now = time.Now() // after enqueue, so next_attempt_at (set at enqueue time) is already due

	claimedA, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws-a", SourceID: "shared-source", WebhookName: "hook", Now: now, Lease: time.Minute})
	if err != nil || claimedA == nil {
		t.Fatalf("claim ws-a: %v %v", claimedA, err)
	}
	claimedB, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws-b", SourceID: "shared-source", WebhookName: "hook", Now: now, Lease: time.Minute})
	if err != nil || claimedB == nil {
		t.Fatalf("claim ws-b: %v %v", claimedB, err)
	}
	if claimedA.EventID == claimedB.EventID {
		t.Fatal("workspace-scoped claims must never return the same row")
	}
}
