package outbound

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOutboundEffectMatch_ExactAndWildcard(t *testing.T) {
	cfg := WebhookConfig{Events: []EventRule{
		{Operation: OperationReconcile, Result: ResultSuccess, EffectsAny: []string{"identity.*", "access.hbac"}, Payload: PayloadBoth},
	}}
	if _, ok := MatchEventRule(cfg, OperationReconcile, ResultSuccess, []string{"dns.records", "identity.users"}); !ok {
		t.Fatal("expected identity.users to match wildcard identity.*")
	}
	if _, ok := MatchEventRule(cfg, OperationReconcile, ResultSuccess, []string{"access.hbac"}); !ok {
		t.Fatal("expected exact match on access.hbac")
	}
	if _, ok := MatchEventRule(cfg, OperationReconcile, ResultSuccess, []string{"dns.zones", "dns.records"}); ok {
		t.Fatal("dns-only effects must not match an identity/access-only subscription")
	}
}

func TestOutboundEffectMatch_DeployRuleMatchesOnOperationResultOnly(t *testing.T) {
	cfg := WebhookConfig{Events: []EventRule{
		{Operation: OperationDeploy, Result: ResultSuccess, Payload: PayloadSnapshot},
	}}
	if _, ok := MatchEventRule(cfg, OperationDeploy, ResultSuccess, nil); !ok {
		t.Fatal("a deploy rule with no effects_any must match regardless of effects")
	}
	if _, ok := MatchEventRule(cfg, OperationDeploy, ResultFailure, nil); ok {
		t.Fatal("must not match a different result")
	}
}

func TestOutboundEffectMatch_NamespaceWildcardDoesNotMatchBareNamespace(t *testing.T) {
	cfg := WebhookConfig{Events: []EventRule{
		{Operation: OperationReconcile, Result: ResultSuccess, EffectsAny: []string{"identity.*"}, Payload: PayloadSnapshot},
	}}
	if _, ok := MatchEventRule(cfg, OperationReconcile, ResultSuccess, []string{"identity"}); ok {
		t.Fatal("bare 'identity' must not match wildcard 'identity.*'")
	}
	if _, ok := MatchEventRule(cfg, OperationReconcile, ResultSuccess, []string{"access.identity"}); ok {
		t.Fatal("access.identity must not match identity.* (different namespace)")
	}
}

// TestOutboundDiff_D13/D14 (via ResolveEffectiveBase, pure function):
// a pending authoritative event's target becomes the next base, never a
// stale cursor; a non-authoritative event is never a chain predecessor.
func TestOutboundDiff_ResolveEffectiveBase(t *testing.T) {
	cursor := &SnapshotRef{ID: "sha256:cursor", JSON: json.RawMessage(`{}`)}
	pending := &SnapshotRef{ID: "sha256:pending", JSON: json.RawMessage(`{"users":[]}`)}

	base, bootstrap := ResolveEffectiveBase(pending, cursor)
	if bootstrap || base.ID != "sha256:pending" {
		t.Fatalf("with a pending authoritative target, base = %+v bootstrap=%v, want pending target, not cursor", base, bootstrap)
	}

	base, bootstrap = ResolveEffectiveBase(nil, cursor)
	if bootstrap || base.ID != "sha256:cursor" {
		t.Fatalf("with no pending target, base = %+v bootstrap=%v, want cursor", base, bootstrap)
	}

	base, bootstrap = ResolveEffectiveBase(nil, nil)
	if !bootstrap || base.ID != "" {
		t.Fatalf("with neither pending nor cursor, want bootstrap=true empty base, got %+v bootstrap=%v", base, bootstrap)
	}
}

// TestOutboundDiff_D8: a failure event's cursor never advances.
func TestOutboundDiff_D8(t *testing.T) {
	o := newTestOutbox(t)
	ctx := context.Background()
	mustEnqueue(t, o, testDraft("wf1", "ws", "src", "hook"))
	now := time.Now()
	claimed, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: now, Lease: time.Minute})
	if err != nil || claimed == nil {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if err := o.MarkDelivered(ctx, DeliveryACK{EventID: claimed.EventID, ClaimOwner: claimed.ClaimOwner, Authoritative: false, StateAvailable: true, SourceComplete: true, Now: now}); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}
	var count int
	if err := o.db.QueryRow(`SELECT COUNT(*) FROM webhook_state_cursor WHERE workspace_key='ws' AND source_id='src' AND webhook_name='hook'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("a non-authoritative (failure) event must never create/advance a cursor row")
	}
}

// TestOutboundDiff_D9: a success ACK (authoritative+available+complete)
// advances the cursor.
func TestOutboundDiff_D9(t *testing.T) {
	o := newTestOutbox(t)
	ctx := context.Background()
	draft := testDraft("wf1", "ws", "src", "hook")
	draft.TargetSnapshotID = "sha256:target1"
	draft.TargetSnapshotJSON = `{"hosts":[]}`
	mustEnqueue(t, o, draft)
	now := time.Now()
	claimed, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: now, Lease: time.Minute})
	if err != nil || claimed == nil {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if err := o.MarkDelivered(ctx, DeliveryACK{EventID: claimed.EventID, ClaimOwner: claimed.ClaimOwner, Authoritative: true, StateAvailable: true, SourceComplete: true, Now: now}); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}
	var snapshotID string
	if err := o.db.QueryRow(`SELECT snapshot_id FROM webhook_state_cursor WHERE workspace_key='ws' AND source_id='src' AND webhook_name='hook'`).Scan(&snapshotID); err != nil {
		t.Fatalf("expected a cursor row: %v", err)
	}
	if snapshotID != "sha256:target1" {
		t.Fatalf("cursor snapshot_id = %q, want sha256:target1", snapshotID)
	}
}

// TestOutboundDiff_D11_H16: a diff-only event whose base doesn't match
// the current cursor is blocked (blocked_base_mismatch), and a later
// snapshot/both event re-establishes the cursor from scratch.
func TestOutboundDiff_D11_H16(t *testing.T) {
	o := newTestOutbox(t)
	ctx := context.Background()

	// A diff-only event whose base_snapshot_id doesn't match any
	// existing cursor (there is none yet — but a diff always assumes a
	// specific predecessor, so a mismatched non-empty base is unsafe).
	draft := testDraft("wf1", "ws", "src", "hook")
	draft.PayloadMode = string(PayloadDiff)
	draft.BaseSnapshotID = "sha256:never-acked"
	mustEnqueue(t, o, draft)
	now := time.Now() // after enqueue, so next_attempt_at (set at enqueue time) is already due

	claimed, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: now, Lease: time.Minute})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if claimed != nil {
		t.Fatalf("expected no claimable event (blocked), got %+v", claimed)
	}
	var state string
	if err := o.db.QueryRow(`SELECT state FROM webhook_outbox WHERE workflow_id='wf1'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != string(OutboxBlockedBaseMismatch) {
		t.Fatalf("state = %q, want blocked_base_mismatch", state)
	}

	// blocked_base_mismatch is terminal — it must not block a later
	// sequence. A subsequent snapshot event is claimable and, once
	// delivered, re-establishes the cursor.
	recovery := testDraft("wf2", "ws", "src", "hook")
	recovery.PayloadMode = string(PayloadSnapshot)
	recovery.TargetSnapshotID = "sha256:recovered"
	mustEnqueue(t, o, recovery)
	now = time.Now()

	claimed2, err := o.ClaimNextDue(ctx, ClaimRequest{WorkspaceKey: "ws", SourceID: "src", WebhookName: "hook", Now: now, Lease: time.Minute})
	if err != nil || claimed2 == nil {
		t.Fatalf("claim recovery event: %v %v", claimed2, err)
	}
	if claimed2.PayloadMode != string(PayloadSnapshot) {
		t.Fatalf("expected to claim the recovery (snapshot) event, got %+v", claimed2)
	}
	if err := o.MarkDelivered(ctx, DeliveryACK{EventID: claimed2.EventID, ClaimOwner: claimed2.ClaimOwner, Authoritative: true, StateAvailable: true, SourceComplete: true, Now: now}); err != nil {
		t.Fatalf("MarkDelivered recovery: %v", err)
	}
	var snapshotID string
	if err := o.db.QueryRow(`SELECT snapshot_id FROM webhook_state_cursor WHERE workspace_key='ws' AND source_id='src' AND webhook_name='hook'`).Scan(&snapshotID); err != nil {
		t.Fatal(err)
	}
	if snapshotID != "sha256:recovered" {
		t.Fatalf("cursor snapshot_id = %q, want sha256:recovered", snapshotID)
	}
}

// TestOutboundEvent_BuildEnvelopeShape sanity-checks BuildEnvelope
// against design spec §16's success snapshot example shape.
func TestOutboundEvent_BuildEnvelopeShape(t *testing.T) {
	now := time.Date(2026, 9, 15, 6, 30, 0, 0, time.UTC)
	env, err := BuildEnvelope(BuildEnvelopeParams{
		SourceID: "linker-infra-prod", PilotVersion: "0.x", WebhookName: "external-user-host-directory",
		Sequence: 42, EventID: "94c0568d-6f66-4d26-bbd2-c2b207f7a183", CreatedAt: now,
		Op: OperationMetadata{
			WorkflowID: "d94cd98b", Operation: OperationDeploy, Result: ResultSuccess,
			RequestedComponents: []string{"docker"}, ExecutedComponents: []string{"docker"}, CompletedComponents: []string{"docker"},
			Effects:      nil,
			DeliveryRuns: []WireDeliveryRun{{RunID: "5a777", Outcome: "success"}},
			StartedAt:    now.Add(-2 * time.Minute), FinishedAt: now,
			ApplicationConsistency: "confirmed_for_effects",
			ConfirmedEffects:       nil,
		},
		Payload:       PayloadSnapshot,
		Projection:    ProjectionResult{Available: true, Snapshot: UserHostAccessSnapshotV1{}},
		Bootstrap:     true,
		Target:        UserHostAccessSnapshotV1{},
		Authoritative: true,
	})
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if env.SchemaVersion != 1 || env.EventType != "pilot.operation.terminal" {
		t.Fatalf("envelope header wrong: %+v", env)
	}
	if env.Source.ID != "linker-infra-prod" || env.Subscription.Name != "external-user-host-directory" || env.Subscription.Sequence != 42 {
		t.Fatalf("source/subscription wrong: %+v", env)
	}
	if env.Operation.Type != "deploy" || env.Operation.Result != "success" {
		t.Fatalf("operation wrong: %+v", env.Operation)
	}
	if !env.State.Available || !env.State.Authoritative || env.State.Basis != "pilot_declared" {
		t.Fatalf("state wrong: %+v", env.State)
	}
	if len(env.Snapshot) == 0 {
		t.Fatal("expected snapshot to be present for payload=snapshot")
	}
	if len(env.Diff) != 0 {
		t.Fatal("expected diff omitted for payload=snapshot")
	}

	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"schema_version":1`) {
		t.Fatalf("marshaled envelope missing schema_version: %s", body)
	}
}

// TestOutboundEvent_UnavailableOmitsSnapshotDiff (P24's event-envelope
// half, deferred from Phase 2): an unavailable projection's envelope
// omits snapshot/diff entirely and forces authoritative=false.
func TestOutboundEvent_UnavailableOmitsSnapshotDiff(t *testing.T) {
	now := time.Now()
	env, err := BuildEnvelope(BuildEnvelopeParams{
		SourceID: "src", PilotVersion: "0.x", WebhookName: "hook", Sequence: 1, EventID: "evt1", CreatedAt: now,
		Op: OperationMetadata{
			Operation: OperationDeploy, Result: ResultSuccess,
			ApplicationConsistency: "confirmed_for_effects",
			ConfirmedEffects:       []string{"access.hbac"},
		},
		Payload:       PayloadBoth,
		Projection:    ProjectionResult{Available: false, ErrorClass: ErrorClassProjectionUnavailable},
		Authoritative: true, // candidate — must be forced false since unavailable
	})
	if err != nil {
		t.Fatal(err)
	}
	if env.Snapshot != nil || env.Diff != nil {
		t.Fatalf("expected omitted snapshot/diff, got snapshot=%s diff=%s", env.Snapshot, env.Diff)
	}
	if env.State.Available || env.State.Authoritative {
		t.Fatalf("expected available=false authoritative=false, got %+v", env.State)
	}
	if env.State.ErrorClass != string(ErrorClassProjectionUnavailable) {
		t.Fatalf("error_class = %q, want %q", env.State.ErrorClass, ErrorClassProjectionUnavailable)
	}
	// application_consistency/confirmed_effects must survive unchanged.
	if env.State.ApplicationConsistency != "confirmed_for_effects" || len(env.State.ConfirmedEffects) != 1 {
		t.Fatalf("structured result fields must not be rewritten by projection unavailability: %+v", env.State)
	}

	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > int(MaxUnavailableEventBytes) {
		t.Fatalf("unavailable envelope is %d bytes, want <= %d", len(body), MaxUnavailableEventBytes)
	}
}

// TestOutboundEvent_PayloadTooLargeFallback (§38): an oversized body
// falls back to a bounded metadata-only envelope, never truncated
// entity arrays.
func TestOutboundEvent_PayloadTooLargeFallback(t *testing.T) {
	huge := make([]ProjectedUser, 0, 200000)
	for i := 0; i < 200000; i++ {
		huge = append(huge, ProjectedUser{Name: "user-with-a-fairly-long-name-to-pad-size", Enabled: true, EffectiveGroups: []string{"g1", "g2", "g3"}})
	}
	env, err := BuildEnvelope(BuildEnvelopeParams{
		SourceID: "src", PilotVersion: "0.x", WebhookName: "hook", Sequence: 1, EventID: "evt1", CreatedAt: time.Now(),
		Op:            OperationMetadata{Operation: OperationReconcile, Result: ResultSuccess, ApplicationConsistency: "confirmed_for_effects"},
		Payload:       PayloadSnapshot,
		Projection:    ProjectionResult{Available: true},
		Target:        UserHostAccessSnapshotV1{Users: huge},
		Authoritative: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	body, errClass, err := FinalizeEnvelope(env)
	if err != nil {
		t.Fatalf("FinalizeEnvelope: %v", err)
	}
	if errClass != ErrorClassPayloadTooLarge {
		t.Fatalf("errClass = %q, want %q", errClass, ErrorClassPayloadTooLarge)
	}
	if len(body) > int(MaxUnavailableEventBytes) {
		t.Fatalf("fallback body is %d bytes, want <= %d", len(body), MaxUnavailableEventBytes)
	}
	var fallback Envelope
	if err := json.Unmarshal(body, &fallback); err != nil {
		t.Fatal(err)
	}
	if fallback.Snapshot != nil {
		t.Fatal("fallback envelope must omit snapshot")
	}
	if fallback.State.Available {
		t.Fatal("fallback envelope must report available=false")
	}
}
