package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/outbound"
)

// publishPartialFailure publishes the terminal event of a users-groups run that
// committed writes and then ended partial_failed at verify (spec §6.1), from ctx.
func publishPartialFailure(ctx context.Context, env *outboundWorkflowEnv, out *bytes.Buffer) {
	results := []ComponentDeliveryResult{{ComponentIDs: []string{"freeipa-identity"}, RunID: "run-ug", Outcome: delivery.OutcomePartialFailed, FailedStep: "verify"}}
	agg := aggregateDeploymentResult(results)
	publishTerminalWorkflow(ctx, out, PublishTerminalWorkflowInput{
		WorkspaceDir: env.workspace, Inventory: env.inv,
		Operation: outbound.OperationReconcile, WorkflowID: newWorkflowID(),
		RequestedComponents: []string{"freeipa-identity"}, ExecutedComponents: []string{"freeipa-identity"},
		CompletedComponents: agg.CompletedComponents, FailedComponent: agg.FailedComponent,
		Effects:          []string{"identity.users", "identity.groups"},
		ConfirmedEffects: agg.ConfirmedEffects,
		Result:           agg.Result, ApplicationConsistency: agg.ApplicationConsistency,
		DeliveryRuns: agg.DeliveryRuns, Failure: agg.Failure,
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
}

// T5-T7 of spec 2026-11-06 phase 2 §4.4: a run whose ctx was cancelled (Ctrl-C,
// --timeout, a lost lock) still announces its result. Before the class rule the
// enqueue ran on the cancelled ctx and failed ("event NOT durable"), so a run that
// had committed writes published nothing at all.
func TestPublishTerminalWorkflowAnnouncesARunWhoseContextWasCancelled(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"host-a": {"host-a"}}, reconcileEventsYAMLEffectsAny(outbound.ResultFailure, "identity.users"), 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	publishPartialFailure(ctx, env, &out)
	if got := env.capture.count(); got != 1 {
		t.Fatalf("webhook deliveries = %d, want 1 although ctx was cancelled; output:\n%s", got, out.String())
	}
	if strings.Contains(out.String(), "NOT durable") {
		t.Fatalf("the enqueue failed on the cancelled ctx:\n%s", out.String())
	}
	var body map[string]any
	if err := json.Unmarshal(env.capture.last(), &body); err != nil {
		t.Fatal(err)
	}
	op, _ := body["operation"].(map[string]any)
	failure, _ := body["failure"].(map[string]any)
	if op["result"] != "failure" || failure["class"] != "verify_failed" || failure["phase"] != "verify" {
		t.Fatalf("operation.result = %v, failure = %v; want failure / verify_failed at verify", op["result"], failure)
	}
	state, _ := body["state"].(map[string]any)
	if state["application_consistency"] != "partial_or_unknown" {
		t.Errorf("state.application_consistency = %v, want partial_or_unknown", state["application_consistency"])
	}
	if confirmed, _ := state["confirmed_effects"].([]any); len(confirmed) != 0 {
		t.Errorf("state.confirmed_effects = %v: a partial_failed run confirms no effect (R7)", confirmed)
	}
}

// The detached path is bounded and best effort: a receiver that never answers
// costs at most webhookFlushTimeout, the publication returns, and the event stays
// in the outbox (pending) for `pilot webhook flush`, not lost.
func TestPublishTerminalWorkflowOfACancelledRunIsBoundedWhenTheReceiverHangs(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"host-a": {"host-a"}}, reconcileEventsYAMLEffectsAny(outbound.ResultFailure, "identity.users"), 0)
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer hung.Close()
	defer close(release)
	writeOutboundWorkflowIntegrationsYAML(t, env.workspace, hung.URL, reconcileEventsYAMLEffectsAny(outbound.ResultFailure, "identity.users"))
	oldFlush, oldAll := webhookFlushTimeout, outboundPublishTimeout
	webhookFlushTimeout, outboundPublishTimeout = 300*time.Millisecond, 20*time.Second
	t.Cleanup(func() { webhookFlushTimeout, outboundPublishTimeout = oldFlush, oldAll })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	start := time.Now()
	publishPartialFailure(ctx, env, &out)
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("the publication of a cancelled run took %s, the flush bound is %s", took, webhookFlushTimeout)
	}
	if strings.Contains(out.String(), "NOT durable") {
		t.Fatalf("the event was not enqueued:\n%s", out.String())
	}
	// The event that could not be delivered inside its bound is in the outbox, not
	// lost: `pilot webhook flush` sends it later.
	db, err := outbound.OpenOutboxDB(filepath.Join(resolvePilotDataDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var rows int
	var result string
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(MAX(result), '') FROM webhook_outbox`).Scan(&rows, &result); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || result != "failure" {
		t.Fatalf("outbox holds %d events (result %q), want the one failure event", rows, result)
	}
}

// The normal path is what it was: a live ctx is not given the cancelled path's
// bounds (a slow receiver is waited for, up to the 30 s flush budget), so the
// change to cancelled runs does not shorten anything for the others.
func TestPublishTerminalWorkflowOfALiveRunKeepsItsFlushBudget(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"host-a": {"host-a"}}, reconcileEventsYAMLEffectsAny(outbound.ResultFailure, "identity.users"), 0)
	slow := newWebhookCapture(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(700 * time.Millisecond)
		slow.handler()(w, r)
	}))
	defer srv.Close()
	writeOutboundWorkflowIntegrationsYAML(t, env.workspace, srv.URL, reconcileEventsYAMLEffectsAny(outbound.ResultFailure, "identity.users"))
	oldFlush, oldAll := webhookFlushTimeout, outboundPublishTimeout
	webhookFlushTimeout, outboundPublishTimeout = 100*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { webhookFlushTimeout, outboundPublishTimeout = oldFlush, oldAll })

	var out bytes.Buffer
	publishPartialFailure(context.Background(), env, &out)
	if got := slow.count(); got != 1 {
		t.Fatalf("a live run's event was delivered %d times, want 1 (the cancelled path's bounds applied to it?); output:\n%s", got, out.String())
	}
}
