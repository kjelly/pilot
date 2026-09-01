package agentcontroller

import (
	"testing"
	"time"
)

func TestLastActionAt_NoneYet(t *testing.T) {
	s := newTestStore(t)
	got, err := s.LastActionAt("web-1", "prometheus", "restart")
	if err != nil {
		t.Fatalf("LastActionAt: %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil (no prior approved action)", got)
	}
}

func TestLastActionAt_ReturnsMostRecentApproval(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testRepairPlan(incidentID, now)
	if err := s.CreatePlan(p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	approvedAt := now.Add(time.Minute)
	if _, err := s.Approve(p.ID, p.PlanHash, "alice", "ok", approvedAt); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	got, err := s.LastActionAt(p.Host, p.Component, p.Action)
	if err != nil {
		t.Fatalf("LastActionAt: %v", err)
	}
	// rfc3339() truncates to whole seconds — compare at that precision,
	// like every other stored-timestamp round trip in this package.
	if got == nil || !got.Equal(approvedAt.UTC().Truncate(time.Second)) {
		t.Errorf("got %v, want %v", got, approvedAt.UTC().Truncate(time.Second))
	}
}

func TestCountApprovedActionsForHostAndComponent(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testRepairPlan(incidentID, now)
	if err := s.CreatePlan(p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	since := now.Add(-time.Hour)
	if n, err := s.CountApprovedActionsForHost(p.Host, since); err != nil || n != 0 {
		t.Fatalf("before approval: n=%d err=%v, want 0", n, err)
	}
	if _, err := s.Approve(p.ID, p.PlanHash, "alice", "ok", now); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if n, err := s.CountApprovedActionsForHost(p.Host, since); err != nil || n != 1 {
		t.Fatalf("CountApprovedActionsForHost: n=%d err=%v, want 1", n, err)
	}
	if n, err := s.CountApprovedActionsForComponent(p.Component, since); err != nil || n != 1 {
		t.Fatalf("CountApprovedActionsForComponent: n=%d err=%v, want 1", n, err)
	}
	// Outside the window -> 0.
	if n, err := s.CountApprovedActionsForHost(p.Host, now.Add(time.Minute)); err != nil || n != 0 {
		t.Fatalf("outside window: n=%d err=%v, want 0", n, err)
	}
}

func TestCountPolicyRunsForIncident_OnlyCountsPolicyActor(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)

	human := testRepairPlan(incidentID, now)
	human.ID, human.PlanHash = "plan-human", "hash-human"
	if err := s.CreatePlan(human); err != nil {
		t.Fatalf("CreatePlan human: %v", err)
	}
	if _, err := s.Approve(human.ID, human.PlanHash, "alice", "ok", now); err != nil {
		t.Fatalf("Approve human: %v", err)
	}
	if _, err := s.MarkExecuting(human.ID, now); err != nil {
		t.Fatalf("MarkExecuting human: %v", err)
	}
	if err := s.FinishRun(human.ID, PlanStateAppliedVerified, "a1", "v1", now, now); err != nil {
		t.Fatalf("FinishRun human: %v", err)
	}
	if n, err := s.CountPolicyRunsForIncident(incidentID); err != nil || n != 0 {
		t.Fatalf("after human-only run: n=%d err=%v, want 0", n, err)
	}

	auto := testRepairPlan(incidentID, now)
	auto.ID, auto.PlanHash = "plan-auto", "hash-auto"
	if err := s.CreatePlan(auto); err != nil {
		t.Fatalf("CreatePlan auto: %v", err)
	}
	if _, err := s.Approve(auto.ID, auto.PlanHash, PolicyActor("agent-monitoring-r1-autonomy", "d1"), "policy allow", now); err != nil {
		t.Fatalf("Approve auto: %v", err)
	}
	if _, err := s.MarkExecuting(auto.ID, now); err != nil {
		t.Fatalf("MarkExecuting auto: %v", err)
	}
	if err := s.FinishRun(auto.ID, PlanStateExecutionFailed, "a2", "", now, now); err != nil {
		t.Fatalf("FinishRun auto: %v", err)
	}
	if n, err := s.CountPolicyRunsForIncident(incidentID); err != nil || n != 1 {
		t.Fatalf("after one policy run (failed): n=%d err=%v, want 1 — any outcome counts", n, err)
	}
}

func TestHasHumanRejection(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testRepairPlan(incidentID, now)
	if err := s.CreatePlan(p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	if has, err := s.HasHumanRejection(p.Host, p.Component, p.Action); err != nil || has {
		t.Fatalf("before rejection: has=%v err=%v, want false", has, err)
	}
	if _, err := s.Reject(p.ID, p.PlanHash, "alice", "not now", now); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if has, err := s.HasHumanRejection(p.Host, p.Component, p.Action); err != nil || !has {
		t.Fatalf("after rejection: has=%v err=%v, want true", has, err)
	}
}

func TestHasHumanRejection_PolicyActorNeverCounts(t *testing.T) {
	// A policy-actor "rejection" is not a real code path today (policy
	// only ever Approves), but the query itself must never conflate a
	// policy actor with a human one even if that ever changes — this
	// locks the NOT LIKE 'policy:%' filter in place.
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testRepairPlan(incidentID, now)
	if err := s.CreatePlan(p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	if _, err := s.Reject(p.ID, p.PlanHash, PolicyActor("pol", "d1"), "auto-deny", now); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if has, err := s.HasHumanRejection(p.Host, p.Component, p.Action); err != nil || has {
		t.Fatalf("has=%v err=%v, want false — a policy-actor rejection is not a HUMAN rejection", has, err)
	}
}

func TestRecordAndListPolicyDecisions(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testRepairPlan(incidentID, now)
	if err := s.CreatePlan(p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	rec, err := s.RecordPolicyDecision(incidentID, p.ID, p.PlanHash, "allow_auto", "agent-monitoring-r1-autonomy", "1", `["all guards passed"]`, "shadow", now)
	if err != nil {
		t.Fatalf("RecordPolicyDecision: %v", err)
	}
	if rec.ID == "" {
		t.Fatal("expected a non-empty decision ID")
	}
	got, err := s.ListPolicyDecisions(p.ID)
	if err != nil {
		t.Fatalf("ListPolicyDecisions: %v", err)
	}
	if len(got) != 1 || got[0].Decision != "allow_auto" || got[0].Mode != "shadow" {
		t.Fatalf("got %+v", got)
	}
}

func TestHealthCheck(t *testing.T) {
	s := newTestStore(t)
	if !s.HealthCheck() {
		t.Error("HealthCheck() = false on a fresh store, want true")
	}
}

func TestRecoverOrphanedExecutingPlans(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testRepairPlan(incidentID, now)
	if err := s.CreatePlan(p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	if _, err := s.Approve(p.ID, p.PlanHash, "alice", "ok", now); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := s.MarkExecuting(p.ID, now); err != nil {
		t.Fatalf("MarkExecuting: %v", err)
	}
	// Simulate a crash: no FinishRun ever called. Plan is stuck EXECUTING.

	n, err := s.RecoverOrphanedExecutingPlans(now.Add(time.Minute))
	if err != nil {
		t.Fatalf("RecoverOrphanedExecutingPlans: %v", err)
	}
	if n != 1 {
		t.Fatalf("recovered = %d, want 1", n)
	}
	got, _ := s.GetPlan(p.ID)
	if got.State != PlanStateExecutionFailed {
		t.Errorf("State = %q, want EXECUTION_FAILED", got.State)
	}
	// A second recovery pass must be a no-op (nothing left to recover) —
	// and MarkExecuting must permanently refuse this plan now.
	n2, err := s.RecoverOrphanedExecutingPlans(now.Add(2 * time.Minute))
	if err != nil || n2 != 0 {
		t.Fatalf("second recovery: n=%d err=%v, want 0", n2, err)
	}
	if _, err := s.MarkExecuting(p.ID, now.Add(3*time.Minute)); err == nil {
		t.Fatal("expected an error: a recovered plan must never execute again")
	}
}
