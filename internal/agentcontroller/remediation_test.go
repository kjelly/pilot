package agentcontroller

import (
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/repair"
)

// testIncidentForRemediation ingests one real incident (remediation_plans
// has a foreign key to incidents, PRAGMA foreign_keys=ON) and returns its
// ID for use as a plan's IncidentID.
func testIncidentForRemediation(t *testing.T, s *Store, now time.Time) string {
	t.Helper()
	ev := firingEvent("prometheus-rule", "fp-remediation-1", "fp-remediation-1", "web-1", "critical", now)
	out, err := s.IngestEvent(ev, now)
	if err != nil {
		t.Fatalf("IngestEvent: %v", err)
	}
	return out.IncidentID
}

func testRepairPlan(incidentID string, now time.Time) repair.Plan {
	return repair.Plan{
		SchemaVersion: 1, ID: "plan-1", IncidentID: incidentID, Host: "web-1", Component: "prometheus",
		Action: "restart", Risk: "R1", ExecutorKind: "docker_restart", ExecutorTarget: "pilot-prometheus",
		VerificationSpec: "docs/verification/prometheus.md", InventoryRevision: "irev", ContractHash: "chash",
		PlanHash: "phash", CreatedAt: now, ExpiresAt: now.Add(repair.PlanTTL),
	}
}

func TestCreatePlanAndGetPlan(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testRepairPlan(incidentID, now)
	if err := s.CreatePlan(p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	got, err := s.GetPlan(p.ID)
	if err != nil || got == nil {
		t.Fatalf("GetPlan: %v, %+v", err, got)
	}
	if got.State != PlanStateProposed {
		t.Errorf("State = %q, want PROPOSED", got.State)
	}
	if got.PlanHash != p.PlanHash || got.ExecutorTarget != p.ExecutorTarget {
		t.Errorf("got = %+v, want fields matching %+v", got, p)
	}
}

func TestMarkExecuting_RequiresApproved(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testRepairPlan(incidentID, now)
	if err := s.CreatePlan(p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	if _, err := s.MarkExecuting(p.ID, now); err == nil {
		t.Fatal("expected an error: plan is PROPOSED, not APPROVED")
	}
	if _, err := s.Approve(p.ID, p.PlanHash, "alice", "looks safe", now); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := s.MarkExecuting(p.ID, now); err != nil {
		t.Fatalf("MarkExecuting after approval: %v", err)
	}
	got, _ := s.GetPlan(p.ID)
	if got.State != PlanStateExecuting {
		t.Errorf("State = %q, want EXECUTING", got.State)
	}
}

func TestMarkExecuting_ExpiredPlanRejected(t *testing.T) {
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
	later := now.Add(repair.PlanTTL + time.Minute)
	if _, err := s.MarkExecuting(p.ID, later); err == nil {
		t.Fatal("expected an error: plan expired before execution")
	}
	got, _ := s.GetPlan(p.ID)
	if got.State != PlanStateExpired {
		t.Errorf("State = %q, want EXPIRED", got.State)
	}
}

func TestFinishRun_TransitionsToTerminalStateAndBlocksReplay(t *testing.T) {
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
	if err := s.FinishRun(p.ID, PlanStateAppliedVerified, "audit-1", "verify-1", now, now.Add(time.Second)); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}
	got, _ := s.GetPlan(p.ID)
	if got.State != PlanStateAppliedVerified {
		t.Errorf("State = %q, want APPLIED_VERIFIED", got.State)
	}

	// Replay: a second FinishRun for the SAME plan must fail (unique
	// index on remediation_runs.plan_id) — design doc §10: "Replay of an
	// already executed approved plan must fail."
	if err := s.FinishRun(p.ID, PlanStateAppliedVerified, "audit-2", "verify-2", now, now.Add(time.Second)); err == nil {
		t.Fatal("expected an error: a plan must never execute twice")
	}
}

func TestMarkExecuting_CannotReexecuteTerminalPlan(t *testing.T) {
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
	if err := s.FinishRun(p.ID, PlanStateExecutionFailed, "audit-1", "", now, now); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}
	if _, err := s.MarkExecuting(p.ID, now); err == nil {
		t.Fatal("expected an error: cannot re-execute a plan already in a terminal state")
	}
}
