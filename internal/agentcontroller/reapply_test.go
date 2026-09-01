package agentcontroller

import (
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/repair"
)

func testReapplyPlan(incidentID string, now time.Time) repair.ReapplyPlan {
	return repair.ReapplyPlan{
		SchemaVersion: 1, ID: "reapply-plan-1", IncidentID: incidentID, Host: "web-1", Component: "alertmanager",
		Action: "reapply", Risk: "R2", VerificationSpec: "docs/verification/alertmanager.md",
		InventoryRevision: "irev", ContractHash: "chash", PlanHash: "phash", CreatedAt: now, ExpiresAt: now.Add(repair.ReapplyPlanTTL),
		Resolved: repair.ReapplyResolvedInput{
			PlaybookPath: "playbooks/apply/alertmanager-apply.yml", PlaybookHash: "pbhash", TargetHost: "web-1", Stage: "sandbox",
			ResolvedInputKeys: []string{"retention_days"}, SecretReferenceKeys: []string{"alertmanager_config"},
			DependencySnapshot: []repair.DependencyStatus{{Component: "docker", Required: true, Healthy: true, Detail: "active"}},
			PreviewRef:         "prevref", PreviewSupported: true, PreviewSummary: "no changes", PreviewEstimatedChanged: 0,
		},
	}
}

func TestCreateReapplyPlanAndGet(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testReapplyPlan(incidentID, now)
	if err := s.CreateReapplyPlan(p); err != nil {
		t.Fatalf("CreateReapplyPlan: %v", err)
	}
	got, err := s.GetReapplyPlan(p.ID)
	if err != nil || got == nil {
		t.Fatalf("GetReapplyPlan: %v, %+v", err, got)
	}
	if got.State != ReapplyPlanStateProposed {
		t.Errorf("State = %q, want PROPOSED", got.State)
	}
	if got.PlaybookHash != p.Resolved.PlaybookHash || got.PlanHash != p.PlanHash {
		t.Errorf("got = %+v, want fields matching %+v", got, p)
	}
	if len(got.ResolvedInputKeys) != 1 || got.ResolvedInputKeys[0] != "retention_days" {
		t.Errorf("ResolvedInputKeys = %v", got.ResolvedInputKeys)
	}
	if len(got.SecretReferenceKeys) != 1 || got.SecretReferenceKeys[0] != "alertmanager_config" {
		t.Errorf("SecretReferenceKeys = %v", got.SecretReferenceKeys)
	}
	if len(got.DependencySnapshot) != 1 || !got.DependencySnapshot[0].Healthy {
		t.Errorf("DependencySnapshot = %+v", got.DependencySnapshot)
	}
}

func TestMarkReapplyExecuting_RequiresApproved(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testReapplyPlan(incidentID, now)
	if err := s.CreateReapplyPlan(p); err != nil {
		t.Fatalf("CreateReapplyPlan: %v", err)
	}
	if _, err := s.MarkReapplyExecuting(p.ID, now); err == nil {
		t.Fatal("expected an error: plan is PROPOSED, not APPROVED")
	}
	if _, err := s.ApproveReapply(p.ID, p.PlanHash, "alice", "looks safe", now); err != nil {
		t.Fatalf("ApproveReapply: %v", err)
	}
	if _, err := s.MarkReapplyExecuting(p.ID, now); err != nil {
		t.Fatalf("MarkReapplyExecuting after approval: %v", err)
	}
	got, _ := s.GetReapplyPlan(p.ID)
	if got.State != ReapplyPlanStateExecuting {
		t.Errorf("State = %q, want EXECUTING", got.State)
	}
}

func TestApproveReapply_RequiresActor(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testReapplyPlan(incidentID, now)
	if err := s.CreateReapplyPlan(p); err != nil {
		t.Fatalf("CreateReapplyPlan: %v", err)
	}
	if _, err := s.ApproveReapply(p.ID, p.PlanHash, "", "no actor", now); err == nil {
		t.Fatal("expected an error: actor is required")
	}
}

func TestApproveReapply_WrongHashRejected(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testReapplyPlan(incidentID, now)
	if err := s.CreateReapplyPlan(p); err != nil {
		t.Fatalf("CreateReapplyPlan: %v", err)
	}
	if _, err := s.ApproveReapply(p.ID, "wrong-hash", "alice", "ok", now); err == nil {
		t.Fatal("expected an error: plan hash mismatch")
	}
}

func TestRejectReapply_IsTerminal(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testReapplyPlan(incidentID, now)
	if err := s.CreateReapplyPlan(p); err != nil {
		t.Fatalf("CreateReapplyPlan: %v", err)
	}
	if _, err := s.RejectReapply(p.ID, p.PlanHash, "alice", "not now", now); err != nil {
		t.Fatalf("RejectReapply: %v", err)
	}
	if _, err := s.ApproveReapply(p.ID, p.PlanHash, "alice", "changed my mind", now); err == nil {
		t.Fatal("expected an error: a rejected plan can never later be approved")
	}
}

func TestMarkReapplyExecuting_ExpiredPlanRejected(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testReapplyPlan(incidentID, now)
	if err := s.CreateReapplyPlan(p); err != nil {
		t.Fatalf("CreateReapplyPlan: %v", err)
	}
	if _, err := s.ApproveReapply(p.ID, p.PlanHash, "alice", "ok", now); err != nil {
		t.Fatalf("ApproveReapply: %v", err)
	}
	later := now.Add(repair.ReapplyPlanTTL + time.Minute)
	if _, err := s.MarkReapplyExecuting(p.ID, later); err == nil {
		t.Fatal("expected an error: plan expired before execution")
	}
	got, _ := s.GetReapplyPlan(p.ID)
	if got.State != ReapplyPlanStateExpired {
		t.Errorf("State = %q, want EXPIRED", got.State)
	}
}

func TestFinishReapplyRun_TransitionsToTerminalStateAndBlocksReplay(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testReapplyPlan(incidentID, now)
	if err := s.CreateReapplyPlan(p); err != nil {
		t.Fatalf("CreateReapplyPlan: %v", err)
	}
	if _, err := s.ApproveReapply(p.ID, p.PlanHash, "alice", "ok", now); err != nil {
		t.Fatalf("ApproveReapply: %v", err)
	}
	if _, err := s.MarkReapplyExecuting(p.ID, now); err != nil {
		t.Fatalf("MarkReapplyExecuting: %v", err)
	}
	if err := s.FinishReapplyRun(p.ID, repair.ReapplyAppliedVerified, 1, "audit-1", "verify-1", now, now.Add(time.Second)); err != nil {
		t.Fatalf("FinishReapplyRun: %v", err)
	}
	got, _ := s.GetReapplyPlan(p.ID)
	if got.State != repair.ReapplyAppliedVerified {
		t.Errorf("State = %q, want %q", got.State, repair.ReapplyAppliedVerified)
	}

	if err := s.FinishReapplyRun(p.ID, repair.ReapplyAppliedVerified, 1, "audit-2", "verify-2", now, now.Add(time.Second)); err == nil {
		t.Fatal("expected an error: a plan must never execute twice")
	}
}

func TestRecoverOrphanedExecutingReapplyPlans(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testReapplyPlan(incidentID, now)
	if err := s.CreateReapplyPlan(p); err != nil {
		t.Fatalf("CreateReapplyPlan: %v", err)
	}
	if _, err := s.ApproveReapply(p.ID, p.PlanHash, "alice", "ok", now); err != nil {
		t.Fatalf("ApproveReapply: %v", err)
	}
	if _, err := s.MarkReapplyExecuting(p.ID, now); err != nil {
		t.Fatalf("MarkReapplyExecuting: %v", err)
	}

	n, err := s.RecoverOrphanedExecutingReapplyPlans(now.Add(time.Minute))
	if err != nil {
		t.Fatalf("RecoverOrphanedExecutingReapplyPlans: %v", err)
	}
	if n != 1 {
		t.Fatalf("recovered = %d, want 1", n)
	}
	got, _ := s.GetReapplyPlan(p.ID)
	if got.State != repair.ReapplyApplyFailedPartial {
		t.Errorf("State = %q, want %q", got.State, repair.ReapplyApplyFailedPartial)
	}
	if _, err := s.MarkReapplyExecuting(p.ID, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expected an error: a recovered plan must never execute again")
	}
}

func TestListReapplyApprovals(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testReapplyPlan(incidentID, now)
	if err := s.CreateReapplyPlan(p); err != nil {
		t.Fatalf("CreateReapplyPlan: %v", err)
	}
	if _, err := s.ApproveReapply(p.ID, p.PlanHash, "alice", "ok", now); err != nil {
		t.Fatalf("ApproveReapply: %v", err)
	}
	got, err := s.ListReapplyApprovals(p.ID)
	if err != nil {
		t.Fatalf("ListReapplyApprovals: %v", err)
	}
	if len(got) != 1 || got[0].Decision != ApprovalDecisionApproved || got[0].Actor != "alice" {
		t.Fatalf("got %+v", got)
	}
}
