package agentcontroller

import (
	"testing"
	"time"
)

func TestApprove_BindsToExactPlanHash(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testRepairPlan(incidentID, now)
	if err := s.CreatePlan(p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	if _, err := s.Approve(p.ID, "wrong-hash", "alice", "ok", now); err == nil {
		t.Fatal("expected an error: approval must bind to the exact current plan hash")
	}
	rec, err := s.Approve(p.ID, p.PlanHash, "alice", "looks safe", now)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if rec.Decision != ApprovalDecisionApproved || rec.Actor != "alice" {
		t.Errorf("rec = %+v", rec)
	}
	got, _ := s.GetPlan(p.ID)
	if got.State != PlanStateApproved {
		t.Errorf("State = %q, want APPROVED", got.State)
	}
}

func TestApprove_ActorRequired(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testRepairPlan(incidentID, now)
	if err := s.CreatePlan(p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	if _, err := s.Approve(p.ID, p.PlanHash, "", "ok", now); err == nil {
		t.Fatal("expected an error: actor is required — never Agent-supplied text with no identity")
	}
}

func TestApprove_CannotApproveTwice(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testRepairPlan(incidentID, now)
	if err := s.CreatePlan(p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	if _, err := s.Approve(p.ID, p.PlanHash, "alice", "ok", now); err != nil {
		t.Fatalf("first Approve: %v", err)
	}
	if _, err := s.Approve(p.ID, p.PlanHash, "bob", "also ok", now); err == nil {
		t.Fatal("expected an error: plan is no longer PROPOSED, cannot approve again")
	}
}

func TestReject_TerminalNoLaterApproval(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testRepairPlan(incidentID, now)
	if err := s.CreatePlan(p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	if _, err := s.Reject(p.ID, p.PlanHash, "alice", "too risky right now", now); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	got, _ := s.GetPlan(p.ID)
	if got.State != PlanStateRejected {
		t.Errorf("State = %q, want REJECTED", got.State)
	}
	if _, err := s.Approve(p.ID, p.PlanHash, "bob", "changed my mind", now); err == nil {
		t.Fatal("expected an error: a rejected plan can never later be approved")
	}
}

func TestListApprovals_ReturnsRecordedDecisions(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	incidentID := testIncidentForRemediation(t, s, now)
	p := testRepairPlan(incidentID, now)
	if err := s.CreatePlan(p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	if _, err := s.Approve(p.ID, p.PlanHash, "alice", "looks safe", now); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	approvals, err := s.ListApprovals(p.ID)
	if err != nil {
		t.Fatalf("ListApprovals: %v", err)
	}
	if len(approvals) != 1 || approvals[0].Actor != "alice" {
		t.Fatalf("approvals = %+v", approvals)
	}
}
