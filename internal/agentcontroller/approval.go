package agentcontroller

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	ApprovalDecisionApproved = "approved"
	ApprovalDecisionRejected = "rejected"
)

// ApprovalRecord is one human decision on one plan — binds to
// (PlanID, PlanHash) together (design doc §7), never PlanID alone, so an
// approval can never be reinterpreted as covering a plan whose
// executable content changed after the human looked at it.
type ApprovalRecord struct {
	ID        string
	PlanID    string
	PlanHash  string
	Decision  string
	Actor     string
	Reason    string
	CreatedAt time.Time
}

// Approve records human approval and transitions a PROPOSED plan to
// APPROVED. Actor MUST come from trusted operator context (the CLI
// caller's own identity), never from Agent-supplied text (design doc
// §7). planHash must match the plan's OWN stored hash exactly — a
// caller approving against a stale/wrong hash (e.g. copy-pasted from an
// old plan) is rejected rather than silently approving whatever the
// current plan happens to be.
func (s *Store) Approve(planID, planHash, actor, reason string, now time.Time) (ApprovalRecord, error) {
	return s.recordApprovalDecision(planID, planHash, ApprovalDecisionApproved, actor, reason, PlanStateApproved, now)
}

// Reject records human rejection and transitions a PROPOSED plan to
// REJECTED — a terminal state; a rejected plan can never later be
// approved (create a new plan instead, so a fresh hash/expiry applies).
func (s *Store) Reject(planID, planHash, actor, reason string, now time.Time) (ApprovalRecord, error) {
	return s.recordApprovalDecision(planID, planHash, ApprovalDecisionRejected, actor, reason, PlanStateRejected, now)
}

func (s *Store) recordApprovalDecision(planID, planHash, decision, actor, reason, nextState string, now time.Time) (ApprovalRecord, error) {
	if actor == "" {
		return ApprovalRecord{}, fmt.Errorf("actor is required — approval must come from trusted operator context")
	}
	p, err := s.GetPlan(planID)
	if err != nil {
		return ApprovalRecord{}, err
	}
	if p == nil {
		return ApprovalRecord{}, fmt.Errorf("plan %s not found", planID)
	}
	if err := s.expireIfPastDeadline(p, now); err != nil {
		return ApprovalRecord{}, err
	}
	if p.State != PlanStateProposed {
		return ApprovalRecord{}, fmt.Errorf("plan %s is %s, not PROPOSED — cannot record a decision", planID, p.State)
	}
	if p.PlanHash != planHash {
		return ApprovalRecord{}, fmt.Errorf("plan hash mismatch for %s — approval must bind to the exact current plan hash (got %s, plan is %s)", planID, planHash, p.PlanHash)
	}

	rec := ApprovalRecord{ID: uuid.NewString(), PlanID: planID, PlanHash: planHash, Decision: decision, Actor: actor, Reason: reason, CreatedAt: now}

	tx, err := s.db.Begin()
	if err != nil {
		return ApprovalRecord{}, fmt.Errorf("begin approval: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	if _, execErr := tx.Exec(`
		INSERT INTO approvals (id, plan_id, plan_hash, decision, actor, reason, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, rec.ID, rec.PlanID, rec.PlanHash, rec.Decision, rec.Actor, rec.Reason, rfc3339(rec.CreatedAt)); execErr != nil {
		err = fmt.Errorf("insert approval: %w", execErr)
		return ApprovalRecord{}, err
	}
	res, execErr := tx.Exec(`UPDATE remediation_plans SET state = ? WHERE id = ? AND state = ?`, nextState, planID, PlanStateProposed)
	if execErr != nil {
		err = fmt.Errorf("update plan %s state: %w", planID, execErr)
		return ApprovalRecord{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		err = fmt.Errorf("plan %s state changed concurrently — refusing to record decision", planID)
		return ApprovalRecord{}, err
	}
	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit approval: %w", commitErr)
		return ApprovalRecord{}, err
	}
	return rec, nil
}

// ListApprovals returns every approval decision recorded for planID, in
// chronological order.
func (s *Store) ListApprovals(planID string) ([]ApprovalRecord, error) {
	rows, err := s.db.Query(`
		SELECT id, plan_id, plan_hash, decision, actor, COALESCE(reason, ''), created_at
		FROM approvals WHERE plan_id = ? ORDER BY created_at ASC
	`, planID)
	if err != nil {
		return nil, fmt.Errorf("list approvals for %s: %w", planID, err)
	}
	defer rows.Close()
	var out []ApprovalRecord
	for rows.Next() {
		var r ApprovalRecord
		var createdAt string
		if err := rows.Scan(&r.ID, &r.PlanID, &r.PlanHash, &r.Decision, &r.Actor, &r.Reason, &createdAt); err != nil {
			return nil, fmt.Errorf("scan approval: %w", err)
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, r)
	}
	return out, rows.Err()
}
