package agentcontroller

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ReapplyApprovalRecord is one human decision on one R2 plan — binds to
// (PlanID, PlanHash) together, exactly like R1's ApprovalRecord (design
// doc §12: an approval can never be reinterpreted as covering a plan
// whose executable content — including its dependency snapshot and
// preview — changed after the human looked at it). There is
// deliberately no policy-actor variant of this function anywhere in
// this package — R2 is always human-approved, in every environment
// (design doc §12), enforced here by simply never having built an
// auto-approve entry point, not by a runtime flag that could be
// misconfigured.
type ReapplyApprovalRecord struct {
	ID        string
	PlanID    string
	PlanHash  string
	Decision  string
	Actor     string
	Reason    string
	CreatedAt time.Time
}

// ApproveReapply records human approval and transitions a PROPOSED R2
// plan to APPROVED. actor MUST come from trusted operator context — the
// CLI caller's own identity, never Agent-supplied text.
func (s *Store) ApproveReapply(planID, planHash, actor, reason string, now time.Time) (ReapplyApprovalRecord, error) {
	return s.recordReapplyApprovalDecision(planID, planHash, ApprovalDecisionApproved, actor, reason, ReapplyPlanStateApproved, now)
}

// RejectReapply records human rejection and transitions a PROPOSED R2
// plan to REJECTED — terminal; propose a new plan instead of
// reconsidering this one.
func (s *Store) RejectReapply(planID, planHash, actor, reason string, now time.Time) (ReapplyApprovalRecord, error) {
	return s.recordReapplyApprovalDecision(planID, planHash, ApprovalDecisionRejected, actor, reason, ReapplyPlanStateRejected, now)
}

func (s *Store) recordReapplyApprovalDecision(planID, planHash, decision, actor, reason, nextState string, now time.Time) (ReapplyApprovalRecord, error) {
	if actor == "" {
		return ReapplyApprovalRecord{}, fmt.Errorf("actor is required — approval must come from trusted operator context")
	}
	p, err := s.GetReapplyPlan(planID)
	if err != nil {
		return ReapplyApprovalRecord{}, err
	}
	if p == nil {
		return ReapplyApprovalRecord{}, fmt.Errorf("reapply plan %s not found", planID)
	}
	if err := s.expireReapplyIfPastDeadline(p, now); err != nil {
		return ReapplyApprovalRecord{}, err
	}
	if p.State != ReapplyPlanStateProposed {
		return ReapplyApprovalRecord{}, fmt.Errorf("reapply plan %s is %s, not PROPOSED — cannot record a decision", planID, p.State)
	}
	if p.PlanHash != planHash {
		return ReapplyApprovalRecord{}, fmt.Errorf("plan hash mismatch for %s — approval must bind to the exact current plan hash (got %s, plan is %s)", planID, planHash, p.PlanHash)
	}

	rec := ReapplyApprovalRecord{ID: uuid.NewString(), PlanID: planID, PlanHash: planHash, Decision: decision, Actor: actor, Reason: reason, CreatedAt: now}

	tx, err := s.db.Begin()
	if err != nil {
		return ReapplyApprovalRecord{}, fmt.Errorf("begin reapply approval: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	if _, execErr := tx.Exec(`
		INSERT INTO reapply_approvals (id, plan_id, plan_hash, decision, actor, reason, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, rec.ID, rec.PlanID, rec.PlanHash, rec.Decision, rec.Actor, rec.Reason, rfc3339(rec.CreatedAt)); execErr != nil {
		err = fmt.Errorf("insert reapply approval: %w", execErr)
		return ReapplyApprovalRecord{}, err
	}
	res, execErr := tx.Exec(`UPDATE reapply_plans SET state = ? WHERE id = ? AND state = ?`, nextState, planID, ReapplyPlanStateProposed)
	if execErr != nil {
		err = fmt.Errorf("update reapply plan %s state: %w", planID, execErr)
		return ReapplyApprovalRecord{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		err = fmt.Errorf("reapply plan %s state changed concurrently — refusing to record decision", planID)
		return ReapplyApprovalRecord{}, err
	}
	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit reapply approval: %w", commitErr)
		return ReapplyApprovalRecord{}, err
	}
	return rec, nil
}

// ListReapplyApprovals returns every approval decision recorded for
// planID, in chronological order.
func (s *Store) ListReapplyApprovals(planID string) ([]ReapplyApprovalRecord, error) {
	rows, err := s.db.Query(`
		SELECT id, plan_id, plan_hash, decision, actor, COALESCE(reason, ''), created_at
		FROM reapply_approvals WHERE plan_id = ? ORDER BY created_at ASC
	`, planID)
	if err != nil {
		return nil, fmt.Errorf("list reapply approvals for %s: %w", planID, err)
	}
	defer rows.Close()
	var out []ReapplyApprovalRecord
	for rows.Next() {
		var r ReapplyApprovalRecord
		var createdAt string
		if err := rows.Scan(&r.ID, &r.PlanID, &r.PlanHash, &r.Decision, &r.Actor, &r.Reason, &createdAt); err != nil {
			return nil, fmt.Errorf("scan reapply approval: %w", err)
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, r)
	}
	return out, rows.Err()
}
