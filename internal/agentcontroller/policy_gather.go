// policy_gather.go assembles a live policy.PolicyInput from durable
// store state (design doc §5's "IO that gathers history/current alert
// state is outside [EvaluatePolicy]"). Every function here is read-only
// except RecordPolicyDecision, which persists EvaluatePolicy's own
// output — the ONE piece of IO the pure decision core in internal/policy
// deliberately excludes.
//
// Budget/cooldown counts are DERIVED from approvals+remediation_plans
// rather than a separate ledger table (see store.go's schemaV3 doc
// comment) — every count below only ever reads rows that Store.Approve
// already wrote inside its own transaction, so there is no second
// "reservation" step that could itself crash independently of the
// approval it is supposed to represent.
package agentcontroller

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PolicyDecisionRecord is one policy_decisions row (design doc §11).
type PolicyDecisionRecord struct {
	ID            string
	IncidentID    string
	PlanID        string
	PlanHash      string
	Decision      string
	PolicyID      string
	PolicyVersion string
	ReasonsJSON   string
	Mode          string
	CreatedAt     time.Time
}

// RecordPolicyDecision persists a policy evaluation BEFORE any execution
// is attempted (design doc §12 step 6) — this is the "persist the
// decision" half of "Budget reservation + decision persistence must
// happen atomically before repair call" (§11); the "budget reservation"
// half is Store.Approve's own transaction, called separately by the
// caller immediately after this when decision == allow_auto.
func (s *Store) RecordPolicyDecision(incidentID, planID, planHash, decision, policyID, policyVersion, reasonsJSON, mode string, now time.Time) (PolicyDecisionRecord, error) {
	id := uuid.NewString()
	if _, err := s.db.Exec(`
		INSERT INTO policy_decisions (id, incident_id, plan_id, plan_hash, decision, policy_id, policy_version, reasons_json, mode, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, incidentID, planID, planHash, decision, policyID, policyVersion, reasonsJSON, mode, rfc3339(now)); err != nil {
		return PolicyDecisionRecord{}, fmt.Errorf("record policy decision: %w", err)
	}
	return PolicyDecisionRecord{ID: id, IncidentID: incidentID, PlanID: planID, PlanHash: planHash, Decision: decision,
		PolicyID: policyID, PolicyVersion: policyVersion, ReasonsJSON: reasonsJSON, Mode: mode, CreatedAt: now}, nil
}

// ListPolicyDecisions returns every decision recorded for planID, in
// chronological order.
func (s *Store) ListPolicyDecisions(planID string) ([]PolicyDecisionRecord, error) {
	rows, err := s.db.Query(`
		SELECT id, incident_id, plan_id, plan_hash, decision, policy_id, policy_version, reasons_json, mode, created_at
		FROM policy_decisions WHERE plan_id = ? ORDER BY created_at ASC
	`, planID)
	if err != nil {
		return nil, fmt.Errorf("list policy decisions for %s: %w", planID, err)
	}
	defer rows.Close()
	var out []PolicyDecisionRecord
	for rows.Next() {
		var r PolicyDecisionRecord
		var createdAt string
		if err := rows.Scan(&r.ID, &r.IncidentID, &r.PlanID, &r.PlanHash, &r.Decision, &r.PolicyID, &r.PolicyVersion, &r.ReasonsJSON, &r.Mode, &createdAt); err != nil {
			return nil, fmt.Errorf("scan policy decision: %w", err)
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

// policyActorPrefix marks an approval as policy-originated rather than
// human — Store.Approve's actor argument, not a separate column, is the
// single source of truth for "was this decision human or autonomous"
// (design doc §3's unified execution path: policy and human approval
// are the SAME Approve call, differing only in actor identity).
const policyActorPrefix = "policy:"

// PolicyActor formats the actor string an autonomous approval records —
// always this, never raw operator text, so ListApprovals/audit queries
// can distinguish policy-originated approvals from human ones by a
// simple prefix check.
func PolicyActor(policyID, decisionID string) string {
	return policyActorPrefix + policyID + ":" + decisionID
}

// LastActionAt returns the most recent APPROVED time for this exact
// (host, component, action) tuple, across ANY actor (human or policy) —
// cooldown exists to protect the TARGET from repeated repair attempts in
// quick succession, not specifically to throttle autonomy, so a human's
// recent approval starts the same cooldown an autonomous one would.
func (s *Store) LastActionAt(host, component, action string) (*time.Time, error) {
	var createdAt string
	err := s.db.QueryRow(`
		SELECT a.created_at FROM approvals a
		JOIN remediation_plans p ON p.id = a.plan_id
		WHERE p.host = ? AND p.component = ? AND p.action = ? AND a.decision = ?
		ORDER BY a.created_at DESC LIMIT 1
	`, host, component, action, ApprovalDecisionApproved).Scan(&createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("last action at for %s/%s/%s: %w", host, component, action, err)
	}
	t, perr := time.Parse(time.RFC3339, createdAt)
	if perr != nil {
		return nil, fmt.Errorf("parse last action time: %w", perr)
	}
	return &t, nil
}

// CountApprovedActionsForHost counts APPROVED plans for host since a
// given time — the host budget guard's input (design doc §7).
func (s *Store) CountApprovedActionsForHost(host string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM approvals a
		JOIN remediation_plans p ON p.id = a.plan_id
		WHERE p.host = ? AND a.decision = ? AND a.created_at >= ?
	`, host, ApprovalDecisionApproved, rfc3339(since)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count approved actions for host %s: %w", host, err)
	}
	return n, nil
}

// CountApprovedActionsForComponent counts APPROVED plans for component
// since a given time — the component budget guard's input (design doc
// §7).
func (s *Store) CountApprovedActionsForComponent(component string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM approvals a
		JOIN remediation_plans p ON p.id = a.plan_id
		WHERE p.component = ? AND a.decision = ? AND a.created_at >= ?
	`, component, ApprovalDecisionApproved, rfc3339(since)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count approved actions for component %s: %w", component, err)
	}
	return n, nil
}

// CountPolicyRunsForIncident counts every AUTONOMOUS (policy-actor)
// execution attempt ever recorded for incidentID, regardless of
// outcome — design doc §7 "max auto R1 per incident episode: 1" and
// guard 10 "incident episode has no prior failed autonomous repair" are
// the SAME check: any prior autonomous attempt, successful or not,
// already consumed this episode's one auto-repair budget. A human may
// still approve as many further attempts as they choose; only the
// AUTONOMOUS count is capped here.
func (s *Store) CountPolicyRunsForIncident(incidentID string) (int, error) {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM remediation_runs r
		JOIN remediation_plans p ON p.id = r.plan_id
		JOIN approvals a ON a.plan_id = p.id AND a.decision = ?
		WHERE p.incident_id = ? AND a.actor LIKE ?
	`, ApprovalDecisionApproved, incidentID, policyActorPrefix+"%").Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count policy runs for incident %s: %w", incidentID, err)
	}
	return n, nil
}

// HasHumanRejection reports whether a genuine HUMAN (never a policy
// actor) has ever rejected a plan targeting this exact
// (host, component, action) tuple — across any plan ID, since a fresh
// re-propose after rejection gets a new plan ID but represents the same
// remediation a human already said no to (design doc guard 13: "no
// human rejection exists").
func (s *Store) HasHumanRejection(host, component, action string) (bool, error) {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM approvals a
		JOIN remediation_plans p ON p.id = a.plan_id
		WHERE p.host = ? AND p.component = ? AND p.action = ? AND a.decision = ? AND a.actor NOT LIKE ?
	`, host, component, action, ApprovalDecisionRejected, policyActorPrefix+"%").Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check human rejection for %s/%s/%s: %w", host, component, action, err)
	}
	return n > 0, nil
}

// HealthCheck is a lightweight probe for guard 14 ("audit DB/change
// journal writable") — PRAGMA integrity_check both confirms the
// database file is readable AND, on a corrupt/read-only file, is where
// SQLite surfaces that fact, without this function needing to perform
// (and then roll back) a real write of its own.
func (s *Store) HealthCheck() bool {
	result, err := s.IntegrityCheck()
	return err == nil && result == "ok"
}
