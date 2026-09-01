package agentcontroller

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kjelly/pilot/internal/repair"
)

// Remediation plan state machine values (Agent Monitoring Phase 3 §10),
// extended with the two terminal outcomes spec §9's result enum adds
// beyond the bare state-machine diagram (APPLIED_ALERT_STILL_FIRING is
// still a FAILURE outcome — "a resolved alert with failed verification
// is still remediation failure" cuts the other way too: a passing
// verification with the alert still firing is not a clean success
// either).
const (
	PlanStateProposed                 = "PROPOSED"
	PlanStateApproved                 = "APPROVED"
	PlanStateRejected                 = "REJECTED"
	PlanStateExpired                  = "EXPIRED"
	PlanStateStale                    = "STALE"
	PlanStateExecuting                = "EXECUTING"
	PlanStateAppliedVerified          = "APPLIED_VERIFIED"
	PlanStateAppliedAlertStillFiring  = "APPLIED_ALERT_STILL_FIRING"
	PlanStateExecutionFailed          = "EXECUTION_FAILED"
	PlanStateVerificationFailed       = "VERIFICATION_FAILED"
	PlanStateVerificationInconclusive = "VERIFICATION_INCONCLUSIVE"
)

// StoredPlan mirrors one remediation_plans row.
type StoredPlan struct {
	ID                string
	IncidentID        string
	Host              string
	Component         string
	Action            string
	Risk              string
	ExecutorKind      string
	ExecutorTarget    string
	VerificationSpec  string
	InventoryRevision string
	ContractHash      string
	PlanHash          string
	State             string
	CreatedAt         time.Time
	ExpiresAt         time.Time
}

func (p StoredPlan) Expired(now time.Time) bool { return now.After(p.ExpiresAt) }

// CreatePlan persists a repair.Plan (already resolved server-side by
// internal/repair.BuildPlan — this function never re-derives or
// second-guesses any field) as PROPOSED.
func (s *Store) CreatePlan(p repair.Plan) error {
	_, err := s.db.Exec(`
		INSERT INTO remediation_plans (
			id, incident_id, host, component, action, risk, executor_kind, executor_target,
			verification_spec, inventory_revision, contract_hash, plan_hash, state, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, p.ID, p.IncidentID, p.Host, p.Component, p.Action, p.Risk, p.ExecutorKind, p.ExecutorTarget,
		p.VerificationSpec, p.InventoryRevision, p.ContractHash, p.PlanHash, PlanStateProposed,
		rfc3339(p.CreatedAt), rfc3339(p.ExpiresAt))
	if err != nil {
		return fmt.Errorf("create remediation plan: %w", err)
	}
	return nil
}

// GetPlan returns one plan by ID, or nil if it does not exist.
func (s *Store) GetPlan(id string) (*StoredPlan, error) {
	row := s.db.QueryRow(`
		SELECT id, incident_id, host, component, action, risk, executor_kind, executor_target,
			verification_spec, inventory_revision, contract_hash, plan_hash, state, created_at, expires_at
		FROM remediation_plans WHERE id = ?
	`, id)
	var p StoredPlan
	var createdAt, expiresAt string
	if err := row.Scan(&p.ID, &p.IncidentID, &p.Host, &p.Component, &p.Action, &p.Risk, &p.ExecutorKind, &p.ExecutorTarget,
		&p.VerificationSpec, &p.InventoryRevision, &p.ContractHash, &p.PlanHash, &p.State, &createdAt, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get plan %s: %w", id, err)
	}
	p.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	p.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	return &p, nil
}

// expireIfPastDeadline moves a still-open plan (PROPOSED/APPROVED) to
// EXPIRED when now is past its ExpiresAt — called at the top of every
// state-changing operation so an operator/controller action against a
// long-idle plan always sees an accurate, up-to-date state rather than a
// stale PROPOSED/APPROVED row that quietly can't actually be acted on
// anymore.
func (s *Store) expireIfPastDeadline(p *StoredPlan, now time.Time) error {
	if p.State != PlanStateProposed && p.State != PlanStateApproved {
		return nil
	}
	if !p.Expired(now) {
		return nil
	}
	if _, err := s.db.Exec(`UPDATE remediation_plans SET state = ? WHERE id = ? AND state = ?`,
		PlanStateExpired, p.ID, p.State); err != nil {
		return fmt.Errorf("expire plan %s: %w", p.ID, err)
	}
	p.State = PlanStateExpired
	return nil
}

// MarkExecuting transitions an APPROVED plan to EXECUTING — the ONLY
// entry point into execution. It re-checks expiry first (a plan
// approved long ago but never executed must not silently execute past
// its TTL) and requires State == APPROVED exactly, so a plan that is
// PROPOSED (never approved), REJECTED, or already EXECUTING/terminal
// can never enter execution from here.
func (s *Store) MarkExecuting(planID string, now time.Time) (StoredPlan, error) {
	p, err := s.GetPlan(planID)
	if err != nil {
		return StoredPlan{}, err
	}
	if p == nil {
		return StoredPlan{}, fmt.Errorf("plan %s not found", planID)
	}
	if err := s.expireIfPastDeadline(p, now); err != nil {
		return StoredPlan{}, err
	}
	if p.State != PlanStateApproved {
		return StoredPlan{}, fmt.Errorf("plan %s is %s, not APPROVED — cannot execute", planID, p.State)
	}
	res, err := s.db.Exec(`UPDATE remediation_plans SET state = ? WHERE id = ? AND state = ?`,
		PlanStateExecuting, planID, PlanStateApproved)
	if err != nil {
		return StoredPlan{}, fmt.Errorf("mark plan %s executing: %w", planID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Lost a race with a concurrent MarkExecuting/Approve/Reject —
		// safer to fail than to silently proceed on stale in-memory state.
		return StoredPlan{}, fmt.Errorf("plan %s state changed concurrently — refusing to execute", planID)
	}
	p.State = PlanStateExecuting
	return *p, nil
}

// FinishRun records the terminal outcome of exactly one execution
// attempt. The unique index on remediation_runs(plan_id) makes a SECOND
// call for the same plan fail at the DB level — "replay of an already
// executed approved plan must fail" (design doc §10) is a structural
// guarantee, not just a state check.
func (s *Store) FinishRun(planID, result, auditRef, verifyRef string, startedAt, finishedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin finish run: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	runID := uuid.NewString()
	if _, execErr := tx.Exec(`
		INSERT INTO remediation_runs (id, plan_id, started_at, finished_at, result, audit_ref, verify_ref)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, runID, planID, rfc3339(startedAt), rfc3339(finishedAt), result, auditRef, verifyRef); execErr != nil {
		err = fmt.Errorf("insert remediation_run: %w", execErr)
		return err
	}
	if _, execErr := tx.Exec(`UPDATE remediation_plans SET state = ? WHERE id = ? AND state = ?`,
		result, planID, PlanStateExecuting); execErr != nil {
		err = fmt.Errorf("update plan %s to terminal state: %w", planID, execErr)
		return err
	}
	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit finish run: %w", commitErr)
		return err
	}
	return nil
}

// RecoverOrphanedExecutingPlans closes out any plan left EXECUTING by an
// unclean controller shutdown — mirrors RecoverInFlightRuns' own
// reasoning exactly (no lease-timestamp arithmetic; this controller runs
// as a single process, so anything still EXECUTING at startup was
// definitely orphaned, never a live concurrent execution). The outcome
// of the interrupted ansible run is genuinely unknown — it may have
// mutated the host or not — so it is recorded as a distinct terminal
// state (never APPLIED_VERIFIED, which would wrongly claim success) via
// the SAME FinishRun path every other execution outcome goes through,
// which is what makes it correctly count against budgets/breakers and
// what makes remediation_runs' unique index permanently block any
// future MarkExecuting for the same plan_id (design doc §17.8: "restart
// controller -> budgets/breakers persist").
func (s *Store) RecoverOrphanedExecutingPlans(now time.Time) (recovered int, err error) {
	rows, queryErr := s.db.Query(`SELECT id FROM remediation_plans WHERE state = ?`, PlanStateExecuting)
	if queryErr != nil {
		return 0, fmt.Errorf("query executing plans: %w", queryErr)
	}
	var ids []string
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr != nil {
			rows.Close()
			return 0, fmt.Errorf("scan executing plan: %w", scanErr)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}

	for _, id := range ids {
		if finishErr := s.FinishRun(id, PlanStateExecutionFailed, "", "recovered: orphaned EXECUTING plan after unclean shutdown — outcome unknown", now, now); finishErr != nil {
			return recovered, fmt.Errorf("recover orphaned plan %s: %w", id, finishErr)
		}
		recovered++
	}
	return recovered, nil
}
