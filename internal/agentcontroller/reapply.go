package agentcontroller

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kjelly/pilot/internal/repair"
)

// R2 reapply plan state machine values — same shape as R1's (design doc
// §12: "An R1 approval cannot authorize R2"), but persisted in its own
// table so the two can never be confused at the storage layer either.
const (
	ReapplyPlanStateProposed  = "PROPOSED"
	ReapplyPlanStateApproved  = "APPROVED"
	ReapplyPlanStateRejected  = "REJECTED"
	ReapplyPlanStateExpired   = "EXPIRED"
	ReapplyPlanStateExecuting = "EXECUTING"
)

// StoredReapplyPlan mirrors one reapply_plans row.
type StoredReapplyPlan struct {
	ID                       string
	IncidentID               string
	Host                     string
	Component                string
	Action                   string
	Risk                     string
	PlaybookPath             string
	PlaybookHash             string
	Stage                    string
	ResolvedInputKeys        []string
	SecretReferenceKeys      []string
	DependencySnapshot       []repair.DependencyStatus
	PreviewRef               string
	PreviewSupported         bool
	PreviewSummary           string
	PreviewEstimatedChanged  int
	PreviewUnsupportedReason string
	VerificationSpec         string
	InventoryRevision        string
	ContractHash             string
	PlanHash                 string
	State                    string
	CreatedAt                time.Time
	ExpiresAt                time.Time
}

func (p StoredReapplyPlan) Expired(now time.Time) bool { return now.After(p.ExpiresAt) }

func marshalJSONList(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// CreateReapplyPlan persists a repair.ReapplyPlan (already resolved
// server-side by internal/repair.BuildReapplyPlan — this function never
// re-derives or second-guesses any field) as PROPOSED.
func (s *Store) CreateReapplyPlan(p repair.ReapplyPlan) error {
	_, err := s.db.Exec(`
		INSERT INTO reapply_plans (
			id, incident_id, host, component, action, risk, playbook_path, playbook_hash, stage,
			resolved_input_keys_json, secret_reference_keys_json, dependency_snapshot_json,
			preview_ref, preview_supported, preview_summary, preview_estimated_changed, preview_unsupported_reason,
			verification_spec, inventory_revision, contract_hash, plan_hash, state, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, p.ID, p.IncidentID, p.Host, p.Component, p.Action, p.Risk, p.Resolved.PlaybookPath, p.Resolved.PlaybookHash, p.Resolved.Stage,
		marshalJSONList(p.Resolved.ResolvedInputKeys), marshalJSONList(p.Resolved.SecretReferenceKeys), marshalJSONList(p.Resolved.DependencySnapshot),
		p.Resolved.PreviewRef, p.Resolved.PreviewSupported, p.Resolved.PreviewSummary, p.Resolved.PreviewEstimatedChanged, p.Resolved.PreviewUnsupportedReason,
		p.VerificationSpec, p.InventoryRevision, p.ContractHash, p.PlanHash, ReapplyPlanStateProposed, rfc3339(p.CreatedAt), rfc3339(p.ExpiresAt))
	if err != nil {
		return fmt.Errorf("create reapply plan: %w", err)
	}
	return nil
}

func scanReapplyPlan(row interface {
	Scan(dest ...any) error
}) (*StoredReapplyPlan, error) {
	var p StoredReapplyPlan
	var resolvedJSON, secretJSON, depJSON, createdAt, expiresAt string
	if err := row.Scan(&p.ID, &p.IncidentID, &p.Host, &p.Component, &p.Action, &p.Risk, &p.PlaybookPath, &p.PlaybookHash, &p.Stage,
		&resolvedJSON, &secretJSON, &depJSON,
		&p.PreviewRef, &p.PreviewSupported, &p.PreviewSummary, &p.PreviewEstimatedChanged, &p.PreviewUnsupportedReason,
		&p.VerificationSpec, &p.InventoryRevision, &p.ContractHash, &p.PlanHash, &p.State, &createdAt, &expiresAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(resolvedJSON), &p.ResolvedInputKeys)
	_ = json.Unmarshal([]byte(secretJSON), &p.SecretReferenceKeys)
	_ = json.Unmarshal([]byte(depJSON), &p.DependencySnapshot)
	p.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	p.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	return &p, nil
}

const reapplyPlanSelectColumns = `id, incident_id, host, component, action, risk, playbook_path, playbook_hash, stage,
	resolved_input_keys_json, secret_reference_keys_json, dependency_snapshot_json,
	preview_ref, preview_supported, COALESCE(preview_summary, ''), preview_estimated_changed, COALESCE(preview_unsupported_reason, ''),
	verification_spec, inventory_revision, contract_hash, plan_hash, state, created_at, expires_at`

// GetReapplyPlan returns one plan by ID, or nil if it does not exist.
func (s *Store) GetReapplyPlan(id string) (*StoredReapplyPlan, error) {
	row := s.db.QueryRow(`SELECT `+reapplyPlanSelectColumns+` FROM reapply_plans WHERE id = ?`, id)
	p, err := scanReapplyPlan(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get reapply plan %s: %w", id, err)
	}
	return p, nil
}

func (s *Store) expireReapplyIfPastDeadline(p *StoredReapplyPlan, now time.Time) error {
	if p.State != ReapplyPlanStateProposed && p.State != ReapplyPlanStateApproved {
		return nil
	}
	if !p.Expired(now) {
		return nil
	}
	if _, err := s.db.Exec(`UPDATE reapply_plans SET state = ? WHERE id = ? AND state = ?`,
		ReapplyPlanStateExpired, p.ID, p.State); err != nil {
		return fmt.Errorf("expire reapply plan %s: %w", p.ID, err)
	}
	p.State = ReapplyPlanStateExpired
	return nil
}

// MarkReapplyExecuting transitions an APPROVED plan to EXECUTING — the
// ONLY entry point into execution, mirroring MarkExecuting's own R1
// invariants exactly (re-checks expiry first; requires State ==
// APPROVED exactly; a concurrent state change loses the race safely).
func (s *Store) MarkReapplyExecuting(planID string, now time.Time) (StoredReapplyPlan, error) {
	p, err := s.GetReapplyPlan(planID)
	if err != nil {
		return StoredReapplyPlan{}, err
	}
	if p == nil {
		return StoredReapplyPlan{}, fmt.Errorf("reapply plan %s not found", planID)
	}
	if err := s.expireReapplyIfPastDeadline(p, now); err != nil {
		return StoredReapplyPlan{}, err
	}
	if p.State != ReapplyPlanStateApproved {
		return StoredReapplyPlan{}, fmt.Errorf("reapply plan %s is %s, not APPROVED — cannot execute", planID, p.State)
	}
	res, err := s.db.Exec(`UPDATE reapply_plans SET state = ? WHERE id = ? AND state = ?`,
		ReapplyPlanStateExecuting, planID, ReapplyPlanStateApproved)
	if err != nil {
		return StoredReapplyPlan{}, fmt.Errorf("mark reapply plan %s executing: %w", planID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return StoredReapplyPlan{}, fmt.Errorf("reapply plan %s state changed concurrently — refusing to execute", planID)
	}
	p.State = ReapplyPlanStateExecuting
	return *p, nil
}

// FinishReapplyRun records the terminal outcome of exactly one execution
// attempt — the unique index on reapply_runs(plan_id) makes a SECOND
// call for the same plan fail at the DB level, same structural replay
// guarantee R1's FinishRun already has.
func (s *Store) FinishReapplyRun(planID, result string, changed int, auditRef, verifyRef string, startedAt, finishedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin finish reapply run: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	runID := uuid.NewString()
	if _, execErr := tx.Exec(`
		INSERT INTO reapply_runs (id, plan_id, started_at, finished_at, result, changed, audit_ref, verify_ref)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, runID, planID, rfc3339(startedAt), rfc3339(finishedAt), result, changed, auditRef, verifyRef); execErr != nil {
		err = fmt.Errorf("insert reapply_run: %w", execErr)
		return err
	}
	if _, execErr := tx.Exec(`UPDATE reapply_plans SET state = ? WHERE id = ? AND state = ?`,
		result, planID, ReapplyPlanStateExecuting); execErr != nil {
		err = fmt.Errorf("update reapply plan %s to terminal state: %w", planID, execErr)
		return err
	}
	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit finish reapply run: %w", commitErr)
		return err
	}
	return nil
}

// RecoverOrphanedExecutingReapplyPlans mirrors
// RecoverOrphanedExecutingPlans exactly, for the R2 table family — see
// that function's own doc comment for the full reasoning (single
// controller process, no lease-timestamp arithmetic, outcome recorded
// as a distinct never-successful terminal state since the interrupted
// canonical apply's real effect is unknown).
func (s *Store) RecoverOrphanedExecutingReapplyPlans(now time.Time) (recovered int, err error) {
	rows, queryErr := s.db.Query(`SELECT id FROM reapply_plans WHERE state = ?`, ReapplyPlanStateExecuting)
	if queryErr != nil {
		return 0, fmt.Errorf("query executing reapply plans: %w", queryErr)
	}
	var ids []string
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr != nil {
			rows.Close()
			return 0, fmt.Errorf("scan executing reapply plan: %w", scanErr)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}

	for _, id := range ids {
		if finishErr := s.FinishReapplyRun(id, repair.ReapplyApplyFailedPartial, -1, "", "recovered: orphaned EXECUTING plan after unclean shutdown — outcome unknown", now, now); finishErr != nil {
			return recovered, fmt.Errorf("recover orphaned reapply plan %s: %w", id, finishErr)
		}
		recovered++
	}
	return recovered, nil
}
