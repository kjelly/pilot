package store

import "database/sql"

// DecommissionPlanRecord is the persisted row shape for one host
// decommission plan (spec.md §9.1). PlanJSON carries the full domain
// internal/decommission.Plan as an opaque JSON blob -- this package
// deliberately has no domain import (see host_decommission_plans' schema
// comment in sqlite.go), so it never inspects PlanJSON's contents; the
// scalar fields duplicate the handful of columns callers need to
// list/filter without deserializing it. CreatedAt/ExpiresAt/CompletedAt are
// plain RFC3339Nano strings, not time.Time -- the domain layer
// (internal/decommission) already formats them once and this layer never
// needs to compute with them, only store and return them verbatim.
type DecommissionPlanRecord struct {
	ID                string
	Host              string
	FQDN              string
	Environment       string
	Status            string
	PlanHash          string
	InventoryRevision string
	PlanJSON          string
	CreatedAt         string
	ExpiresAt         string
	CompletedAt       string // "" means NULL
}

// SaveDecommissionPlan inserts or replaces the plan row keyed by rec.ID --
// plans are not append-only (re-planning the same workspace/host commonly
// re-derives the same ID's row via a fresh `plan` invocation... in
// practice each Plan() call mints a new ID, but callers that persist an
// already-known ID, e.g. a resumed CLI invocation, still overwrite in
// place rather than erroring on conflict).
func (s *Store) SaveDecommissionPlan(rec DecommissionPlanRecord) error {
	_, err := s.db.Exec(
		`INSERT INTO host_decommission_plans
		 (id, host, fqdn, environment, status, plan_hash, inventory_revision, plan_json, created_at, expires_at, completed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		     host=excluded.host, fqdn=excluded.fqdn, environment=excluded.environment,
		     status=excluded.status, plan_hash=excluded.plan_hash, inventory_revision=excluded.inventory_revision,
		     plan_json=excluded.plan_json, expires_at=excluded.expires_at, completed_at=excluded.completed_at`,
		rec.ID, rec.Host, rec.FQDN, rec.Environment, rec.Status, rec.PlanHash, rec.InventoryRevision,
		rec.PlanJSON, rec.CreatedAt, rec.ExpiresAt, nullableString(rec.CompletedAt),
	)
	return err
}

// GetDecommissionPlan reads back one plan row by id.
func (s *Store) GetDecommissionPlan(id string) (*DecommissionPlanRecord, error) {
	row := s.db.QueryRow(
		`SELECT id, host, fqdn, environment, status, plan_hash, inventory_revision, plan_json, created_at, expires_at, completed_at
		 FROM host_decommission_plans WHERE id = ?`, id)
	var rec DecommissionPlanRecord
	var completedAt sql.NullString
	if err := row.Scan(&rec.ID, &rec.Host, &rec.FQDN, &rec.Environment, &rec.Status, &rec.PlanHash, &rec.InventoryRevision, &rec.PlanJSON, &rec.CreatedAt, &rec.ExpiresAt, &completedAt); err != nil {
		return nil, err
	}
	rec.CompletedAt = completedAt.String
	return &rec, nil
}

// DecommissionStepRecord is one persisted step row. No writer exists yet in
// Phase 1 (no executor); ListDecommissionSteps exists now so `show` and the
// Phase 2+ executor share one read path from day one.
type DecommissionStepRecord struct {
	ID, PlanID                                                string
	Seq                                                       int
	Component, Provider, Phase, Action, TargetIdentity, State string
	Attempts                                                  int
	StartedAt, FinishedAt, ErrorClass, ErrorText, ResultJSON  string
}

// ListDecommissionSteps returns every persisted step for planID, in seq
// order.
func (s *Store) ListDecommissionSteps(planID string) ([]DecommissionStepRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, plan_id, seq, component, provider, phase, action, target_identity, state, attempts, started_at, finished_at, error_class, error_text, result_json
		 FROM host_decommission_steps WHERE plan_id = ? ORDER BY seq`, planID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []DecommissionStepRecord
	for rows.Next() {
		var st DecommissionStepRecord
		var started, finished, errClass, errText, resultJSON sql.NullString
		if err := rows.Scan(&st.ID, &st.PlanID, &st.Seq, &st.Component, &st.Provider, &st.Phase, &st.Action, &st.TargetIdentity, &st.State, &st.Attempts, &started, &finished, &errClass, &errText, &resultJSON); err != nil {
			return nil, err
		}
		st.StartedAt, st.FinishedAt, st.ErrorClass, st.ErrorText, st.ResultJSON = started.String, finished.String, errClass.String, errText.String, resultJSON.String
		out = append(out, st)
	}
	return out, rows.Err()
}

// RecordDecommissionApproval persists one approval decision bound to
// EXACTLY (planID, planHash) -- spec.md §30: an approval never carries over
// to a changed plan.
func (s *Store) RecordDecommissionApproval(id, planID, planHash, actor, decision, reason, createdAt string) error {
	_, err := s.db.Exec(
		`INSERT INTO host_decommission_approvals (id, plan_id, plan_hash, actor, decision, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, planID, planHash, actor, decision, reason, createdAt,
	)
	return err
}

// ApprovalForPlanHash reports the most recent approval decision recorded
// for EXACTLY (planID, planHash) -- HD27: a changed plan_hash means no row
// matches here, even though older approvals for the same plan_id exist.
func (s *Store) ApprovalForPlanHash(planID, planHash string) (decision string, found bool, err error) {
	row := s.db.QueryRow(
		`SELECT decision FROM host_decommission_approvals WHERE plan_id = ? AND plan_hash = ? ORDER BY created_at DESC, id DESC LIMIT 1`,
		planID, planHash,
	)
	if err := row.Scan(&decision); err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}
	return decision, true, nil
}

// SaveRetiredHost records the finalization retirement marker (spec.md §22).
// No finalizer calls this yet in Phase 1 -- the method exists for Phase 2.
func (s *Store) SaveRetiredHost(host, fqdn, decommissionID, reason, retiredAt, finalInventoryRevision string) error {
	_, err := s.db.Exec(
		`INSERT INTO retired_hosts (host, fqdn, decommission_id, reason, retired_at, final_inventory_revision) VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(host) DO UPDATE SET fqdn=excluded.fqdn, decommission_id=excluded.decommission_id, reason=excluded.reason, retired_at=excluded.retired_at, final_inventory_revision=excluded.final_inventory_revision`,
		host, fqdn, decommissionID, reason, retiredAt, finalInventoryRevision,
	)
	return err
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
