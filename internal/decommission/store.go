package decommission

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/kjelly/pilot/internal/store"
)

// Store persists decommission plans/approvals through Pilot's general
// SQLite delivery/evidence store (spec.md §9) -- deliberately NOT
// internal/agentcontroller, since host lifecycle is a core Pilot concern
// that must function without Agent Controller deployed.
type Store struct {
	db *store.Store
}

// NewStore wraps an already-opened *store.Store.
func NewStore(db *store.Store) *Store {
	return &Store{db: db}
}

// secretLikeKeyPattern matches host Extra/var key names that must never be
// persisted verbatim in a decommission plan/step/approval/receipt record
// (spec.md §9.2/§31.1). This is a structural belt-and-suspenders check:
// the Phase 1 Plan model carries no raw secret VALUE at all (only
// non-secret host/contract/reference data) -- but a future field addition
// that reused a secret-shaped key name is caught here at encode time
// instead of shipping silently. Mirrors the same secret/vault-like naming
// convention contracts already use (contract.GroupVar.Secret) and the
// pattern real vault-backed vars in this repo follow (e.g.
// ipa_admin_password, keycloak_db_password).
var secretLikeKeyPattern = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|vault|credential)`)

// ErrSecretLikeField is returned by EncodePlanJSON when the plan's host
// snapshot Extra map (or any other persisted string-keyed map added later)
// contains a key name that looks like a secret -- persisting it verbatim
// would violate spec.md §9.2's "never persist secret values" rule.
var ErrSecretLikeField = errors.New("decommission: refusing to persist a secret-shaped field")

// EncodePlanJSON serializes plan for persistence, refusing (fail-closed)
// to encode at all if any host Extra key looks secret-shaped.
func EncodePlanJSON(plan *Plan) (string, error) {
	for k := range plan.Host.Extra {
		if secretLikeKeyPattern.MatchString(k) {
			return "", fmt.Errorf("%w: host Extra key %q", ErrSecretLikeField, k)
		}
	}
	b, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("encode plan %s: %w", plan.ID, err)
	}
	return string(b), nil
}

// SavePlan persists plan, keyed by plan.ID. Re-saving the same ID
// overwrites in place -- plans are not append-only.
func (s *Store) SavePlan(plan *Plan) error {
	payload, err := EncodePlanJSON(plan)
	if err != nil {
		return err
	}
	return s.db.SaveDecommissionPlan(store.DecommissionPlanRecord{
		ID: plan.ID, Host: plan.Host.Name, FQDN: plan.Host.AnsibleHost, Environment: plan.Environment,
		Status: string(plan.Status), PlanHash: plan.PlanHash, InventoryRevision: plan.InventoryRevision,
		PlanJSON: payload, CreatedAt: plan.CreatedAt, ExpiresAt: plan.ExpiresAt,
	})
}

// LoadPlan reads back a plan persisted by SavePlan.
func (s *Store) LoadPlan(id string) (*Plan, error) {
	rec, err := s.db.GetDecommissionPlan(id)
	if err != nil {
		return nil, err
	}
	var plan Plan
	if err := json.Unmarshal([]byte(rec.PlanJSON), &plan); err != nil {
		return nil, fmt.Errorf("decode persisted plan %s: %w", id, err)
	}
	return &plan, nil
}

// RecordApproval persists an approval bound to EXACTLY (planID, planHash)
// (spec.md §30) -- a later changed plan hash invalidates it (HD27).
func (s *Store) RecordApproval(planID, planHash, actor, decision, reason string, now time.Time) error {
	return s.db.RecordDecommissionApproval(newApprovalID(), planID, planHash, actor, decision, reason, now.Format(time.RFC3339Nano))
}

// ApprovedForHash reports whether the most recent approval recorded for
// planID at EXACTLY planHash was an "approve" decision. A prior approval
// recorded against a different (now-stale) plan_hash never counts, even
// for the same plan_id.
func (s *Store) ApprovedForHash(planID, planHash string) (bool, error) {
	decision, found, err := s.db.ApprovalForPlanHash(planID, planHash)
	if err != nil {
		return false, err
	}
	return found && decision == "approve", nil
}

// SaveRetiredHost writes the retirement marker (spec.md §22/§23 step 9) —
// Finalize's only write beyond the plan row itself on success.
func (s *Store) SaveRetiredHost(host, fqdn, decommissionID, reason string, retiredAt time.Time, finalInventoryRevision string) error {
	return s.db.SaveRetiredHost(host, fqdn, decommissionID, reason, retiredAt.Format(time.RFC3339Nano), finalInventoryRevision)
}
