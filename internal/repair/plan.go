package repair

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/networkcheck"
)

// PlanTTL is how long a plan stays approvable/executable after creation
// (design doc §5: "expired ... inventory or contract rejects apply").
// Deliberately short — a plan is meant to be reviewed and acted on
// promptly, not held indefinitely as standing authorization.
const PlanTTL = 15 * time.Minute

// Plan is Agent Monitoring Phase 3's immutable RemediationPlan (design
// doc §5). Every field an execution actually depends on is covered by
// PlanHash — approval binds to (ID, PlanHash) together, so a plan whose
// executable content changed after approval can never silently execute
// under the old approval.
type Plan struct {
	SchemaVersion     int
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
	CreatedAt         time.Time
	ExpiresAt         time.Time
}

// Expired reports whether now is past p.ExpiresAt.
func (p Plan) Expired(now time.Time) bool { return now.After(p.ExpiresAt) }

// planHashFields is the exact, stable set of executable fields PlanHash
// covers — deliberately excludes ID/CreatedAt/ExpiresAt (bookkeeping,
// not executable content) so re-deriving the hash from a stored Plan at
// apply time is a pure function of what the plan actually DOES.
type planHashFields struct {
	SchemaVersion     int
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
}

func computeHash(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// contractHashFields is what ContractHash covers — the exact declared
// shape of the ONE remediation action this plan resolves against, not
// the whole contract file. If the contract's declaration of this action
// changes between plan and apply (executor retargeted, verification
// spec changed, risk changed), ContractHash — and therefore PlanHash —
// changes too, and BuildApplyPlan/VerifyPlanFresh below reject the stale
// plan rather than execute against a moved target.
type contractHashFields struct {
	ID               string
	Risk             string
	ExecutorKind     string
	ExecutorTarget   string
	MaxTargets       int
	RequiresApproval bool
	VerificationSpec string
}

func hashAction(a contract.RemediationAction) string {
	return computeHash(contractHashFields{
		ID: a.ID, Risk: a.Risk, ExecutorKind: a.Executor.Kind, ExecutorTarget: a.Executor.Target,
		MaxTargets: a.MaxTargets, RequiresApproval: a.RequiresApproval, VerificationSpec: a.Verification.Spec,
	})
}

// BuildPlan resolves an Agent's recommendation (incident ID + exact
// host + component + action ID — nothing else) into an immutable Plan.
// Every execution-relevant field is resolved HERE, server-side, from the
// contract and the current inventory — never taken from the caller
// (design doc §5: "executor target resolved from contract, never Agent
// input"). newPlanID is injected (not generated internally) so callers
// control ID generation/uniqueness (e.g. a caller already using
// google/uuid or a store-assigned ID) without this package taking on an
// ID-generation dependency of its own.
func BuildPlan(catalog contract.Catalog, resolved networkcheck.ResolvedInventory, newPlanID, incidentID, host, component, actionID string, now time.Time) (Plan, error) {
	if incidentID == "" {
		return Plan{}, fmt.Errorf("incident id is required")
	}
	if _, known := resolved.HostVars[host]; !known {
		return Plan{}, fmt.Errorf("host %q is not a known inventory host", host)
	}

	c, ok := catalog.Component(component)
	if !ok {
		return Plan{}, fmt.Errorf("unknown component %q", component)
	}

	assigned := false
	for _, h := range resolved.GroupHosts[c.Role] {
		if h == host {
			assigned = true
			break
		}
	}
	if !assigned {
		return Plan{}, fmt.Errorf("component %q is not assigned to host %q", component, host)
	}

	var action *contract.RemediationAction
	for i := range c.Remediation.Actions {
		if c.Remediation.Actions[i].ID == actionID {
			action = &c.Remediation.Actions[i]
			break
		}
	}
	if action == nil {
		return Plan{}, fmt.Errorf("component %q has no remediation action %q", component, actionID)
	}
	if action.Risk != "R1" {
		return Plan{}, fmt.Errorf("action %q is risk %s — Phase 3 only plans R1 actions", actionID, action.Risk)
	}
	if action.MaxTargets != 1 {
		return Plan{}, fmt.Errorf("action %q has maxTargets=%d — Phase 3 requires exactly 1", actionID, action.MaxTargets)
	}

	addr := resolved.HostAddr(host)
	if addr == "" {
		addr = host
	}
	inventoryRevision := computeHash(struct{ Host, Addr string }{Host: host, Addr: addr})
	contractHash := hashAction(*action)

	p := Plan{
		SchemaVersion: 1, ID: newPlanID, IncidentID: incidentID, Host: host, Component: component,
		Action: actionID, Risk: action.Risk, ExecutorKind: action.Executor.Kind, ExecutorTarget: action.Executor.Target,
		VerificationSpec: action.Verification.Spec, InventoryRevision: inventoryRevision, ContractHash: contractHash,
		CreatedAt: now, ExpiresAt: now.Add(PlanTTL),
	}
	p.PlanHash = computeHash(planHashFields{
		SchemaVersion: p.SchemaVersion, IncidentID: p.IncidentID, Host: p.Host, Component: p.Component,
		Action: p.Action, Risk: p.Risk, ExecutorKind: p.ExecutorKind, ExecutorTarget: p.ExecutorTarget,
		VerificationSpec: p.VerificationSpec, InventoryRevision: p.InventoryRevision, ContractHash: p.ContractHash,
	})
	return p, nil
}

// VerifyPlanFresh re-derives a Plan from the CURRENT catalog/inventory
// (using ONLY p's identity fields — ID/IncidentID/Host/Component/
// Action, never its executor/verification/hash fields) and returns that
// FRESH plan when it still matches p's recorded PlanHash — the
// apply-time gate design doc §5 requires ("expired/stale inventory or
// contract rejects apply").
//
// Callers MUST execute using the RETURNED plan, never the caller-
// supplied p, even after a nil error. Reason: p arrives over the wire
// (an MCP tool argument) and its ExecutorKind/ExecutorTarget/
// VerificationSpec fields are only ever DISPLAY/AUDIT copies — nothing
// stops a tampered p from changing one of them while leaving PlanHash
// untouched. Comparing hashes tells you "this identity still resolves
// to the same plan it did at creation time" — it does NOT tell you that
// p's own executor fields are what the hash actually covers. Executing
// against the freshly-REBUILT plan (whose executor fields come straight
// from today's contract, exactly like BuildPlan's original resolution)
// closes that gap by construction: a tampered ExecutorTarget in p is
// simply never read by anything downstream of this function.
//
// It does not re-check expiry (Plan.Expired covers that separately) or
// approval (that is the caller's own approval-store lookup).
func VerifyPlanFresh(catalog contract.Catalog, resolved networkcheck.ResolvedInventory, p Plan) (Plan, error) {
	fresh, err := BuildPlan(catalog, resolved, p.ID, p.IncidentID, p.Host, p.Component, p.Action, p.CreatedAt)
	if err != nil {
		return Plan{}, fmt.Errorf("plan no longer resolvable: %w", err)
	}
	// BuildPlan recomputes ExpiresAt from p.CreatedAt with the SAME TTL,
	// so fresh.PlanHash is directly comparable to p.PlanHash — both are
	// pure functions of the same executable fields.
	if fresh.PlanHash != p.PlanHash {
		return Plan{}, fmt.Errorf("plan is stale: current contract/inventory no longer resolves to the approved plan hash")
	}
	return fresh, nil
}
