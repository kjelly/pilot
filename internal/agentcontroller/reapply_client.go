package agentcontroller

import (
	"context"
	"fmt"
	"time"

	"github.com/kjelly/pilot/internal/repair"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ReapplyDependencyStatus mirrors cmd/pilot/cmd's reapplyDependencyStatusJSON wire shape exactly.
type ReapplyDependencyStatus struct {
	Component string `json:"component"`
	Required  bool   `json:"required"`
	Healthy   bool   `json:"healthy"`
	Detail    string `json:"detail"`
}

// ReapplyPlanWire mirrors cmd/pilot/cmd's reapplyPlanJSON wire shape
// exactly — a deliberate 1:1 duplication, not an import (cmd/pilot
// cannot be imported from internal/agentcontroller; the wire JSON is the
// only shared contract between the two binaries, same convention
// RepairPlan already establishes for R1).
type ReapplyPlanWire struct {
	SchemaVersion            int                       `json:"schema_version"`
	ID                       string                    `json:"id"`
	IncidentID               string                    `json:"incident_id"`
	Host                     string                    `json:"host"`
	Component                string                    `json:"component"`
	Action                   string                    `json:"action"`
	Risk                     string                    `json:"risk"`
	VerificationSpec         string                    `json:"verification_spec"`
	InventoryRevision        string                    `json:"inventory_revision"`
	ContractHash             string                    `json:"contract_hash"`
	PlanHash                 string                    `json:"plan_hash"`
	CreatedAt                string                    `json:"created_at"`
	ExpiresAt                string                    `json:"expires_at"`
	PlaybookPath             string                    `json:"playbook_path"`
	PlaybookHash             string                    `json:"playbook_hash"`
	Stage                    string                    `json:"stage"`
	ResolvedInputKeys        []string                  `json:"resolved_input_keys,omitempty"`
	SecretReferenceKeys      []string                  `json:"secret_reference_keys,omitempty"`
	DependencySnapshot       []ReapplyDependencyStatus `json:"dependency_snapshot,omitempty"`
	PreviewRef               string                    `json:"preview_ref"`
	PreviewSupported         bool                      `json:"preview_supported"`
	PreviewSummary           string                    `json:"preview_summary,omitempty"`
	PreviewEstimatedChanged  int                       `json:"preview_estimated_changed"`
	PreviewUnsupportedReason string                    `json:"preview_unsupported_reason,omitempty"`
}

// ToReapplyPlan converts the wire-format ReapplyPlanWire into a
// repair.ReapplyPlan (parsed timestamps) for Store.CreateReapplyPlan.
func (rp ReapplyPlanWire) ToReapplyPlan() (repair.ReapplyPlan, error) {
	created, err := time.Parse(time.RFC3339, rp.CreatedAt)
	if err != nil {
		return repair.ReapplyPlan{}, fmt.Errorf("plan.created_at: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, rp.ExpiresAt)
	if err != nil {
		return repair.ReapplyPlan{}, fmt.Errorf("plan.expires_at: %w", err)
	}
	deps := make([]repair.DependencyStatus, 0, len(rp.DependencySnapshot))
	for _, d := range rp.DependencySnapshot {
		deps = append(deps, repair.DependencyStatus{Component: d.Component, Required: d.Required, Healthy: d.Healthy, Detail: d.Detail})
	}
	return repair.ReapplyPlan{
		SchemaVersion: rp.SchemaVersion, ID: rp.ID, IncidentID: rp.IncidentID, Host: rp.Host, Component: rp.Component,
		Action: rp.Action, Risk: rp.Risk, VerificationSpec: rp.VerificationSpec, InventoryRevision: rp.InventoryRevision,
		ContractHash: rp.ContractHash, PlanHash: rp.PlanHash, CreatedAt: created, ExpiresAt: expires,
		Resolved: repair.ReapplyResolvedInput{
			PlaybookPath: rp.PlaybookPath, PlaybookHash: rp.PlaybookHash, TargetHost: rp.Host, Stage: rp.Stage,
			ResolvedInputKeys: rp.ResolvedInputKeys, SecretReferenceKeys: rp.SecretReferenceKeys, DependencySnapshot: deps,
			PreviewRef: rp.PreviewRef, PreviewSupported: rp.PreviewSupported, PreviewSummary: rp.PreviewSummary,
			PreviewEstimatedChanged: rp.PreviewEstimatedChanged, PreviewUnsupportedReason: rp.PreviewUnsupportedReason,
		},
	}, nil
}

// ReapplyPlanWireFromStored converts a persisted StoredReapplyPlan back
// into the wire format ReapplyApply needs — used by the `remediation
// reapply-execute` CLI path, which reads the plan back out of the
// controller's OWN store since propose/approve/execute are separate CLI
// invocations.
func ReapplyPlanWireFromStored(p StoredReapplyPlan) ReapplyPlanWire {
	deps := make([]ReapplyDependencyStatus, 0, len(p.DependencySnapshot))
	for _, d := range p.DependencySnapshot {
		deps = append(deps, ReapplyDependencyStatus{Component: d.Component, Required: d.Required, Healthy: d.Healthy, Detail: d.Detail})
	}
	return ReapplyPlanWire{
		SchemaVersion: 1, ID: p.ID, IncidentID: p.IncidentID, Host: p.Host, Component: p.Component,
		Action: p.Action, Risk: p.Risk, VerificationSpec: p.VerificationSpec, InventoryRevision: p.InventoryRevision,
		ContractHash: p.ContractHash, PlanHash: p.PlanHash,
		CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: p.ExpiresAt.UTC().Format(time.RFC3339),
		PlaybookPath: p.PlaybookPath, PlaybookHash: p.PlaybookHash, Stage: p.Stage,
		ResolvedInputKeys: p.ResolvedInputKeys, SecretReferenceKeys: p.SecretReferenceKeys, DependencySnapshot: deps,
		PreviewRef: p.PreviewRef, PreviewSupported: p.PreviewSupported, PreviewSummary: p.PreviewSummary,
		PreviewEstimatedChanged: p.PreviewEstimatedChanged, PreviewUnsupportedReason: p.PreviewUnsupportedReason,
	}
}

// ReapplyApplyResult mirrors cmd/pilot/cmd's reapplyApplyOutput wire
// shape (minus the verbose per-step evidence this client doesn't need).
type ReapplyApplyResult struct {
	Result         string `json:"result"`
	ExecutionOK    bool   `json:"execution_ok"`
	Changed        int    `json:"changed"`
	ExecutionError string `json:"execution_error,omitempty"`
	VerifyPassed   bool   `json:"verify_passed"`
	AuditDirectory string `json:"audit_directory"`
}

// ReapplyPlan resolves an incident+host+component+action into an
// immutable ReapplyPlanWire via pilot_repair_reapply_plan.
func (c *RepairClient) ReapplyPlan(ctx context.Context, incidentID, host, component, action string) (ReapplyPlanWire, error) {
	type wrapped struct {
		Plan ReapplyPlanWire `json:"plan"`
	}
	var out wrapped
	err := c.withSession(ctx, func(s *mcp.ClientSession) error {
		w, callErr := callRepairTool[wrapped](ctx, s, "pilot_repair_reapply_plan", map[string]any{
			"incident_id": incidentID, "host": host, "component": component, "action": action,
		})
		out = w
		return callErr
	})
	return out.Plan, err
}

// ReapplyApply executes plan via pilot_repair_reapply_apply. The caller
// is responsible for having already recorded human approval (see
// Store.ApproveReapply) — this client, like the tool itself, does not
// check for one. R2 is always human-approved, in every environment;
// there is no autonomous variant of this call anywhere in this codebase.
func (c *RepairClient) ReapplyApply(ctx context.Context, plan ReapplyPlanWire) (ReapplyApplyResult, error) {
	var out ReapplyApplyResult
	err := c.withSession(ctx, func(s *mcp.ClientSession) error {
		o, callErr := callRepairTool[ReapplyApplyResult](ctx, s, "pilot_repair_reapply_apply", map[string]any{"plan": plan})
		out = o
		return callErr
	})
	return out, err
}
