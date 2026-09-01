// mcp_repair_tools.go implements Agent Monitoring Phase 3's repair MCP
// family: pilot_repair_capabilities, pilot_repair_plan, pilot_repair_apply.
// This is a SEPARATE tool family from pilot_diagnose_*/pilot_edit_* —
// registered only when --enable-repair is set, independent of
// --enable-diagnose/--enable-diagnose-raw/--allow-write. The Agent
// Runtime must never receive an MCP session with this family registered
// (design doc §2/§3) — only the Agent Controller (or a trusted operator)
// connects here, over its own private session.
//
// This process is stateless: it holds no plan/approval store of its
// own. pilot_repair_plan resolves and returns a Plan; the CALLER (the
// Agent Controller) is responsible for persisting it and recording
// approval before ever calling pilot_repair_apply — this tool never
// checks "is this approved", because it has no approval store to check
// against. pilot_repair_apply still re-validates the plan's freshness
// (internal/repair.VerifyPlanFresh) and expiry against ITS OWN current
// contract/inventory before executing, so a stale or tampered plan is
// rejected regardless of what the caller believes about it.
package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/kjelly/pilot/internal/networkcheck"
	"github.com/kjelly/pilot/internal/repair"
	"github.com/kjelly/pilot/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// repairMCPToolsOptions is the canonicalized, server-lifetime config the
// repair tool handlers close over — deliberately separate from
// diagnoseMCPToolsOptions even though several fields overlap, so a
// future change to one family's options shape can never silently affect
// the other's.
type repairMCPToolsOptions struct {
	Inventory      string
	AuditDir       string
	StepTimeout    time.Duration
	AnsibleRuntime deployAnsibleRuntime
	AdHocRunner    diagnose.AdHocRunner  // nil in production; injected only by tests
	VerifyExecutor repair.VerifyExecutor // nil in production (real tools.VerifySpecTool built per call); injected only by tests
}

func registerRepairTools(server *mcp.Server, opts repairMCPToolsOptions) {
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_repair_capabilities",
		Description: "list every R1 repair action currently offerable: a contracts/*.yaml `remediation` action whose component is assigned to a host that actually exists in the current inventory. Never returns an R2/R3/R4 action even if one is declared in a contract — Phase 3 hard-restricts to R1.",
	}, repairCapabilitiesHandler(opts))
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_repair_plan",
		Description: "resolve an incident id + exact host + component + action id into an immutable, hashed RemediationPlan. Every execution-relevant field (executor kind/target, verification spec) is resolved HERE from the component's own contract — never taken from the caller. Rejects anything but a declared R1, maxTargets=1 action. This tool holds no plan store of its own — the caller must persist the returned plan and obtain human approval before ever calling pilot_repair_apply.",
	}, repairPlanHandler(opts))
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_repair_apply",
		Description: "execute a previously-planned R1 action on its exact one host, then verify success via the component's own verification spec — never process exit code alone. Re-validates the plan hash against the CURRENT contract/inventory and rejects an expired or stale plan before executing anything. The caller is responsible for having already obtained and checked human approval — this tool has no approval store and does not check one.",
	}, repairApplyHandler(opts))
}

// ---- pilot_repair_capabilities ---------------------------------------

type repairCapabilitiesInput struct{}

type repairCapabilitiesOutput struct {
	Capabilities []repairCapabilityJSON `json:"capabilities"`
}

type repairCapabilityJSON struct {
	Component    string `json:"component"`
	Host         string `json:"host"`
	ActionID     string `json:"action_id"`
	Risk         string `json:"risk"`
	ExecutorKind string `json:"executor_kind"`
}

func repairCapabilitiesHandler(opts repairMCPToolsOptions) mcp.ToolHandlerFor[repairCapabilitiesInput, repairCapabilitiesOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in repairCapabilitiesInput) (*mcp.CallToolResult, repairCapabilitiesOutput, error) {
		catalog, resolved, err := loadRepairCatalogAndInventory(ctx, opts)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), repairCapabilitiesOutput{}, nil
		}
		caps := repair.ListCapabilities(catalog, resolved)
		out := repairCapabilitiesOutput{}
		for _, c := range caps {
			out.Capabilities = append(out.Capabilities, repairCapabilityJSON{
				Component: c.Component, Host: c.Host, ActionID: c.ActionID, Risk: c.Risk, ExecutorKind: c.ExecutorKind,
			})
		}
		return nil, out, nil
	}
}

// ---- pilot_repair_plan -------------------------------------------------

type repairPlanInput struct {
	IncidentID string `json:"incident_id" jsonschema:"the incident this plan is for, as recorded by the caller — never validated against a store this stateless tool doesn't have"`
	Host       string `json:"host" jsonschema:"exact inventory hostname — must be an exact ansible-inventory key, never a pattern/group/wildcard"`
	Component  string `json:"component" jsonschema:"component ID from contracts/*.yaml — must have a remediation block AND be assigned to host"`
	Action     string `json:"action" jsonschema:"remediation action id from that component's contracts/*.yaml remediation.actions[]"`
}

type repairPlanOutput struct {
	Plan repairPlanJSON `json:"plan"`
}

type repairPlanJSON struct {
	SchemaVersion     int    `json:"schema_version"`
	ID                string `json:"id"`
	IncidentID        string `json:"incident_id"`
	Host              string `json:"host"`
	Component         string `json:"component"`
	Action            string `json:"action"`
	Risk              string `json:"risk"`
	ExecutorKind      string `json:"executor_kind"`
	ExecutorTarget    string `json:"executor_target"`
	VerificationSpec  string `json:"verification_spec"`
	InventoryRevision string `json:"inventory_revision"`
	ContractHash      string `json:"contract_hash"`
	PlanHash          string `json:"plan_hash"`
	CreatedAt         string `json:"created_at"`
	ExpiresAt         string `json:"expires_at"`
	AutonomySandbox   string `json:"autonomy_sandbox,omitempty"`
	AutonomyStaging   string `json:"autonomy_staging,omitempty"`
	AutonomyProd      string `json:"autonomy_prod,omitempty"`
}

func toPlanJSON(p repair.Plan) repairPlanJSON {
	return repairPlanJSON{
		SchemaVersion: p.SchemaVersion, ID: p.ID, IncidentID: p.IncidentID, Host: p.Host, Component: p.Component,
		Action: p.Action, Risk: p.Risk, ExecutorKind: p.ExecutorKind, ExecutorTarget: p.ExecutorTarget,
		VerificationSpec: p.VerificationSpec, InventoryRevision: p.InventoryRevision, ContractHash: p.ContractHash,
		PlanHash: p.PlanHash, CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: p.ExpiresAt.UTC().Format(time.RFC3339),
		AutonomySandbox: p.AutonomySandbox, AutonomyStaging: p.AutonomyStaging, AutonomyProd: p.AutonomyProd,
	}
}

func repairPlanHandler(opts repairMCPToolsOptions) mcp.ToolHandlerFor[repairPlanInput, repairPlanOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in repairPlanInput) (*mcp.CallToolResult, repairPlanOutput, error) {
		if in.IncidentID == "" || in.Host == "" || in.Component == "" || in.Action == "" {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: "incident_id, host, component, and action are all required"}), repairPlanOutput{}, nil
		}
		catalog, resolved, err := loadRepairCatalogAndInventory(ctx, opts)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), repairPlanOutput{}, nil
		}
		planID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), repairPlanOutput{}, nil
		}
		p, err := repair.BuildPlan(catalog, resolved, planID, in.IncidentID, in.Host, in.Component, in.Action, time.Now())
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), repairPlanOutput{}, nil
		}
		return nil, repairPlanOutput{Plan: toPlanJSON(p)}, nil
	}
}

// ---- pilot_repair_apply -------------------------------------------------

// repairApplyInput carries the FULL plan the caller obtained from
// pilot_repair_plan (and had approved) — this process has no plan
// store, so it cannot look one up by ID alone.
type repairApplyInput struct {
	Plan repairPlanJSON `json:"plan" jsonschema:"the exact plan object returned by pilot_repair_plan — every field is re-validated against the current contract/inventory before anything executes"`
}

type repairApplyOutput struct {
	Result         string                 `json:"result"` // APPLIED_VERIFIED | APPLIED_ALERT_STILL_FIRING | EXECUTION_FAILED | VERIFICATION_FAILED | VERIFICATION_INCONCLUSIVE | PLAN_STALE
	ExecutionOK    bool                   `json:"execution_ok"`
	ExecutionRC    int                    `json:"execution_rc,omitempty"`
	ExecutionError string                 `json:"execution_error,omitempty"`
	VerifyPassed   bool                   `json:"verify_passed"`
	VerifyRows     []diagnoseStepEvidence `json:"verify_rows,omitempty"`
	AuditDirectory string                 `json:"audit_directory"`
}

func fromPlanJSON(pj repairPlanJSON) (repair.Plan, error) {
	created, err := time.Parse(time.RFC3339, pj.CreatedAt)
	if err != nil {
		return repair.Plan{}, fmt.Errorf("plan.created_at: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, pj.ExpiresAt)
	if err != nil {
		return repair.Plan{}, fmt.Errorf("plan.expires_at: %w", err)
	}
	return repair.Plan{
		SchemaVersion: pj.SchemaVersion, ID: pj.ID, IncidentID: pj.IncidentID, Host: pj.Host, Component: pj.Component,
		Action: pj.Action, Risk: pj.Risk, ExecutorKind: pj.ExecutorKind, ExecutorTarget: pj.ExecutorTarget,
		VerificationSpec: pj.VerificationSpec, InventoryRevision: pj.InventoryRevision, ContractHash: pj.ContractHash,
		PlanHash: pj.PlanHash, CreatedAt: created, ExpiresAt: expires,
		AutonomySandbox: pj.AutonomySandbox, AutonomyStaging: pj.AutonomyStaging, AutonomyProd: pj.AutonomyProd,
	}, nil
}

func repairApplyHandler(opts repairMCPToolsOptions) mcp.ToolHandlerFor[repairApplyInput, repairApplyOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in repairApplyInput) (*mcp.CallToolResult, repairApplyOutput, error) {
		p, err := fromPlanJSON(in.Plan)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), repairApplyOutput{}, nil
		}

		now := time.Now()
		if p.Expired(now) {
			return nil, repairApplyOutput{Result: "PLAN_STALE"}, nil
		}

		catalog, resolved, err := loadRepairCatalogAndInventory(ctx, opts)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), repairApplyOutput{}, nil
		}
		// Execute using the FRESHLY REBUILT plan, never the caller-
		// supplied p, past this point — see VerifyPlanFresh's own doc
		// comment for why (p's executor fields are only ever a display/
		// audit copy, not a trusted execution parameter).
		fresh, err := repair.VerifyPlanFresh(catalog, resolved, p)
		if err != nil {
			return nil, repairApplyOutput{Result: "PLAN_STALE"}, nil
		}
		p = fresh

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), repairApplyOutput{}, nil
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(diagnoseMCPToolsOptions{AuditDir: opts.AuditDir}, "repair_apply", sessionID, start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), repairApplyOutput{}, nil
		}

		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}
		execResult, err := repair.Execute(ctx, runner, opts.Inventory, p, int(opts.StepTimeout.Seconds()))
		out := repairApplyOutput{AuditDirectory: auditDir}
		if err != nil {
			out.Result, out.ExecutionError = "EXECUTION_FAILED", err.Error()
			writeRepairAuditRecord(auditDir, sessionID, req, opts, p, start, []diagnose.StepResult{})
			return nil, out, nil
		}
		out.ExecutionRC = execResult.Result.RC
		if execResult.Result.RunErr != nil || execResult.Result.Unreachable || execResult.Result.RC != 0 {
			out.Result = "EXECUTION_FAILED"
			if execResult.Result.RunErr != nil {
				out.ExecutionError = execResult.Result.RunErr.Error()
			}
			writeRepairAuditRecord(auditDir, sessionID, req, opts, p, start, []diagnose.StepResult{execResult})
			return nil, out, nil
		}
		out.ExecutionOK = true

		verifyTool := opts.VerifyExecutor
		if verifyTool == nil {
			verifyTool = &tools.VerifySpecTool{Inventory: opts.Inventory, Host: p.Host}
		}
		verifyOutcome, verr := repair.VerifyAfterExecution(ctx, verifyTool, p.VerificationSpec, p.Host, int(opts.StepTimeout.Seconds()))
		writeRepairAuditRecord(auditDir, sessionID, req, opts, p, start, []diagnose.StepResult{execResult})
		if verr != nil {
			out.Result = "VERIFICATION_INCONCLUSIVE"
			return nil, out, nil
		}
		out.VerifyPassed = verifyOutcome.Passed
		for _, r := range verifyOutcome.Rows {
			out.VerifyRows = append(out.VerifyRows, diagnoseStepEvidence{ID: r.ID, Description: r.Detail, OK: r.Status == "pass" || r.Status == "skip" || r.Status == "not_applicable"})
		}
		if verifyOutcome.Passed {
			out.Result = "APPLIED_VERIFIED"
		} else {
			out.Result = "VERIFICATION_FAILED"
		}
		return nil, out, nil
	}
}

func writeRepairAuditRecord(auditDir, sessionID string, req *mcp.CallToolRequest, opts repairMCPToolsOptions, p repair.Plan, start time.Time, steps []diagnose.StepResult) {
	rec := diagnoseAuditRecord{
		SessionID: sessionID, Check: "repair_apply", PilotVersion: rootCmd.Version,
		GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
		Inventory: opts.Inventory, Host: p.Host,
		Params: map[string]string{"plan_id": p.ID, "plan_hash": p.PlanHash, "component": p.Component, "action": p.Action},
		Start:  start, Finish: time.Now(), Steps: stepAuditList(steps),
	}
	_ = writeDiagnoseAudit(auditDir, rec)
}

// loadRepairCatalogAndInventory resolves the current contract catalog
// and inventory fresh on every call — matching resolveDiagnoseInventory's
// own "never cached from mcp serve startup" convention (mcp_diagnose_
// tools.go), so a contract or inventory edited while this long-running
// server is up is picked up on the very next repair call.
func loadRepairCatalogAndInventory(ctx context.Context, opts repairMCPToolsOptions) (contract.Catalog, networkcheck.ResolvedInventory, error) {
	resolved, err := resolveDiagnoseInventory(ctx, diagnoseMCPToolsOptions{Inventory: opts.Inventory, StepTimeout: opts.StepTimeout})
	if err != nil {
		return contract.Catalog{}, networkcheck.ResolvedInventory{}, fmt.Errorf("resolve inventory: %w", err)
	}
	root, err := resolveContractRoot("")
	if err != nil {
		return contract.Catalog{}, networkcheck.ResolvedInventory{}, fmt.Errorf("resolve contract root: %w", err)
	}
	loader, err := contract.NewLoader(root)
	if err != nil {
		return contract.Catalog{}, networkcheck.ResolvedInventory{}, err
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		return contract.Catalog{}, networkcheck.ResolvedInventory{}, err
	}
	return catalog, resolved, nil
}
