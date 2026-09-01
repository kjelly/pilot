package agentcontroller

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/kjelly/pilot/internal/policy"
	"github.com/kjelly/pilot/internal/repair"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RepairClient is the Agent Controller's OWN connection to pilot's
// repair MCP family (design doc §3's recommended production topology:
// "Agent Controller: owns private repair MCP process/session"). It
// spawns a fresh `pilot mcp serve --enable-repair` subprocess per call
// and talks to it over stdio via the real MCP client SDK — the exact
// same transport mechanism an external Agent Runtime would use for
// observe-only diagnosis, just pointed at a different tool family the
// Agent itself never receives a session for.
//
// This is a genuine process boundary, not an in-process Go call: the
// production ansible-execution machinery (ControlMaster pooling, log
// rotation, timeout/kill handling) lives deep inside cmd/pilot/cmd as
// unexported internals tightly coupled to that binary's own MCP server
// lifecycle. Reimplementing or force-exporting all of that into a
// second binary would duplicate a large, security-relevant surface for
// no benefit — spawning `pilot` itself and using its own, already-
// audited MCP tool family is the correct boundary, matching this
// design doc's own recommendation.
type RepairClient struct {
	// PilotBinary is the path to (or PATH-resolvable name of) the pilot
	// binary this controller spawns for every repair call.
	PilotBinary string
	// Dir is the workspace root passed as `pilot mcp serve --dir` —
	// contracts/*.yaml and docs/verification/*.md are resolved relative
	// to it (via PILOT_ROOT/cwd, same as every other pilot subcommand).
	Dir string
	// Inventory is passed as `--diagnose-inventory` — repair reuses the
	// SAME flag/inventory diagnose tools use (see mcp_repair_tools.go).
	Inventory string
}

// RepairCapability mirrors cmd/pilot/cmd's repairCapabilityJSON wire
// shape exactly — a deliberate 1:1 duplication, not an import (cmd/pilot
// cannot be imported from internal/agentcontroller; the wire JSON is the
// only shared contract between the two binaries).
type RepairCapability struct {
	Component    string `json:"component"`
	Host         string `json:"host"`
	ActionID     string `json:"action_id"`
	Risk         string `json:"risk"`
	ExecutorKind string `json:"executor_kind"`
}

// RepairPlan mirrors cmd/pilot/cmd's repairPlanJSON wire shape exactly.
type RepairPlan struct {
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

// ToPlan converts the wire-format RepairPlan into a repair.Plan (parsed
// timestamps) for Store.CreatePlan.
func (rp RepairPlan) ToPlan() (repair.Plan, error) {
	created, err := time.Parse(time.RFC3339, rp.CreatedAt)
	if err != nil {
		return repair.Plan{}, fmt.Errorf("plan.created_at: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, rp.ExpiresAt)
	if err != nil {
		return repair.Plan{}, fmt.Errorf("plan.expires_at: %w", err)
	}
	return repair.Plan{
		SchemaVersion: rp.SchemaVersion, ID: rp.ID, IncidentID: rp.IncidentID, Host: rp.Host, Component: rp.Component,
		Action: rp.Action, Risk: rp.Risk, ExecutorKind: rp.ExecutorKind, ExecutorTarget: rp.ExecutorTarget,
		VerificationSpec: rp.VerificationSpec, InventoryRevision: rp.InventoryRevision, ContractHash: rp.ContractHash,
		PlanHash: rp.PlanHash, CreatedAt: created, ExpiresAt: expires,
		AutonomySandbox: rp.AutonomySandbox, AutonomyStaging: rp.AutonomyStaging, AutonomyProd: rp.AutonomyProd,
	}, nil
}

// RepairPlanFromStored converts a persisted StoredPlan back into the
// wire format RepairClient.Apply needs — used by the `remediation
// execute` CLI path, which reads the plan back out of the controller's
// OWN store rather than holding it in memory since propose/approve/
// execute are separate CLI invocations.
func RepairPlanFromStored(p StoredPlan) RepairPlan {
	return RepairPlan{
		SchemaVersion: 1, ID: p.ID, IncidentID: p.IncidentID, Host: p.Host, Component: p.Component,
		Action: p.Action, Risk: p.Risk, ExecutorKind: p.ExecutorKind, ExecutorTarget: p.ExecutorTarget,
		VerificationSpec: p.VerificationSpec, InventoryRevision: p.InventoryRevision, ContractHash: p.ContractHash,
		PlanHash: p.PlanHash, CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: p.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

// Autonomy converts a wire RepairPlan's resolved per-environment
// autonomy opt-in into a policy.ComponentAutonomy — used by the
// autonomy evaluate/auto-execute path (policy_gather.go) instead of
// this binary loading contracts/*.yaml itself, so contract loading has
// exactly one implementation (pilot's own, server-side, in
// internal/repair.BuildPlan) rather than two that could drift.
func (rp RepairPlan) Autonomy() policy.ComponentAutonomy {
	return policy.ComponentAutonomy{Sandbox: rp.AutonomySandbox, Staging: rp.AutonomyStaging, Prod: rp.AutonomyProd}
}

// RepairApplyResult mirrors cmd/pilot/cmd's repairApplyOutput wire shape
// (minus the verbose per-step evidence this client doesn't need).
type RepairApplyResult struct {
	Result         string `json:"result"`
	ExecutionOK    bool   `json:"execution_ok"`
	ExecutionRC    int    `json:"execution_rc,omitempty"`
	ExecutionError string `json:"execution_error,omitempty"`
	VerifyPassed   bool   `json:"verify_passed"`
	AuditDirectory string `json:"audit_directory"`
}

func (c *RepairClient) withSession(ctx context.Context, fn func(*mcp.ClientSession) error) error {
	cmd := exec.CommandContext(ctx, c.PilotBinary, "mcp", "serve",
		"--dir", c.Dir, "--enable-repair", "--diagnose-inventory", c.Inventory)
	// Contract loading (contracts/*.yaml) resolves from $PILOT_ROOT or
	// the PROCESS's own working directory — a DIFFERENT root than
	// --dir's edit-workspace meaning. Without this, the spawned pilot
	// process inherits THIS controller's own cwd (wherever it happens
	// to be running from) and silently fails to find contracts/ at all
	// — found via a real spawned-subprocess test 2026-09-01, not
	// theorized.
	cmd.Dir = c.Dir
	transport := &mcp.CommandTransport{Command: cmd}
	client := mcp.NewClient(&mcp.Implementation{Name: "pilot-agent-controller", Version: "dev"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return fmt.Errorf("connect to repair MCP: %w", err)
	}
	defer session.Close()
	return fn(session)
}

func callRepairTool[Out any](ctx context.Context, session *mcp.ClientSession, name string, args any) (Out, error) {
	var zero Out
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return zero, fmt.Errorf("call %s: %w", name, err)
	}
	if result.IsError {
		msg := ""
		for _, c := range result.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				msg = tc.Text
			}
		}
		return zero, fmt.Errorf("%s: %s", name, msg)
	}
	b, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return zero, fmt.Errorf("marshal %s result: %w", name, err)
	}
	var out Out
	if err := json.Unmarshal(b, &out); err != nil {
		return zero, fmt.Errorf("unmarshal %s result: %w", name, err)
	}
	return out, nil
}

// Capabilities lists every R1 repair action pilot currently offers.
func (c *RepairClient) Capabilities(ctx context.Context) ([]RepairCapability, error) {
	type wrapped struct {
		Capabilities []RepairCapability `json:"capabilities"`
	}
	var out wrapped
	err := c.withSession(ctx, func(s *mcp.ClientSession) error {
		w, callErr := callRepairTool[wrapped](ctx, s, "pilot_repair_capabilities", map[string]any{})
		out = w
		return callErr
	})
	return out.Capabilities, err
}

// Plan resolves an incident+host+component+action into an immutable
// RepairPlan via pilot_repair_plan.
func (c *RepairClient) Plan(ctx context.Context, incidentID, host, component, action string) (RepairPlan, error) {
	type wrapped struct {
		Plan RepairPlan `json:"plan"`
	}
	var out wrapped
	err := c.withSession(ctx, func(s *mcp.ClientSession) error {
		w, callErr := callRepairTool[wrapped](ctx, s, "pilot_repair_plan", map[string]any{
			"incident_id": incidentID, "host": host, "component": component, "action": action,
		})
		out = w
		return callErr
	})
	return out.Plan, err
}

// Apply executes plan via pilot_repair_apply. The caller is responsible
// for having already recorded human approval (see Store.Approve) —
// this client, like the tool itself, does not check for one.
func (c *RepairClient) Apply(ctx context.Context, plan RepairPlan) (RepairApplyResult, error) {
	var out RepairApplyResult
	err := c.withSession(ctx, func(s *mcp.ClientSession) error {
		o, callErr := callRepairTool[RepairApplyResult](ctx, s, "pilot_repair_apply", map[string]any{"plan": plan})
		out = o
		return callErr
	})
	return out, err
}
