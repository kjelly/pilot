package cmd

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/repair"
	"github.com/kjelly/pilot/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func baseRepairOpts(t *testing.T, inventory string, runner func(context.Context, []string, int) (string, int, error)) repairMCPToolsOptions {
	t.Helper()
	runtime, err := prepareDeployAnsibleRuntime(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return repairMCPToolsOptions{
		Inventory:      inventory,
		AuditDir:       t.TempDir(),
		StepTimeout:    5 * time.Second,
		AnsibleRuntime: runtime,
		AdHocRunner:    runner,
	}
}

func TestRepairCapabilitiesHandler_OnlyR1(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseFixtureInventory(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := repairCapabilitiesHandler(baseRepairOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, repairCapabilitiesInput{})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	for _, c := range out.Capabilities {
		if c.Risk != "R1" {
			t.Errorf("capability %+v has non-R1 risk", c)
		}
	}
}

func TestRepairPlanHandler_MissingFieldsRejected(t *testing.T) {
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := repairPlanHandler(baseRepairOpts(t, "unused.yml", fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, repairPlanInput{Host: "web1"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil, want a structured tool error")
	}
}

func TestRepairPlanHandler_UnknownComponentRejected(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseFixtureInventory(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := repairPlanHandler(baseRepairOpts(t, inv, fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, repairPlanInput{
		IncidentID: "inc-1", Host: "web1", Component: "not-a-component", Action: "restart",
	})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil, want a structured tool error")
	}
}

func TestRepairPlanHandler_SuccessResolvesFromContract(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseMultiGroupFixtureInventory(t, map[string]string{"prometheus": "web1"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := repairPlanHandler(baseRepairOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, repairPlanInput{
		IncidentID: "inc-1", Host: "web1", Component: "prometheus", Action: "restart",
	})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if out.Plan.ExecutorKind != "docker_restart" || out.Plan.ExecutorTarget != "pilot-prometheus" {
		t.Errorf("plan executor = %s/%s", out.Plan.ExecutorKind, out.Plan.ExecutorTarget)
	}
	if out.Plan.PlanHash == "" {
		t.Error("PlanHash is empty")
	}
	if out.Plan.Risk != "R1" {
		t.Errorf("Risk = %q, want R1", out.Plan.Risk)
	}
}

// fakeVerifyExecutorAllPass is a minimal repair.VerifyExecutor stub for
// apply-handler tests — real verify-spec execution is already covered
// by internal/repair's own tests.
type fakeVerifyExecutorAllPass struct{}

func (fakeVerifyExecutorAllPass) Execute(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
	return &tools.Result{Content: `{"id":"C1","status":"pass"}` + "\n"}, nil
}

func TestRepairApplyHandler_ExpiredPlanRejectedBeforeExecution(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseMultiGroupFixtureInventory(t, map[string]string{"prometheus": "web1"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	opts := baseRepairOpts(t, inv, fake.run)
	opts.VerifyExecutor = fakeVerifyExecutorAllPass{}
	handler := repairApplyHandler(opts)

	past := time.Now().Add(-time.Hour)
	plan := repairPlanJSON{
		SchemaVersion: 1, ID: "plan-1", IncidentID: "inc-1", Host: "web1", Component: "prometheus",
		Action: "restart", Risk: "R1", ExecutorKind: "docker_restart", ExecutorTarget: "pilot-prometheus",
		VerificationSpec: "docs/verification/prometheus.md", PlanHash: "irrelevant-since-expiry-checked-first",
		CreatedAt: past.Format(time.RFC3339), ExpiresAt: past.Add(time.Minute).Format(time.RFC3339),
	}
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, repairApplyInput{Plan: plan})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (structured PLAN_STALE, not a tool error)", result)
	}
	if out.Result != "PLAN_STALE" {
		t.Fatalf("Result = %q, want PLAN_STALE", out.Result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expired plan must never dispatch an ad-hoc call, got %v", fake.calls)
	}
}

// TestRepairApplyHandler_TamperedExecutorTargetIsIgnoredNotTrusted locks
// in a real bug found while writing this test (2026-09-01): tampering
// plan.ExecutorTarget WITHOUT recomputing plan.PlanHash does NOT change
// the hash (PlanHash was never derived from the caller's copy of that
// field to begin with), so a naive "hash still matches -> trust p as-is"
// check would silently execute against the ATTACKER-CHOSEN target. The
// fix: apply always executes against the plan freshly re-derived from
// today's contract (see repair.VerifyPlanFresh), never the caller-
// supplied plan object — proven here by configuring the fake runner to
// answer ONLY the correct, contract-derived target and asserting
// execution actually succeeds against it, not the tampered one.
func TestRepairApplyHandler_TamperedExecutorTargetIsIgnoredNotTrusted(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseMultiGroupFixtureInventory(t, map[string]string{"prometheus": "web1"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"docker restart pilot-prometheus": func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, ""), 0, nil
		},
	}}
	opts := baseRepairOpts(t, inv, fake.run)
	opts.VerifyExecutor = fakeVerifyExecutorAllPass{}

	planHandler := repairPlanHandler(opts)
	_, planOut, err := planHandler(context.Background(), &mcp.CallToolRequest{}, repairPlanInput{
		IncidentID: "inc-1", Host: "web1", Component: "prometheus", Action: "restart",
	})
	if err != nil {
		t.Fatalf("plan handler error = %v", err)
	}
	tampered := planOut.Plan
	tampered.ExecutorTarget = "some-other-container" // PlanHash deliberately left untouched

	applyHandler := repairApplyHandler(opts)
	result, out, err := applyHandler(context.Background(), &mcp.CallToolRequest{}, repairApplyInput{Plan: tampered})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if out.Result != "APPLIED_VERIFIED" {
		t.Fatalf("Result = %q, want APPLIED_VERIFIED (executed against the correct, contract-derived target)", out.Result)
	}
	if len(fake.calls) != 1 || fake.calls[0] != "docker restart pilot-prometheus" {
		t.Fatalf("calls = %v, want exactly one call restarting pilot-prometheus (the tampered target must never be dispatched)", fake.calls)
	}
}

func TestRepairApplyHandler_SuccessExecutesAndVerifies(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseMultiGroupFixtureInventory(t, map[string]string{"prometheus": "web1"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"docker restart pilot-prometheus": func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, ""), 0, nil
		},
	}}
	opts := baseRepairOpts(t, inv, fake.run)
	opts.VerifyExecutor = fakeVerifyExecutorAllPass{}

	planHandler := repairPlanHandler(opts)
	_, planOut, err := planHandler(context.Background(), &mcp.CallToolRequest{}, repairPlanInput{
		IncidentID: "inc-1", Host: "web1", Component: "prometheus", Action: "restart",
	})
	if err != nil {
		t.Fatalf("plan handler error = %v", err)
	}

	applyHandler := repairApplyHandler(opts)
	result, out, err := applyHandler(context.Background(), &mcp.CallToolRequest{}, repairApplyInput{Plan: planOut.Plan})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success); calls=%v", result, fake.calls)
	}
	if out.Result != "APPLIED_VERIFIED" {
		t.Fatalf("Result = %q, want APPLIED_VERIFIED; out=%+v", out.Result, out)
	}
	if !out.ExecutionOK || !out.VerifyPassed {
		t.Errorf("ExecutionOK=%v VerifyPassed=%v, want both true", out.ExecutionOK, out.VerifyPassed)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("calls = %v, want exactly 1 ad-hoc dispatch", fake.calls)
	}
}

func TestRepairApplyHandler_ExecutionFailureNeverCallsVerify(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseMultiGroupFixtureInventory(t, map[string]string{"prometheus": "web1"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"docker restart pilot-prometheus": func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 1, "Error: No such container: pilot-prometheus"), 0, nil
		},
	}}
	verifyCalled := false
	opts := baseRepairOpts(t, inv, fake.run)
	opts.VerifyExecutor = verifyExecutorFunc(func(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
		verifyCalled = true
		return &tools.Result{Content: `{"id":"C1","status":"pass"}` + "\n"}, nil
	})

	planHandler := repairPlanHandler(opts)
	_, planOut, err := planHandler(context.Background(), &mcp.CallToolRequest{}, repairPlanInput{
		IncidentID: "inc-1", Host: "web1", Component: "prometheus", Action: "restart",
	})
	if err != nil {
		t.Fatalf("plan handler error = %v", err)
	}

	applyHandler := repairApplyHandler(opts)
	_, out, err := applyHandler(context.Background(), &mcp.CallToolRequest{}, repairApplyInput{Plan: planOut.Plan})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if out.Result != "EXECUTION_FAILED" {
		t.Fatalf("Result = %q, want EXECUTION_FAILED", out.Result)
	}
	if verifyCalled {
		t.Fatal("verify must never run after a failed execution")
	}
}

type verifyExecutorFunc func(ctx context.Context, args json.RawMessage) (*tools.Result, error)

func (f verifyExecutorFunc) Execute(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
	return f(ctx, args)
}

var _ repair.VerifyExecutor = fakeVerifyExecutorAllPass{}
var _ repair.VerifyExecutor = verifyExecutorFunc(nil)
