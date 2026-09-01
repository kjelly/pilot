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

// baseReapplyOpts mirrors baseRepairOpts but wires in the fake preview/
// execute runners a Phase 5 reapply handler test needs — no REAL
// ansible-playbook invocation in these tests, same "fake collaborators,
// real contract/inventory resolution" pattern R1's own handler tests
// already established.
func baseReapplyOpts(t *testing.T, inventory string, adhoc func(context.Context, []string, int) (string, int, error), preview, execute repair.PreviewRunner) repairMCPToolsOptions {
	t.Helper()
	opts := baseRepairOpts(t, inventory, adhoc)
	opts.PreviewRunner = preview
	opts.ExecuteRunner = execute
	return opts
}

func fakePreviewRunnerNoChanges() repair.PreviewRunner {
	return func(ctx context.Context, playbookPath, inventory, host, stage string) (string, int, error) {
		return "PLAY RECAP ***\n" + host + " : ok=1 changed=0\n", 0, nil
	}
}

func fakeExecuteRunnerSuccess() repair.PreviewRunner {
	return func(ctx context.Context, playbookPath, inventory, host, stage string) (string, int, error) {
		return "PLAY RECAP ***\n" + host + " : ok=3 changed=1\n", 0, nil
	}
}

func TestRepairReapplyPlanHandler_MissingFieldsRejected(t *testing.T) {
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := repairReapplyPlanHandler(baseReapplyOpts(t, "unused.yml", fake.run, fakePreviewRunnerNoChanges(), fakeExecuteRunnerSuccess()))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, reapplyPlanInput{Host: "web1"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil, want a structured tool error")
	}
}

func TestRepairReapplyPlanHandler_R1ActionRejected(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseMultiGroupFixtureInventory(t, map[string]string{"alertmanager": "web1"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"systemctl is-active docker.service": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "active"), 0, nil },
	}}
	handler := repairReapplyPlanHandler(baseReapplyOpts(t, inv, fake.run, fakePreviewRunnerNoChanges(), fakeExecuteRunnerSuccess()))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, reapplyPlanInput{
		IncidentID: "inc-1", Host: "web1", Component: "alertmanager", Action: "restart", // R1 action, not "reapply"
	})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil, want a structured tool error — restart is R1, not a canonical_apply R2 action")
	}
}

func TestRepairReapplyPlanHandler_SuccessResolvesFromContract(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseMultiGroupFixtureInventory(t, map[string]string{"alertmanager": "web1"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"systemctl is-active docker.service": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "active"), 0, nil },
	}}
	handler := repairReapplyPlanHandler(baseReapplyOpts(t, inv, fake.run, fakePreviewRunnerNoChanges(), fakeExecuteRunnerSuccess()))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, reapplyPlanInput{
		IncidentID: "inc-1", Host: "web1", Component: "alertmanager", Action: "reapply",
	})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if out.Plan.Risk != "R2" {
		t.Errorf("Risk = %q, want R2", out.Plan.Risk)
	}
	if out.Plan.PlaybookPath != "playbooks/apply/alertmanager-apply.yml" {
		t.Errorf("PlaybookPath = %q", out.Plan.PlaybookPath)
	}
	if out.Plan.PlaybookHash == "" {
		t.Error("PlaybookHash is empty")
	}
	if out.Plan.PlanHash == "" {
		t.Error("PlanHash is empty")
	}
	if !out.Plan.PreviewSupported {
		t.Error("PreviewSupported = false, want true")
	}
	if len(out.Plan.DependencySnapshot) != 1 || !out.Plan.DependencySnapshot[0].Healthy {
		t.Errorf("DependencySnapshot = %+v, want exactly one healthy docker entry", out.Plan.DependencySnapshot)
	}
}

func TestRepairReapplyPlanHandler_UnhealthyDependencyBlocksPlan(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseMultiGroupFixtureInventory(t, map[string]string{"alertmanager": "web1"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"systemctl is-active docker.service": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "inactive"), 0, nil },
	}}
	handler := repairReapplyPlanHandler(baseReapplyOpts(t, inv, fake.run, fakePreviewRunnerNoChanges(), fakeExecuteRunnerSuccess()))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, reapplyPlanInput{
		IncidentID: "inc-1", Host: "web1", Component: "alertmanager", Action: "reapply",
	})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil, want a structured tool error — docker.service is inactive")
	}
}

func TestRepairReapplyApplyHandler_ExpiredPlanRejectedBeforeExecution(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseMultiGroupFixtureInventory(t, map[string]string{"alertmanager": "web1"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	opts := baseReapplyOpts(t, inv, fake.run, fakePreviewRunnerNoChanges(), fakeExecuteRunnerSuccess())
	opts.VerifyExecutor = fakeVerifyExecutorAllPass{}
	handler := repairReapplyApplyHandler(opts)

	past := time.Now().Add(-time.Hour)
	plan := reapplyPlanJSON{
		SchemaVersion: 1, ID: "plan-1", IncidentID: "inc-1", Host: "web1", Component: "alertmanager", Action: "reapply",
		Risk: "R2", VerificationSpec: "docs/verification/alertmanager.md", PlanHash: "irrelevant-since-expiry-checked-first",
		CreatedAt: past.Format(time.RFC3339), ExpiresAt: past.Add(time.Minute).Format(time.RFC3339),
	}
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, reapplyApplyInput{Plan: plan})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (structured PLAN_STALE, not a tool error)", result)
	}
	if out.Result != repair.ReapplyPlanStale {
		t.Fatalf("Result = %q, want %q", out.Result, repair.ReapplyPlanStale)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expired plan must never dispatch any preflight call, got %v", fake.calls)
	}
}

// TestRepairReapplyApplyHandler_TamperedPlaybookPathIsIgnoredNotTrusted
// locks in the SAME defense R1's own apply handler already has (see
// TestRepairApplyHandler_TamperedExecutorTargetIsIgnoredNotTrusted):
// execution must always use the FRESHLY rebuilt plan, never the
// caller-supplied one — proven by configuring the fake execute runner
// to answer only the CORRECT playbook path and asserting execution
// succeeds against it.
func TestRepairReapplyApplyHandler_TamperedPlaybookPathIsIgnoredNotTrusted(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseMultiGroupFixtureInventory(t, map[string]string{"alertmanager": "web1"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"systemctl is-active docker.service": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "active"), 0, nil },
	}}
	var executedPlaybook string
	execute := func(ctx context.Context, playbookPath, inventory, host, stage string) (string, int, error) {
		executedPlaybook = playbookPath
		return "PLAY RECAP ***\n" + host + " : ok=3 changed=1\n", 0, nil
	}
	opts := baseReapplyOpts(t, inv, fake.run, fakePreviewRunnerNoChanges(), execute)
	opts.VerifyExecutor = fakeVerifyExecutorAllPass{}

	planHandler := repairReapplyPlanHandler(opts)
	_, planOut, err := planHandler(context.Background(), &mcp.CallToolRequest{}, reapplyPlanInput{
		IncidentID: "inc-1", Host: "web1", Component: "alertmanager", Action: "reapply",
	})
	if err != nil {
		t.Fatalf("plan handler error = %v", err)
	}
	tampered := planOut.Plan
	tampered.PlaybookPath = "playbooks/apply/some-other-dangerous-playbook.yml" // PlanHash left untouched

	applyHandler := repairReapplyApplyHandler(opts)
	result, out, err := applyHandler(context.Background(), &mcp.CallToolRequest{}, reapplyApplyInput{Plan: tampered})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if out.Result != repair.ReapplyAppliedVerified {
		t.Fatalf("Result = %q, want %q; out=%+v", out.Result, repair.ReapplyAppliedVerified, out)
	}
	if executedPlaybook != "playbooks/apply/alertmanager-apply.yml" {
		t.Fatalf("executed playbook = %q, want the contract-derived path, not the tampered one", executedPlaybook)
	}
}

func TestRepairReapplyApplyHandler_SuccessExecutesAndVerifies(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseMultiGroupFixtureInventory(t, map[string]string{"alertmanager": "web1"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"systemctl is-active docker.service": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "active"), 0, nil },
	}}
	opts := baseReapplyOpts(t, inv, fake.run, fakePreviewRunnerNoChanges(), fakeExecuteRunnerSuccess())
	opts.VerifyExecutor = fakeVerifyExecutorAllPass{}

	planHandler := repairReapplyPlanHandler(opts)
	_, planOut, err := planHandler(context.Background(), &mcp.CallToolRequest{}, reapplyPlanInput{
		IncidentID: "inc-1", Host: "web1", Component: "alertmanager", Action: "reapply",
	})
	if err != nil {
		t.Fatalf("plan handler error = %v", err)
	}

	applyHandler := repairReapplyApplyHandler(opts)
	result, out, err := applyHandler(context.Background(), &mcp.CallToolRequest{}, reapplyApplyInput{Plan: planOut.Plan})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if out.Result != repair.ReapplyAppliedVerified {
		t.Fatalf("Result = %q, want %q; out=%+v", out.Result, repair.ReapplyAppliedVerified, out)
	}
	if !out.ExecutionOK || !out.VerifyPassed {
		t.Errorf("ExecutionOK=%v VerifyPassed=%v, want both true", out.ExecutionOK, out.VerifyPassed)
	}
	if out.Changed != 1 {
		t.Errorf("Changed = %d, want 1", out.Changed)
	}
}

func TestRepairReapplyApplyHandler_ExecutionFailureNeverCallsVerify(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseMultiGroupFixtureInventory(t, map[string]string{"alertmanager": "web1"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"systemctl is-active docker.service": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "active"), 0, nil },
	}}
	failingExecute := func(ctx context.Context, playbookPath, inventory, host, stage string) (string, int, error) {
		return "PLAY RECAP ***\n" + host + " : ok=1 changed=0 failed=1\n", 2, nil
	}
	verifyCalled := false
	opts := baseReapplyOpts(t, inv, fake.run, fakePreviewRunnerNoChanges(), failingExecute)
	opts.VerifyExecutor = verifyExecutorFunc(func(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
		verifyCalled = true
		return &tools.Result{Content: `{"id":"C1","status":"pass"}` + "\n"}, nil
	})

	planHandler := repairReapplyPlanHandler(opts)
	_, planOut, err := planHandler(context.Background(), &mcp.CallToolRequest{}, reapplyPlanInput{
		IncidentID: "inc-1", Host: "web1", Component: "alertmanager", Action: "reapply",
	})
	if err != nil {
		t.Fatalf("plan handler error = %v", err)
	}

	applyHandler := repairReapplyApplyHandler(opts)
	_, out, err := applyHandler(context.Background(), &mcp.CallToolRequest{}, reapplyApplyInput{Plan: planOut.Plan})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if out.Result != repair.ReapplyApplyFailedPartial {
		t.Fatalf("Result = %q, want %q", out.Result, repair.ReapplyApplyFailedPartial)
	}
	if verifyCalled {
		t.Fatal("verify must never run after a failed canonical apply")
	}
}
