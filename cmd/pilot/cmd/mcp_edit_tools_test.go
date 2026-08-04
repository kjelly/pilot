package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPAllowedActionNames_ExcludesVaultButKeepsEverythingElse(t *testing.T) {
	allowed := mcpAllowedActionNames()
	for name := range mcpVaultActionNames {
		if allowed[name] {
			t.Fatalf("expected vault action %q to be excluded from MCP capabilities", name)
		}
	}
	nonVaultCount := 0
	for _, def := range editActionRegistry() {
		if mcpVaultActionNames[def.Spec.Name] {
			continue
		}
		nonVaultCount++
		if !allowed[def.Spec.Name] {
			t.Fatalf("expected non-vault action %q to be allowed", def.Spec.Name)
		}
	}
	if len(allowed) != nonVaultCount {
		t.Fatalf("allowed has %d entries, want exactly the %d non-vault registry actions", len(allowed), nonVaultCount)
	}
}

func TestCapabilitiesHandler_ExcludesVaultActionsAndPopulatesUnsupported(t *testing.T) {
	handler := capabilitiesHandler(editMCPToolsOptions{Dir: "/workspace", WriteEnabled: true})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, capabilitiesInput{})
	if err != nil {
		t.Fatalf("capabilitiesHandler() error = %v", err)
	}
	if out.Workspace != "/workspace" || !out.WriteEnabled {
		t.Fatalf("out = %+v, want workspace=/workspace write_enabled=true", out)
	}
	for _, a := range out.Actions {
		if mcpVaultActionNames[a.Name] {
			t.Fatalf("vault action %q leaked into Actions", a.Name)
		}
	}
	if out.Unsupported["deploy"] == "" {
		t.Fatal(`expected Unsupported["deploy"] to be set`)
	}
	for name := range mcpVaultActionNames {
		if out.Unsupported[name] == "" {
			t.Fatalf("expected Unsupported[%q] to explain why it's excluded", name)
		}
	}
}

func TestInspectHandler_ReadsHostsRolePresetsAndCompleteness(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n  web-01:\n    ansible_host: 10.0.0.1\n    roles: [docker]\n")
	writeTestFile(t, filepath.Join(dir, "group_vars", "freeipa.yml"), "freeipa_realm: EXAMPLE.INTERNAL\n")

	handler := inspectHandler(editMCPToolsOptions{Dir: dir})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeGroupVars: true})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if out.WorkspaceRevision == "" {
		t.Fatal("expected a non-empty WorkspaceRevision")
	}
	if len(out.Hosts) != 1 || out.Hosts[0].Name != "web-01" || out.Hosts[0].AnsibleHost != "10.0.0.1" {
		t.Fatalf("Hosts = %+v", out.Hosts)
	}
	if out.GroupVars["freeipa.yml"]["freeipa_realm"] != "EXAMPLE.INTERNAL" {
		t.Fatalf("GroupVars = %+v, want freeipa.yml.freeipa_realm = EXAMPLE.INTERNAL", out.GroupVars)
	}
}

func TestInspectHandler_OmitsGroupVarsWhenNotRequested(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "group_vars", "freeipa.yml"), "freeipa_realm: EXAMPLE.INTERNAL\n")

	handler := inspectHandler(editMCPToolsOptions{Dir: dir})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeGroupVars: false})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if out.GroupVars != nil {
		t.Fatalf("GroupVars = %+v, want nil when include_group_vars is false", out.GroupVars)
	}
}

func TestPlanHandler_RejectsUnsupportedAction(t *testing.T) {
	dir := t.TempDir()
	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	handler := planHandler(editMCPToolsOptions{Dir: dir, AuditDir: t.TempDir()})
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, planInput{
		BaseRevision: rev,
		Scenario: editScenario{Version: 1, Steps: []editAction{
			{Action: "set_vault_value", File: "main.yaml", Key: "x", Value: "y"},
		}},
	})
	if err != nil {
		t.Fatalf("planHandler() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an error result for a vault action")
	}
	if out.PlanID != "" {
		t.Fatalf("expected zero-value output on error, got %+v", out)
	}
	toolErr := decodeToolError(t, result)
	if toolErr.Code != mcpErrUnsupportedAction {
		t.Fatalf("Code = %q, want %q", toolErr.Code, mcpErrUnsupportedAction)
	}
}

func TestPlanHandler_RejectsStaleBaseRevision(t *testing.T) {
	dir := t.TempDir()
	handler := planHandler(editMCPToolsOptions{Dir: dir, AuditDir: t.TempDir()})
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, planInput{
		BaseRevision: "sha256:not-the-real-one",
		Scenario:     editScenario{Version: 1, Steps: []editAction{{Action: "create_host", Host: "web-1"}}},
	})
	if err != nil {
		t.Fatalf("planHandler() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an error result for a stale base_revision")
	}
	toolErr := decodeToolError(t, result)
	if toolErr.Code != mcpErrWorkspaceChanged {
		t.Fatalf("Code = %q, want %q", toolErr.Code, mcpErrWorkspaceChanged)
	}
}

func TestPlanHandler_SuccessfulPlanWritesAuditArtifactsAndLeavesWorkspaceUntouched(t *testing.T) {
	dir := t.TempDir()
	auditRoot := t.TempDir()
	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	handler := planHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditRoot})
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, planInput{
		BaseRevision: rev,
		Scenario: editScenario{Version: 1, Title: "add web-01", Steps: []editAction{
			{Action: "create_host", Host: "web-01"},
			{Action: "save_hosts"},
		}},
	})
	if err != nil {
		t.Fatalf("planHandler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("expected a nil CallToolResult on success (structured Out only), got %+v", result)
	}
	if out.PlanID == "" || out.ScenarioHash == "" {
		t.Fatalf("out = %+v, want non-empty PlanID/ScenarioHash", out)
	}
	found := false
	for _, f := range out.AffectedFiles {
		if f == "hosts.yml" {
			found = true
		}
	}
	if !found {
		t.Fatalf("AffectedFiles = %v, want it to include hosts.yml", out.AffectedFiles)
	}
	if !strings.Contains(out.Diff, "web-01") {
		t.Fatalf("expected diff to mention web-01, got:\n%s", out.Diff)
	}

	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); !os.IsNotExist(err) {
		t.Fatalf("expected the real workspace's hosts.yml to still not exist, stat error = %v", err)
	}

	for _, name := range []string{"metadata.json", "scenario.redacted.json", "diff.patch", "validation.json", "trace.jsonl", "session.cast"} {
		if _, err := os.Stat(filepath.Join(out.Audit.Directory, name)); err != nil {
			t.Fatalf("expected audit artifact %s to exist under %s: %v", name, out.Audit.Directory, err)
		}
	}
}

func TestApplyHandler_WriteDisabledWhenWriteEnabledFalse(t *testing.T) {
	handler := applyHandler(editMCPToolsOptions{Dir: t.TempDir(), AuditDir: t.TempDir(), WriteEnabled: false})
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, applyInput{PlanID: "whatever"})
	if err != nil {
		t.Fatalf("applyHandler() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an error result when WriteEnabled is false")
	}
	if toolErr := decodeToolError(t, result); toolErr.Code != mcpErrWriteDisabled {
		t.Fatalf("Code = %q, want %q", toolErr.Code, mcpErrWriteDisabled)
	}
}

func TestApplyHandler_TargetNotFoundForUnknownPlanID(t *testing.T) {
	handler := applyHandler(editMCPToolsOptions{Dir: t.TempDir(), AuditDir: t.TempDir(), WriteEnabled: true})
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, applyInput{PlanID: "no-such-plan"})
	if err != nil {
		t.Fatalf("applyHandler() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an error result for an unknown plan_id")
	}
	if toolErr := decodeToolError(t, result); toolErr.Code != mcpErrTargetNotFound {
		t.Fatalf("Code = %q, want %q", toolErr.Code, mcpErrTargetNotFound)
	}
}

// createTestPlan runs a real plan through planHandler and returns its
// plan_id and the workspace's revision at plan time — the fixture the
// apply-handler tests below build on, exactly mirroring how apply
// would actually be reached in practice (via a prior plan call).
func createTestPlan(t *testing.T, dir, auditDir string, scenario editScenario) (planID, revision string) {
	t.Helper()
	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	handler := planHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir})
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, planInput{BaseRevision: rev, Scenario: scenario})
	if err != nil {
		t.Fatalf("planHandler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("expected a successful plan, got error result: %+v", result.Content)
	}
	return out.PlanID, rev
}

func TestApplyHandler_WorkspaceChangedForStaleExpectedRevision(t *testing.T) {
	dir := t.TempDir()
	auditDir := t.TempDir()
	scenario := editScenario{Version: 1, Steps: []editAction{{Action: "create_host", Host: "web-01"}, {Action: "save_hosts"}}}
	planID, _ := createTestPlan(t, dir, auditDir, scenario)

	handler := applyHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir, WriteEnabled: true})
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, applyInput{PlanID: planID, ExpectedRevision: "sha256:stale"})
	if err != nil {
		t.Fatalf("applyHandler() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an error result for a stale expected_revision")
	}
	if toolErr := decodeToolError(t, result); toolErr.Code != mcpErrWorkspaceChanged {
		t.Fatalf("Code = %q, want %q", toolErr.Code, mcpErrWorkspaceChanged)
	}
}

func TestApplyHandler_SuccessfulPlanThenApplyMutatesRealWorkspace(t *testing.T) {
	dir := t.TempDir()
	auditDir := t.TempDir()
	scenario := editScenario{Version: 1, Title: "add web-01", Steps: []editAction{
		{Action: "create_host", Host: "web-01"},
		{Action: "set_host_field", Host: "web-01", Field: "ansible_host", Value: "10.0.0.9"},
		{Action: "save_hosts"},
	}}
	planID, revision := createTestPlan(t, dir, auditDir, scenario)

	handler := applyHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir, WriteEnabled: true})
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, applyInput{PlanID: planID, ExpectedRevision: revision})
	if err != nil {
		t.Fatalf("applyHandler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("expected a successful apply, got error result: %+v", result.Content)
	}
	if out.Result != "applied" || out.RolledBack {
		t.Fatalf("out = %+v, want result=applied rolled_back=false", out)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("expected hosts.yml to exist for real: %v", err)
	}
	if !strings.Contains(string(data), "web-01") || !strings.Contains(string(data), "10.0.0.9") {
		t.Fatalf("hosts.yml = %q, want it to contain the planned change", data)
	}

	for _, name := range []string{
		"metadata.json", "scenario.redacted.json", "diff.patch", "validation.json",
		"trace.jsonl", "session.cast", "managed-files-before.json", "managed-files-after.json", "result.json",
	} {
		if _, err := os.Stat(filepath.Join(out.Audit.Directory, name)); err != nil {
			t.Fatalf("expected apply audit artifact %s to exist: %v", name, err)
		}
	}
}

// TestApplyHandler_FailedScenarioRollsBackAndReportsStructuredError uses
// a hand-written plan audit directory rather than createTestPlan: a
// scenario that fails partway would *also* fail identically during
// planning (plan and apply run the same deterministic driver against
// byte-identical content once revisions match), so it could never
// produce a real plan_id through planHandler in the first place. This
// simulates the case apply's rollback path actually exists for: a plan
// directory whose scenario now fails at apply time (e.g. environment
// drift) despite having been recorded as a valid plan.
func TestApplyHandler_FailedScenarioRollsBackAndReportsStructuredError(t *testing.T) {
	dir := t.TempDir()
	auditDir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	revision, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-01"},
		{Action: "save_hosts"},
		{Action: "set_group_var", File: "no-such-stem.yml", Key: "x", Value: "y"},
	}}
	planID := "hand-written-plan"
	planDir := filepath.Join(auditDir, "20260101T000000Z-"+planID+"-plan")
	if err := os.MkdirAll(planDir, 0o755); err != nil {
		t.Fatalf("mkdir planDir: %v", err)
	}
	if err := writeJSONFile(filepath.Join(planDir, "metadata.json"), auditMetadata{WorkspaceRevision: revision}); err != nil {
		t.Fatalf("write plan metadata.json: %v", err)
	}
	if err := writeJSONFile(filepath.Join(planDir, "scenario.redacted.json"), scenario); err != nil {
		t.Fatalf("write plan scenario.redacted.json: %v", err)
	}

	handler := applyHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir, WriteEnabled: true})
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, applyInput{PlanID: planID, ExpectedRevision: revision})
	if err != nil {
		t.Fatalf("applyHandler() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("expected a structured error result for a scenario that fails partway")
	}
	toolErr := decodeToolError(t, result)
	if toolErr.Code != mcpErrApplyFailed || !toolErr.RolledBack {
		t.Fatalf("toolErr = %+v, want code=apply_failed rolled_back=true", toolErr)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	if string(data) != "hosts: {}\n" {
		t.Fatalf("hosts.yml = %q, want the pre-apply content restored", data)
	}
}

func decodeToolError(t *testing.T, result *mcp.CallToolResult) mcpToolError {
	t.Helper()
	raw := contentText(t, result)
	var decoded mcpToolError
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("Content did not decode as mcpToolError: %v\ntext: %s", err, raw)
	}
	return decoded
}
