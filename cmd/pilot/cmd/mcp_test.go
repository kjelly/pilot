//go:build linux || darwin || freebsd

// mcp_test.go is the "MCP Integration Tests" spec's Phase 3 asks for:
// spawn the real, compiled `pilot` binary (not a reimplementation) and
// talk to it as a real MCP client would, over the real stdio
// transport. buildPilotBinary/repoRootForPTYTest are reused from
// edit_tui_pty_test.go's existing PTY harness — building the same
// binary twice for two different kinds of subprocess test would be
// wasteful and drift-prone.
//
// A successful round-trip through mcp.CommandTransport/ClientSession
// is itself strong evidence of stdout cleanliness: that transport's
// newline-delimited JSON framing cannot complete a request/response
// cycle at all if the server has written any stray non-protocol bytes
// to stdout in between — a passing CallTool here is the assertion
// spec's "MCP stdout 每一筆輸出都是合法 protocol message" wants, not
// just a side effect of one.
package cmd

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// decodeStructured re-marshals a CallToolResult's StructuredContent
// (typed as `any` on the wire) into a concrete Go type.
func decodeStructured[T any](t *testing.T, result *mcp.CallToolResult) T {
	t.Helper()
	var out T
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal StructuredContent: %v", err)
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal StructuredContent into %T: %v\nraw: %s", out, err, data)
	}
	return out
}

func TestMCPServe_Integration_CapabilitiesInspectPlan(t *testing.T) {
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	auditDir := t.TempDir()

	beforeRevision, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir, "--allow-write")}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	toolsResult, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	wantTools := map[string]bool{
		"pilot_edit_capabilities": false,
		"pilot_edit_inspect":      false,
		"pilot_edit_plan":         false,
		"pilot_edit_apply":        false, // only listed because --allow-write is set above
	}
	for _, tool := range toolsResult.Tools {
		if _, ok := wantTools[tool.Name]; ok {
			wantTools[tool.Name] = true
		}
	}
	for name, seen := range wantTools {
		if !seen {
			t.Fatalf("expected tool %q to be listed, got %+v", name, toolsResult.Tools)
		}
	}

	capResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "pilot_edit_capabilities", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("CallTool(pilot_edit_capabilities) error = %v", err)
	}
	if capResult.IsError {
		t.Fatalf("pilot_edit_capabilities returned an error: %+v", capResult.Content)
	}
	caps := decodeStructured[capabilitiesOutput](t, capResult)
	if len(caps.Actions) == 0 {
		t.Fatal("expected at least one action in capabilities")
	}
	// Phase 5: vault actions ARE exposed, but only with a value_env-only
	// schema — no action may advertise a literal "value" field.
	seenVaultAction := map[string]bool{}
	for _, a := range caps.Actions {
		if !mcpVaultActionNames[a.Name] {
			continue
		}
		seenVaultAction[a.Name] = true
		for _, opt := range a.Optional {
			if opt == "value" {
				t.Fatalf("vault action %q advertises a literal \"value\" field over the real MCP wire: Optional=%v", a.Name, a.Optional)
			}
		}
	}
	for name := range mcpVaultActionNames {
		if !seenVaultAction[name] {
			t.Fatalf("expected vault action %q to be listed in capabilities over the real MCP wire", name)
		}
	}

	inspectArgs, _ := json.Marshal(inspectInput{IncludeGroupVars: true})
	var inspectArgsMap map[string]any
	_ = json.Unmarshal(inspectArgs, &inspectArgsMap)
	inspectResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "pilot_edit_inspect", Arguments: inspectArgsMap})
	if err != nil {
		t.Fatalf("CallTool(pilot_edit_inspect) error = %v", err)
	}
	if inspectResult.IsError {
		t.Fatalf("pilot_edit_inspect returned an error: %+v", inspectResult.Content)
	}
	inspect := decodeStructured[inspectOutput](t, inspectResult)
	if inspect.WorkspaceRevision == "" {
		t.Fatal("expected a non-empty workspace_revision from inspect")
	}

	planScenario := editScenario{Version: 1, Title: "mcp integration test", Steps: []editAction{
		{Action: "create_host", Host: "web-01"},
		{Action: "set_host_field", Host: "web-01", Field: "ansible_host", Value: "10.0.0.9"},
		{Action: "save_hosts"},
	}}
	planArgsJSON, _ := json.Marshal(planInput{BaseRevision: inspect.WorkspaceRevision, Scenario: planScenario})
	var planArgsMap map[string]any
	_ = json.Unmarshal(planArgsJSON, &planArgsMap)
	planResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "pilot_edit_plan", Arguments: planArgsMap})
	if err != nil {
		t.Fatalf("CallTool(pilot_edit_plan) error = %v", err)
	}
	if planResult.IsError {
		t.Fatalf("pilot_edit_plan returned an error: %+v", planResult.Content)
	}
	// Not asserting plan.Valid here: a brand-new workspace with no
	// `pilot inventory generate`-produced inventory.yml legitimately
	// fails checkWorkspaceCompleteness regardless of what this scenario
	// did correctly — the same real gate `pilot edit`'s own
	// completeness check reports. What matters for this test is that
	// the scenario itself ran and produced the expected diff/artifacts.
	plan := decodeStructured[planOutput](t, planResult)
	if plan.Audit.Directory == "" {
		t.Fatal("expected a non-empty audit directory reference")
	}

	// The real workspace must never see this scenario's write.
	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); !os.IsNotExist(err) {
		t.Fatalf("expected dir/hosts.yml to still not exist after a plan call, stat error = %v", err)
	}
	afterRevision, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	if afterRevision != beforeRevision {
		t.Fatal("expected the real workspace's revision to be unchanged after a plan call")
	}

	if _, err := os.Stat(plan.Audit.Directory); err != nil {
		t.Fatalf("expected the plan's audit directory to exist on disk: %v", err)
	}
	for _, name := range []string{"metadata.json", "scenario.redacted.json", "diff.patch", "validation.json", "trace.jsonl", "session.cast"} {
		if _, err := os.Stat(filepath.Join(plan.Audit.Directory, name)); err != nil {
			t.Fatalf("expected audit artifact %s to exist: %v", name, err)
		}
	}

	// --- apply: the plan just approved now mutates the real workspace ---
	applyArgsJSON, _ := json.Marshal(applyInput{PlanID: plan.PlanID, ExpectedRevision: inspect.WorkspaceRevision})
	var applyArgsMap map[string]any
	_ = json.Unmarshal(applyArgsJSON, &applyArgsMap)
	applyResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "pilot_edit_apply", Arguments: applyArgsMap})
	if err != nil {
		t.Fatalf("CallTool(pilot_edit_apply) error = %v", err)
	}
	if applyResult.IsError {
		t.Fatalf("pilot_edit_apply returned an error: %+v", applyResult.Content)
	}
	applied := decodeStructured[applyOutput](t, applyResult)
	if applied.Result != "applied" || applied.RolledBack {
		t.Fatalf("applied = %+v, want result=applied rolled_back=false", applied)
	}

	hostsData, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("expected the real workspace's hosts.yml to exist after apply: %v", err)
	}
	if !strings.Contains(string(hostsData), "web-01") || !strings.Contains(string(hostsData), "10.0.0.9") {
		t.Fatalf("hosts.yml = %q, want it to contain the applied change", hostsData)
	}
	for _, name := range []string{
		"metadata.json", "scenario.redacted.json", "diff.patch", "validation.json",
		"trace.jsonl", "session.cast", "managed-files-before.json", "managed-files-after.json", "result.json",
	} {
		if _, err := os.Stat(filepath.Join(applied.Audit.Directory, name)); err != nil {
			t.Fatalf("expected apply audit artifact %s to exist: %v", name, err)
		}
	}

	// A second apply against the same (now-stale) plan/revision must be
	// rejected rather than silently reapplied.
	secondApplyResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "pilot_edit_apply", Arguments: applyArgsMap})
	if err != nil {
		t.Fatalf("CallTool(pilot_edit_apply) [second attempt] error = %v", err)
	}
	if !secondApplyResult.IsError {
		t.Fatal("expected the second apply attempt (stale revision) to be rejected")
	}
}

// TestMCPServe_Integration_VaultPlanApplyRoundTrip drives a real
// add_vault_key scenario (value_env, never a literal value) through
// the real spawned pilot mcp serve binary end to end — the env var the
// scenario names must be set on the *subprocess's* environment
// (Command.Env), not just this test process's, since resolution
// happens inside pilot mcp serve itself.
func TestMCPServe_Integration_VaultPlanApplyRoundTrip(t *testing.T) {
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	auditDir := t.TempDir()
	const envVar = "PILOT_TEST_VAULT_SENTINEL_MCP_BINARY"

	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-vault-integration-test", Version: "0.0.1"}, nil)
	cmd := exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir, "--allow-write")
	cmd.Env = append(os.Environ(), envVar+"="+vaultSentinelValue)
	transport := &mcp.CommandTransport{Command: cmd}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	scenario := editScenario{Version: 1, Title: "vault mcp round trip", Steps: []editAction{
		{Action: "add_vault_key", File: "main.yaml", Key: "test_secret", ValueEnv: envVar},
		{Action: "save_vault", File: "main.yaml"},
	}}
	planArgsJSON, _ := json.Marshal(planInput{BaseRevision: rev, Scenario: scenario})
	var planArgsMap map[string]any
	_ = json.Unmarshal(planArgsJSON, &planArgsMap)
	planResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "pilot_edit_plan", Arguments: planArgsMap})
	if err != nil {
		t.Fatalf("CallTool(pilot_edit_plan) error = %v", err)
	}
	if planResult.IsError {
		t.Fatalf("pilot_edit_plan returned an error: %+v", planResult.Content)
	}
	plan := decodeStructured[planOutput](t, planResult)

	planResultRaw, _ := json.Marshal(planResult)
	assertSentinelAbsent(t, "plan CallToolResult (raw)", string(planResultRaw), vaultSentinelValue)

	applyArgsJSON, _ := json.Marshal(applyInput{PlanID: plan.PlanID, ExpectedRevision: rev})
	var applyArgsMap map[string]any
	_ = json.Unmarshal(applyArgsJSON, &applyArgsMap)
	applyResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "pilot_edit_apply", Arguments: applyArgsMap})
	if err != nil {
		t.Fatalf("CallTool(pilot_edit_apply) error = %v", err)
	}
	if applyResult.IsError {
		t.Fatalf("pilot_edit_apply returned an error: %+v", applyResult.Content)
	}
	applied := decodeStructured[applyOutput](t, applyResult)
	if applied.Result != "applied" || !applied.RedactedDiff {
		t.Fatalf("applied = %+v, want result=applied redacted_diff=true", applied)
	}

	applyResultRaw, _ := json.Marshal(applyResult)
	assertSentinelAbsent(t, "apply CallToolResult (raw)", string(applyResultRaw), vaultSentinelValue)

	vaultData, err := os.ReadFile(filepath.Join(dir, ".vault", "main.yaml"))
	if err != nil {
		t.Fatalf("expected the real .vault/main.yaml to exist after apply: %v", err)
	}
	if !strings.Contains(string(vaultData), vaultSentinelValue) {
		t.Fatal("expected the real vault file to contain the sentinel value")
	}

	for _, root := range []string{plan.Audit.Directory, applied.Audit.Directory} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			assertSentinelAbsent(t, path, string(data), vaultSentinelValue)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}

// TestMCPServe_Integration_RosterPlanApplyRoundTrip drives a real
// create_user + set_user_field scenario (Phase 6 increment 1) through
// the real spawned pilot mcp serve binary, then confirms
// pilot_edit_inspect's include_roster listing sees the new user.
func TestMCPServe_Integration_RosterPlanApplyRoundTrip(t *testing.T) {
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	auditDir := t.TempDir()
	writeMinimalRosterFixture(t, dir)

	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-roster-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir, "--allow-write")}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	scenario := editScenario{Version: 1, Title: "roster mcp round trip", Steps: []editAction{
		{Action: "create_user", User: "dana"},
		{Action: "set_user_field", User: "dana", Field: "email", Value: "dana@example.com"},
	}}
	planArgsJSON, _ := json.Marshal(planInput{BaseRevision: rev, Scenario: scenario})
	var planArgsMap map[string]any
	_ = json.Unmarshal(planArgsJSON, &planArgsMap)
	planResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "pilot_edit_plan", Arguments: planArgsMap})
	if err != nil {
		t.Fatalf("CallTool(pilot_edit_plan) error = %v", err)
	}
	if planResult.IsError {
		t.Fatalf("pilot_edit_plan returned an error: %+v", planResult.Content)
	}
	plan := decodeStructured[planOutput](t, planResult)

	applyArgsJSON, _ := json.Marshal(applyInput{PlanID: plan.PlanID, ExpectedRevision: rev})
	var applyArgsMap map[string]any
	_ = json.Unmarshal(applyArgsJSON, &applyArgsMap)
	applyResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "pilot_edit_apply", Arguments: applyArgsMap})
	if err != nil {
		t.Fatalf("CallTool(pilot_edit_apply) error = %v", err)
	}
	if applyResult.IsError {
		t.Fatalf("pilot_edit_apply returned an error: %+v", applyResult.Content)
	}
	applied := decodeStructured[applyOutput](t, applyResult)
	if applied.Result != "applied" {
		t.Fatalf("applied = %+v, want result=applied", applied)
	}

	inspectArgsJSON, _ := json.Marshal(inspectInput{IncludeRoster: true})
	var inspectArgsMap map[string]any
	_ = json.Unmarshal(inspectArgsJSON, &inspectArgsMap)
	inspectResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "pilot_edit_inspect", Arguments: inspectArgsMap})
	if err != nil {
		t.Fatalf("CallTool(pilot_edit_inspect) error = %v", err)
	}
	if inspectResult.IsError {
		t.Fatalf("pilot_edit_inspect returned an error: %+v", inspectResult.Content)
	}
	inspect := decodeStructured[inspectOutput](t, inspectResult)
	found := false
	for _, ru := range inspect.RosterUsers {
		if ru.Name == "dana" {
			found = true
			if ru.Email != "dana@example.com" {
				t.Fatalf("dana's email = %q, want dana@example.com", ru.Email)
			}
		}
	}
	if !found {
		t.Fatalf("expected inspect to list user dana, got %+v", inspect.RosterUsers)
	}
}
