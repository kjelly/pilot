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

func decodeToolError(t *testing.T, result *mcp.CallToolResult) mcpToolError {
	t.Helper()
	raw := contentText(t, result)
	var decoded mcpToolError
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("Content did not decode as mcpToolError: %v\ntext: %s", err, raw)
	}
	return decoded
}
