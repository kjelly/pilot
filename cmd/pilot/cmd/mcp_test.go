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
		if !mcpSecretActionNames[a.Name] {
			continue
		}
		seenVaultAction[a.Name] = true
		for _, opt := range a.Optional {
			if opt == "value" {
				t.Fatalf("vault action %q advertises a literal \"value\" field over the real MCP wire: Optional=%v", a.Name, a.Optional)
			}
		}
	}
	for name := range mcpSecretActionNames {
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

// TestMCPServe_Integration_RosterPasswordAndSSHKeysRoundTrip drives a
// real set_user_password (Phase 6 increment 2, value_env-only) plus
// add_ssh_key/delete_ssh_key (not secret — public keys) through the
// real spawned pilot mcp serve binary, mirroring
// TestMCPServe_Integration_VaultPlanApplyRoundTrip's sentinel-scan style
// for the roster password specifically.
func TestMCPServe_Integration_RosterPasswordAndSSHKeysRoundTrip(t *testing.T) {
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	auditDir := t.TempDir()
	writeMinimalRosterFixture(t, dir)
	const envVar = "PILOT_TEST_ROSTER_PASSWORD_SENTINEL_MCP_BINARY"

	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-roster-password-integration-test", Version: "0.0.1"}, nil)
	cmd := exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir, "--allow-write")
	cmd.Env = append(os.Environ(), envVar+"="+vaultSentinelValue)
	transport := &mcp.CommandTransport{Command: cmd}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	scenario := editScenario{Version: 1, Title: "roster password + ssh key mcp round trip", Steps: []editAction{
		{Action: "create_user", User: "erin"},
		{Action: "set_user_password", User: "erin", ValueEnv: envVar},
		{Action: "add_ssh_key", User: "erin", Value: "ssh-ed25519 AAAAERIN erin@laptop"},
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

	rosterData, err := os.ReadFile(filepath.Join(dir, ".vault", "ipa-identity.yaml"))
	if err != nil {
		t.Fatalf("expected the real roster file to exist after apply: %v", err)
	}
	if !strings.Contains(string(rosterData), vaultSentinelValue) {
		t.Fatal("expected the real roster file to contain the sentinel password value")
	}
	if !strings.Contains(string(rosterData), "ssh-ed25519 AAAAERIN erin@laptop") {
		t.Fatal("expected the real roster file to contain the (non-secret) ssh key")
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

// TestMCPServe_Integration_RosterAccessAndSudoRoundTrip drives the full
// Phase 6 increment 3 relational-entity surface (groups, hostgroups,
// HBAC rules, sudo command groups, sudo rules) through the real spawned
// pilot mcp serve binary in one scenario, proving the whole new action
// set works end to end through the real MCP client/plan/apply pipeline,
// not just the in-process driver tests.
func TestMCPServe_Integration_RosterAccessAndSudoRoundTrip(t *testing.T) {
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

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-roster-access-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir, "--allow-write")}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	scenario := editScenario{Version: 1, Title: "roster access + sudo mcp round trip", Steps: []editAction{
		{Action: "create_group", Name: "access-web", Category: "access"},
		{Action: "create_hostgroup", Name: "webhosts"},
		{Action: "create_hbac_rule", Name: "web-login", Groups: []string{"access-web"}, Hostgroups: []string{"webhosts"}, Services: []string{"sshd"}},
		{Action: "create_group", Name: "role-web", Category: "role"},
		{Action: "create_sudo_command_group", Name: "web-restart", Value: "systemctl restart nginx"},
		{Action: "create_sudo_rule", Name: "web-sudo", Groups: []string{"role-web"}, CommandGroups: []string{"web-restart"}},
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

	rosterData, err := os.ReadFile(filepath.Join(dir, ".vault", "ipa-identity.yaml"))
	if err != nil {
		t.Fatalf("expected the real roster file to exist after apply: %v", err)
	}
	for _, want := range []string{"access-web", "webhosts", "web-login", "role-web", "web-restart", "web-sudo"} {
		if !strings.Contains(string(rosterData), want) {
			t.Fatalf("expected the real roster file to contain %q, got:\n%s", want, rosterData)
		}
	}

	// The general-mechanism check this increment adds: pilot_edit_inspect
	// with include_roster must surface the flat entity dump plus the
	// server-resolved effective_hbac_access/effective_sudo_access views
	// over the real MCP wire, not just in-process.
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
	if len(inspect.HBACRules) != 1 || inspect.HBACRules[0].Name != "web-login" {
		t.Fatalf("HBACRules = %+v, want exactly rule web-login", inspect.HBACRules)
	}
	if len(inspect.SudoRules) != 1 || inspect.SudoRules[0].Name != "web-sudo" {
		t.Fatalf("SudoRules = %+v, want exactly rule web-sudo", inspect.SudoRules)
	}
	if len(inspect.EffectiveHBACAccess) != 1 || inspect.EffectiveHBACAccess[0].Rule != "web-login" {
		t.Fatalf("EffectiveHBACAccess = %+v, want exactly rule web-login", inspect.EffectiveHBACAccess)
	}
	if len(inspect.EffectiveSudoAccess) != 1 || inspect.EffectiveSudoAccess[0].Rule != "web-sudo" {
		t.Fatalf("EffectiveSudoAccess = %+v, want exactly rule web-sudo", inspect.EffectiveSudoAccess)
	}

	// The same data must also be reachable as MCP resources — agents that
	// probe resources/list instead of guessing the right tool must not
	// dead-end on "No resources found" (real failure observed 2026-08-05).
	listed, err := session.ListResources(ctx, &mcp.ListResourcesParams{})
	if err != nil {
		t.Fatalf("ListResources() error = %v", err)
	}
	wantURIs := map[string]bool{
		"pilot://hosts":                   false,
		"pilot://roster":                  false,
		"pilot://roster/effective-access": false,
		"pilot://dns":                     false,
	}
	for _, res := range listed.Resources {
		if _, ok := wantURIs[res.URI]; ok {
			wantURIs[res.URI] = true
		}
	}
	for uri, seen := range wantURIs {
		if !seen {
			t.Fatalf("resources/list is missing %s; got %+v", uri, listed.Resources)
		}
	}

	readResult, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: "pilot://roster/effective-access"})
	if err != nil {
		t.Fatalf("ReadResource(pilot://roster/effective-access) error = %v", err)
	}
	if len(readResult.Contents) != 1 || readResult.Contents[0].MIMEType != "application/json" {
		t.Fatalf("ReadResource contents = %+v, want one application/json entry", readResult.Contents)
	}
	var access effectiveAccessResource
	if err := json.Unmarshal([]byte(readResult.Contents[0].Text), &access); err != nil {
		t.Fatalf("unmarshal effective-access resource: %v\n%s", err, readResult.Contents[0].Text)
	}
	if len(access.EffectiveSudoAccess) != 1 || access.EffectiveSudoAccess[0].Rule != "web-sudo" {
		t.Fatalf("resource effective_sudo_access = %+v, want exactly rule web-sudo", access.EffectiveSudoAccess)
	}
	if len(access.EffectiveHBACAccess) != 1 || access.EffectiveHBACAccess[0].Rule != "web-login" {
		t.Fatalf("resource effective_hbac_access = %+v, want exactly rule web-login", access.EffectiveHBACAccess)
	}
}

// TestMCPServe_Integration_DNSManifestRoundTrip drives the full Phase 6
// increment 4 freeipa-dns manifest surface (create manifest, create
// zone, create records both by inventory-host resolution and by
// explicit CNAME values) through the real spawned pilot mcp serve
// binary, proving it works end to end through the real MCP client/
// plan/apply pipeline.
func TestMCPServe_Integration_DNSManifestRoundTrip(t *testing.T) {
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	auditDir := t.TempDir()
	writeDNSTestHostsFile(t, dir)

	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-dns-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir, "--allow-write")}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	scenario := editScenario{Version: 1, Title: "dns manifest mcp round trip", Steps: []editAction{
		{Action: "create_dns_manifest", Domain: "ipa.pilot.internal", Realm: "IPA.PILOT.INTERNAL", Server: "ipa1.ipa.pilot.internal"},
		{Action: "create_dns_zone", Zone: "svc.pilot.internal."},
		{Action: "create_dns_record", Zone: "svc.pilot.internal.", RecordType: "A", RecordName: "nexus", TargetHost: "nexus"},
		{Action: "create_dns_record", Zone: "svc.pilot.internal.", RecordType: "CNAME", RecordName: "www", Values: []string{"nexus.svc.pilot.internal."}},
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

	dnsData, err := os.ReadFile(filepath.Join(dir, "freeipa-dns.yaml"))
	if err != nil {
		t.Fatalf("expected the real freeipa-dns.yaml to exist after apply: %v", err)
	}
	for _, want := range []string{"svc.pilot.internal.", "nexus", "www", "nexus.svc.pilot.internal."} {
		if !strings.Contains(string(dnsData), want) {
			t.Fatalf("expected the real freeipa-dns.yaml to contain %q, got:\n%s", want, dnsData)
		}
	}

	// The general-mechanism check this increment adds: pilot_edit_inspect
	// with include_dns must cross-resolve a record's target_host into its
	// inventory IP over the real MCP wire, not just in-process.
	inspectArgsJSON, _ := json.Marshal(inspectInput{IncludeDNS: true})
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
	if len(inspect.DNSZones) != 1 || inspect.DNSZones[0].Name != "svc.pilot.internal." {
		t.Fatalf("DNSZones = %+v, want exactly zone svc.pilot.internal.", inspect.DNSZones)
	}
	byName := map[string]inspectDNSRecord{}
	for _, r := range inspect.DNSZones[0].Records {
		byName[r.Name] = r
	}
	if nexus, ok := byName["nexus"]; !ok || nexus.ResolvedIP != "192.168.122.81" {
		t.Fatalf("nexus record = %+v, want resolved_ip=192.168.122.81", nexus)
	}
	if www, ok := byName["www"]; !ok || www.ResolvedIP != "" {
		t.Fatalf("www record = %+v, want no resolved_ip (explicit values, not a target host)", www)
	}
}
