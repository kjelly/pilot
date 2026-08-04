package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPAllowedActionNames_IncludesEveryRegistryAction(t *testing.T) {
	allowed := mcpAllowedActionNames()
	registry := editActionRegistry()
	if len(allowed) != len(registry) {
		t.Fatalf("allowed has %d entries, want exactly the %d registry actions", len(allowed), len(registry))
	}
	for _, def := range registry {
		if !allowed[def.Spec.Name] {
			t.Fatalf("expected action %q to be allowed (Phase 5: vault actions are no longer excluded)", def.Spec.Name)
		}
	}
	for name := range mcpVaultActionNames {
		if !allowed[name] {
			t.Fatalf("expected vault action %q to be allowed (value_env-only policy is enforced separately)", name)
		}
	}
}

func TestCapabilitiesHandler_IncludesVaultActionsWithValueEnvOnlySchema(t *testing.T) {
	handler := capabilitiesHandler(editMCPToolsOptions{Dir: "/workspace", WriteEnabled: true})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, capabilitiesInput{})
	if err != nil {
		t.Fatalf("capabilitiesHandler() error = %v", err)
	}
	if out.Workspace != "/workspace" || !out.WriteEnabled {
		t.Fatalf("out = %+v, want workspace=/workspace write_enabled=true", out)
	}
	if out.Unsupported["deploy"] == "" {
		t.Fatal(`expected Unsupported["deploy"] to be set`)
	}
	for name := range mcpVaultActionNames {
		if _, stillExcluded := out.Unsupported[name]; stillExcluded {
			t.Fatalf("vault action %q should no longer be in Unsupported (Phase 5)", name)
		}
	}

	seen := map[string]bool{}
	for _, a := range out.Actions {
		seen[a.Name] = true
	}
	for name := range mcpVaultActionNames {
		if !seen[name] {
			t.Fatalf("expected vault action %q to be listed in Actions", name)
		}
	}

	for _, a := range out.Actions {
		if !mcpVaultActionNames[a.Name] {
			continue
		}
		for _, opt := range a.Optional {
			if opt == "value" {
				t.Fatalf("action %q advertises a literal \"value\" field; MCP requires value_env-only, got Optional=%v", a.Name, a.Optional)
			}
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

func TestInspectHandler_VaultMetadataListsKeyNamesNotValues(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: super-secret-value\nother_key: another-secret\n")

	handler := inspectHandler(editMCPToolsOptions{Dir: dir})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeVaultMetadata: true})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if len(out.VaultFiles) != 1 {
		t.Fatalf("VaultFiles = %+v, want exactly one entry", out.VaultFiles)
	}
	vf := out.VaultFiles[0]
	if vf.Filename != "main.yaml" || vf.Encrypted {
		t.Fatalf("vf = %+v, want filename=main.yaml encrypted=false", vf)
	}
	wantKeys := map[string]bool{"ipa_admin_password": true, "other_key": true}
	if len(vf.Keys) != len(wantKeys) {
		t.Fatalf("Keys = %v, want %v", vf.Keys, wantKeys)
	}
	for _, k := range vf.Keys {
		if !wantKeys[k] {
			t.Fatalf("unexpected key %q in %v", k, vf.Keys)
		}
	}

	// Serialize the whole output and confirm no secret value leaked in.
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal inspectOutput: %v", err)
	}
	if strings.Contains(string(data), "super-secret-value") || strings.Contains(string(data), "another-secret") {
		t.Fatalf("inspect output leaked a vault value: %s", data)
	}
}

func TestInspectHandler_EncryptedVaultFileReportsEncryptedWithNoKeys(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, ".vault", "main.yaml"), "$ANSIBLE_VAULT;1.1;AES256\n663864653966...\n")

	handler := inspectHandler(editMCPToolsOptions{Dir: dir})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeVaultMetadata: true})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if len(out.VaultFiles) != 1 || !out.VaultFiles[0].Encrypted {
		t.Fatalf("VaultFiles = %+v, want one encrypted entry", out.VaultFiles)
	}
	if len(out.VaultFiles[0].Keys) != 0 {
		t.Fatalf("expected no keys for an encrypted vault file, got %v", out.VaultFiles[0].Keys)
	}
}

func TestInspectHandler_OmitsVaultFilesWhenNotRequested(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, ".vault", "main.yaml"), "x: y\n")

	handler := inspectHandler(editMCPToolsOptions{Dir: dir})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeVaultMetadata: false})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if out.VaultFiles != nil {
		t.Fatalf("VaultFiles = %+v, want nil when include_vault_metadata is false", out.VaultFiles)
	}
}

func TestInspectHandler_RosterListsUsersWithNonSecretFieldsOnly(t *testing.T) {
	dir := t.TempDir()
	writeMinimalRosterFixture(t, dir)

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "alice"},
		{Action: "set_user_field", User: "alice", Field: "email", Value: "alice@example.com"},
		{Action: "set_user_field", User: "alice", Field: "uid", Value: "10001"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	handler := inspectHandler(editMCPToolsOptions{Dir: dir})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeRoster: true})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if len(out.RosterUsers) != 1 {
		t.Fatalf("RosterUsers = %+v, want exactly one entry", out.RosterUsers)
	}
	ru := out.RosterUsers[0]
	if ru.Name != "alice" || ru.Email != "alice@example.com" || ru.UID == nil || *ru.UID != 10001 {
		t.Fatalf("ru = %+v", ru)
	}

	// Serialize and confirm no password/ssh-key field ever appears —
	// inspectRosterUser's type doesn't have those fields at all, but
	// this also guards against a future field addition leaking one.
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal inspectOutput: %v", err)
	}
	if strings.Contains(string(data), "password") || strings.Contains(string(data), "ssh_keys") {
		t.Fatalf("inspect output leaked a secret-adjacent field: %s", data)
	}
}

func TestInspectHandler_OmitsRosterWhenNotRequested(t *testing.T) {
	dir := t.TempDir()
	writeMinimalRosterFixture(t, dir)

	handler := inspectHandler(editMCPToolsOptions{Dir: dir})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeRoster: false})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if out.RosterUsers != nil {
		t.Fatalf("RosterUsers = %+v, want nil when include_roster is false", out.RosterUsers)
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
			// deploy/reconcile run through a different execution path
			// entirely (prompt_automation.go) and are never in
			// editActionRegistry() — genuinely unsupported by MCP,
			// unlike the vault actions (Phase 5: allowed, but
			// value_env-only — see TestPlanHandler_RejectsLiteralVaultValue).
			{Action: "deploy", Inventory: "inventory.yml"},
		}},
	})
	if err != nil {
		t.Fatalf("planHandler() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an error result for an unsupported action")
	}
	if out.PlanID != "" {
		t.Fatalf("expected zero-value output on error, got %+v", out)
	}
	toolErr := decodeToolError(t, result)
	if toolErr.Code != mcpErrUnsupportedAction {
		t.Fatalf("Code = %q, want %q", toolErr.Code, mcpErrUnsupportedAction)
	}
}

func TestPlanHandler_RejectsLiteralVaultValue(t *testing.T) {
	dir := t.TempDir()
	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	handler := planHandler(editMCPToolsOptions{Dir: dir, AuditDir: t.TempDir()})
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, planInput{
		BaseRevision: rev,
		Scenario: editScenario{Version: 1, Steps: []editAction{
			{Action: "set_vault_value", File: "main.yaml", Key: "x", Value: "literal-secret-not-allowed"},
		}},
	})
	if err != nil {
		t.Fatalf("planHandler() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an error result for a vault action carrying a literal value")
	}
	if out.PlanID != "" {
		t.Fatalf("expected zero-value output on error, got %+v", out)
	}
	toolErr := decodeToolError(t, result)
	if toolErr.Code != mcpErrSecretPolicyViolation {
		t.Fatalf("Code = %q, want %q", toolErr.Code, mcpErrSecretPolicyViolation)
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

// TestCapabilitiesHandler_ListsRosterUserActions asserts
// create_user/set_user_field are automatically exposed once they exist
// in editActionRegistry() — capabilitiesHandler needed zero roster-
// specific code changes to pick them up (Phase 5's "include everything
// in the registry" default).
func TestCapabilitiesHandler_ListsRosterUserActions(t *testing.T) {
	handler := capabilitiesHandler(editMCPToolsOptions{Dir: "/workspace"})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, capabilitiesInput{})
	if err != nil {
		t.Fatalf("capabilitiesHandler() error = %v", err)
	}
	seen := map[string]bool{}
	for _, a := range out.Actions {
		seen[a.Name] = true
	}
	for _, name := range []string{"create_user", "set_user_field"} {
		if !seen[name] {
			t.Fatalf("expected capabilities to list %q", name)
		}
	}
}

// TestPlanAndApplyHandler_RosterScenarioRoundTrip asserts
// planHandler/applyHandler round-trip a roster scenario correctly with
// zero roster-specific plan/apply code — planEditScenario/
// applyEditScenario are already generic over editScenario, and the
// roster file was already swept into managedFileEntries (tagged
// IsSecret) before this increment even started.
func TestPlanAndApplyHandler_RosterScenarioRoundTrip(t *testing.T) {
	dir := t.TempDir()
	auditDir := t.TempDir()
	rosterPath := writeMinimalRosterFixture(t, dir)
	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	scenario := editScenario{Version: 1, Title: "roster round trip", Steps: []editAction{
		{Action: "create_user", User: "carol"},
		{Action: "set_user_field", User: "carol", Field: "email", Value: "carol@example.com"},
	}}

	planH := planHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir})
	planResult, planOut, err := planH(context.Background(), &mcp.CallToolRequest{}, planInput{BaseRevision: rev, Scenario: scenario})
	if err != nil {
		t.Fatalf("planHandler() error = %v", err)
	}
	if planResult != nil {
		t.Fatalf("expected a successful plan, got error result: %+v", planResult.Content)
	}
	if _, found, err := inventory.RosterUser(rosterPath, "carol"); err != nil || found {
		t.Fatalf("expected carol not to exist in the real workspace after a plan (found=%v, err=%v)", found, err)
	}

	applyH := applyHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir, WriteEnabled: true})
	applyResult, applyOut, err := applyH(context.Background(), &mcp.CallToolRequest{}, applyInput{PlanID: planOut.PlanID, ExpectedRevision: rev})
	if err != nil {
		t.Fatalf("applyHandler() error = %v", err)
	}
	if applyResult != nil {
		t.Fatalf("expected a successful apply, got error result: %+v", applyResult.Content)
	}
	if applyOut.Result != "applied" || applyOut.RolledBack {
		t.Fatalf("applyOut = %+v", applyOut)
	}
	fields, found, err := inventory.RosterUser(rosterPath, "carol")
	if err != nil {
		t.Fatalf("RosterUser() error = %v", err)
	}
	if !found || fields["email"] != "carol@example.com" {
		t.Fatalf("expected carol to exist with email set after apply, fields=%+v found=%v", fields, found)
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
