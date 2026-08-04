// edit_audit_artifact_vault_test.go is Phase 5's primary deliverable:
// firsthand proof (not just an inference from reading library code)
// that a real secret value, driven through a real vault action and a
// real castAuditRecorder/trace sink/audit-artifact writer, never
// appears anywhere except the actual .vault/ file it was written to.
// This is spec's AC9 checklist, applied to the full plan/apply engine
// rather than asserted in isolation.
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const vaultSentinelValue = "PHASE5-SENTINEL-DO-NOT-LEAK-3f9a7c"

// assertSentinelAbsent fails the test if needle appears in haystack,
// including a snippet of context for debugging.
func assertSentinelAbsent(t *testing.T, label, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		idx := strings.Index(haystack, needle)
		start := max(0, idx-40)
		end := min(len(haystack), idx+len(needle)+40)
		t.Fatalf("sentinel leaked into %s:\n...%s...", label, haystack[start:end])
	}
}

func TestApplyEditScenario_VaultSentinelNeverLeaksIntoAuditArtifacts(t *testing.T) {
	const envVar = "PILOT_TEST_VAULT_SENTINEL_APPLY"
	t.Setenv(envVar, vaultSentinelValue)

	dir := t.TempDir()
	auditDir := t.TempDir()
	scenario := editScenario{Version: 1, Title: "vault sentinel test", Steps: []editAction{
		{Action: "add_vault_key", File: "main.yaml", Key: "test_secret", ValueEnv: envVar},
		{Action: "save_vault", File: "main.yaml"},
	}}

	var castBuf bytes.Buffer
	recorder, err := newCastAuditRecorder(&castBuf, scenario.Title, castTerminalWidth, castTerminalHeight)
	if err != nil {
		t.Fatalf("newCastAuditRecorder() error = %v", err)
	}
	tracePath := filepath.Join(auditDir, "trace.jsonl")
	sink, err := newAutomationTraceSink(tracePath)
	if err != nil {
		t.Fatalf("newAutomationTraceSink() error = %v", err)
	}

	opts := editAgentSessionOptions{
		Trace:    func(event automationTraceEvent) { sink.add(event) },
		Recorder: recorder,
	}
	result, err := applyEditScenario(dir, "vault-sentinel-session", scenario, opts)
	if err != nil {
		t.Fatalf("applyEditScenario() error = %v", err)
	}
	if err := sink.close(); err != nil {
		t.Fatalf("sink.close() error = %v", err)
	}
	if result.RolledBack {
		t.Fatalf("expected a clean apply, got rolled back (ScenarioErr=%v)", result.ScenarioErr)
	}

	meta := auditMetadata{SessionID: "vault-sentinel-session", Kind: "apply", Workspace: dir}
	if err := writeApplyAuditArtifacts(auditDir, meta, scenario, result); err != nil {
		t.Fatalf("writeApplyAuditArtifacts() error = %v", err)
	}

	// The real vault file DID get the secret — proves the action
	// actually worked rather than silently no-op'ing.
	vaultData, err := os.ReadFile(filepath.Join(dir, ".vault", "main.yaml"))
	if err != nil {
		t.Fatalf("read real .vault/main.yaml: %v", err)
	}
	if !strings.Contains(string(vaultData), vaultSentinelValue) {
		t.Fatalf("expected the real vault file to contain the sentinel value, got:\n%s", vaultData)
	}

	// Everything else must never contain it.
	assertSentinelAbsent(t, "session.cast", castBuf.String(), vaultSentinelValue)

	traceData, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("read trace.jsonl: %v", err)
	}
	assertSentinelAbsent(t, "trace.jsonl", string(traceData), vaultSentinelValue)

	for _, name := range []string{
		"metadata.json", "scenario.redacted.json", "diff.patch", "validation.json",
		"managed-files-before.json", "managed-files-after.json", "result.json",
	} {
		data, err := os.ReadFile(filepath.Join(auditDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		assertSentinelAbsent(t, name, string(data), vaultSentinelValue)
	}

	// result.Diff itself (in-memory, before it was even written to disk)
	// must be redacted too.
	assertSentinelAbsent(t, "in-memory result.Diff", result.Diff, vaultSentinelValue)
	if !result.RedactedDiff {
		t.Fatal("expected RedactedDiff = true for a scenario that touched a vault file")
	}
}

func TestPlanEditScenario_VaultSentinelNeverLeaksIntoAuditArtifacts(t *testing.T) {
	const envVar = "PILOT_TEST_VAULT_SENTINEL_PLAN"
	t.Setenv(envVar, vaultSentinelValue)

	dir := t.TempDir()
	auditDir := t.TempDir()
	scenario := editScenario{Version: 1, Title: "vault sentinel plan test", Steps: []editAction{
		{Action: "add_vault_key", File: "main.yaml", Key: "test_secret", ValueEnv: envVar},
		{Action: "save_vault", File: "main.yaml"},
	}}

	var castBuf bytes.Buffer
	recorder, err := newCastAuditRecorder(&castBuf, scenario.Title, castTerminalWidth, castTerminalHeight)
	if err != nil {
		t.Fatalf("newCastAuditRecorder() error = %v", err)
	}
	tracePath := filepath.Join(auditDir, "trace.jsonl")
	sink, err := newAutomationTraceSink(tracePath)
	if err != nil {
		t.Fatalf("newAutomationTraceSink() error = %v", err)
	}

	opts := editAgentSessionOptions{
		Trace:    func(event automationTraceEvent) { sink.add(event) },
		Recorder: recorder,
	}
	result, err := planEditScenario(dir, scenario, opts)
	if err != nil {
		t.Fatalf("planEditScenario() error = %v", err)
	}
	if err := sink.close(); err != nil {
		t.Fatalf("sink.close() error = %v", err)
	}

	meta := auditMetadata{SessionID: "vault-sentinel-plan", Kind: "plan", Workspace: dir}
	if err := writePlanAuditArtifacts(auditDir, meta, scenario, result); err != nil {
		t.Fatalf("writePlanAuditArtifacts() error = %v", err)
	}

	// A plan must never touch the real workspace at all — the real
	// .vault/main.yaml must not even exist.
	if _, err := os.Stat(filepath.Join(dir, ".vault", "main.yaml")); !os.IsNotExist(err) {
		t.Fatalf("expected the real .vault/main.yaml to not exist after a plan, stat error = %v", err)
	}

	assertSentinelAbsent(t, "session.cast", castBuf.String(), vaultSentinelValue)
	traceData, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("read trace.jsonl: %v", err)
	}
	assertSentinelAbsent(t, "trace.jsonl", string(traceData), vaultSentinelValue)
	for _, name := range []string{"metadata.json", "scenario.redacted.json", "diff.patch", "validation.json"} {
		data, err := os.ReadFile(filepath.Join(auditDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		assertSentinelAbsent(t, name, string(data), vaultSentinelValue)
	}
	if !result.RedactedDiff {
		t.Fatal("expected RedactedDiff = true for a plan that touched a vault file")
	}
}

// TestMCPApplyHandler_VaultSentinelNeverLeaksInToolResult drives the
// same scenario through the real MCP handlers (planHandler then
// applyHandler), checking the sentinel never appears in either tool's
// CallToolResult — not just in the on-disk artifacts the two tests
// above already cover.
func TestMCPApplyHandler_VaultSentinelNeverLeaksInToolResult(t *testing.T) {
	const envVar = "PILOT_TEST_VAULT_SENTINEL_MCP"
	t.Setenv(envVar, vaultSentinelValue)

	dir := t.TempDir()
	auditDir := t.TempDir()
	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	scenario := editScenario{Version: 1, Title: "mcp vault sentinel", Steps: []editAction{
		{Action: "add_vault_key", File: "main.yaml", Key: "test_secret", ValueEnv: envVar},
		{Action: "save_vault", File: "main.yaml"},
	}}

	planH := planHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir})
	planResult, planOut, err := planH(context.Background(), &mcp.CallToolRequest{}, planInput{BaseRevision: rev, Scenario: scenario})
	if err != nil {
		t.Fatalf("planHandler() error = %v", err)
	}
	if planResult != nil {
		t.Fatalf("expected a successful plan, got error result: %+v", planResult.Content)
	}
	planResultJSON, _ := json.Marshal(planOut)
	assertSentinelAbsent(t, "plan tool result JSON", string(planResultJSON), vaultSentinelValue)

	applyH := applyHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir, WriteEnabled: true})
	applyResult, applyOut, err := applyH(context.Background(), &mcp.CallToolRequest{}, applyInput{PlanID: planOut.PlanID, ExpectedRevision: rev})
	if err != nil {
		t.Fatalf("applyHandler() error = %v", err)
	}
	if applyResult != nil {
		t.Fatalf("expected a successful apply, got error result: %+v", applyResult.Content)
	}
	applyResultJSON, _ := json.Marshal(applyOut)
	assertSentinelAbsent(t, "apply tool result JSON", string(applyResultJSON), vaultSentinelValue)

	// The real workspace's vault file must contain it for real.
	vaultData, err := os.ReadFile(filepath.Join(dir, ".vault", "main.yaml"))
	if err != nil {
		t.Fatalf("read real .vault/main.yaml: %v", err)
	}
	if !strings.Contains(string(vaultData), vaultSentinelValue) {
		t.Fatal("expected the real vault file to contain the sentinel value after apply")
	}

	// Sweep every file under both audit directories (plan's and
	// apply's) — the literal, filesystem-level proof, not just the
	// specific files each engine function is known to write.
	for _, root := range []string{planOut.Audit.Directory, applyOut.Audit.Directory} {
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

func TestApplyHandler_RejectsLiteralVaultValue(t *testing.T) {
	dir := t.TempDir()
	auditDir := t.TempDir()
	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "add_vault_key", File: "main.yaml", Key: "x", Value: "literal-secret-not-allowed"},
	}}
	planDir := filepath.Join(auditDir, "20260101T000000Z-hand-written-plan-plan")
	if err := os.MkdirAll(planDir, 0o755); err != nil {
		t.Fatalf("mkdir planDir: %v", err)
	}
	if err := writeJSONFile(filepath.Join(planDir, "metadata.json"), auditMetadata{WorkspaceRevision: rev}); err != nil {
		t.Fatalf("write plan metadata.json: %v", err)
	}
	if err := writeJSONFile(filepath.Join(planDir, "scenario.redacted.json"), scenario); err != nil {
		t.Fatalf("write plan scenario.redacted.json: %v", err)
	}

	handler := applyHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir, WriteEnabled: true})
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, applyInput{PlanID: "hand-written-plan", ExpectedRevision: rev})
	if err != nil {
		t.Fatalf("applyHandler() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an error result for a vault action carrying a literal value")
	}
	toolErr := decodeToolError(t, result)
	if toolErr.Code != mcpErrSecretPolicyViolation {
		t.Fatalf("Code = %q, want %q", toolErr.Code, mcpErrSecretPolicyViolation)
	}
}
