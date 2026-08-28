//go:build linux || darwin || freebsd

// mcp_diagnose_test.go spawns the real, compiled `pilot` binary and talks
// to it as a real MCP client, mirroring mcp_test.go's harness. Only
// negative paths are exercised here (flag gating, unknown host, invalid
// param) — none need a live SSH-reachable host, just a real
// ansible-inventory binary and a local-connection fixture (see
// network_check_test.go's requireRealAnsible/writeDiagnoseFixtureInventory
// pattern). A real successful live-host diagnosis is explicitly out of
// scope for this default test suite.
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

func TestMCPServe_Integration_DiagnoseToolsGatedByEnableDiagnoseFlag(t *testing.T) {
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	auditDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	toolsResult, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	for _, tool := range toolsResult.Tools {
		switch tool.Name {
		case "pilot_diagnose_sudo", "pilot_diagnose_dns", "pilot_diagnose_logs", "pilot_diagnose_metrics", "pilot_diagnose_security_logs", "pilot_diagnose_detection":
			t.Fatalf("ListTools() included %q without --enable-diagnose, got %+v", tool.Name, toolsResult.Tools)
		}
	}
}

func TestMCPServe_Integration_DiagnoseToolsListedWhenEnabled(t *testing.T) {
	requireRealAnsible(t)
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	auditDir := t.TempDir()
	inv := writeDiagnoseFixtureInventory(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir, "--enable-diagnose", "--diagnose-inventory", inv)}
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
		"pilot_diagnose_sudo":          false,
		"pilot_diagnose_dns":           false,
		"pilot_diagnose_logs":          false,
		"pilot_diagnose_metrics":       false,
		"pilot_diagnose_security_logs": false,
		"pilot_diagnose_detection":     false,
	}
	for _, tool := range toolsResult.Tools {
		if _, ok := wantTools[tool.Name]; ok {
			wantTools[tool.Name] = true
		}
	}
	for name, seen := range wantTools {
		if !seen {
			t.Fatalf("expected tool %q to be listed with --enable-diagnose, got %+v", name, toolsResult.Tools)
		}
	}
}

func TestMCPServe_Integration_DiagnoseSudoUnknownHostReturnsStructuredError(t *testing.T) {
	requireRealAnsible(t)
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	auditDir := t.TempDir()
	inv := writeDiagnoseFixtureInventory(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir, "--enable-diagnose", "--diagnose-inventory", inv)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "pilot_diagnose_sudo",
		Arguments: map[string]any{"host": "doesnotexist", "user": "alice"},
	})
	if err != nil {
		t.Fatalf("CallTool(pilot_diagnose_sudo) error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("pilot_diagnose_sudo on an unknown host did not return an error: %+v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("error content = %T, want *mcp.TextContent", result.Content[0])
	}
	var toolErr mcpToolError
	if err := json.Unmarshal([]byte(text.Text), &toolErr); err != nil {
		t.Fatalf("parse structured error: %v\nraw: %s", err, text.Text)
	}
	if toolErr.Code != mcpErrHostNotFound {
		t.Fatalf("error code = %q, want %q", toolErr.Code, mcpErrHostNotFound)
	}
}

func TestMCPServe_Integration_DiagnoseDNSInvalidNameReturnsStructuredError(t *testing.T) {
	requireRealAnsible(t)
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	auditDir := t.TempDir()
	inv := writeDiagnoseFixtureInventory(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir, "--enable-diagnose", "--diagnose-inventory", inv)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "pilot_diagnose_dns",
		Arguments: map[string]any{"host": "web1", "name": "not a valid name!"},
	})
	if err != nil {
		t.Fatalf("CallTool(pilot_diagnose_dns) error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("pilot_diagnose_dns with an invalid name did not return an error: %+v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("error content = %T, want *mcp.TextContent", result.Content[0])
	}
	var toolErr mcpToolError
	if err := json.Unmarshal([]byte(text.Text), &toolErr); err != nil {
		t.Fatalf("parse structured error: %v\nraw: %s", err, text.Text)
	}
	if toolErr.Code != mcpErrInvalidParam {
		t.Fatalf("error code = %q, want %q", toolErr.Code, mcpErrInvalidParam)
	}
}

// TestMCPServe_Integration_DiagnoseLogsNoDashboardGroupReturnsStructuredError
// confirms pilot_diagnose_logs auto-resolves the dashboard group itself
// (no host parameter) and fails closed with a structured error, rather
// than panicking or silently picking an arbitrary host, when the
// inventory has no such group.
func TestMCPServe_Integration_DiagnoseLogsNoDashboardGroupReturnsStructuredError(t *testing.T) {
	requireRealAnsible(t)
	binary := buildPilotBinary(t)
	inv := writeDiagnoseFixtureInventory(t) // no "dashboard" group

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", t.TempDir(), "--audit-dir", t.TempDir(), "--enable-diagnose", "--diagnose-inventory", inv)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "pilot_diagnose_logs",
		Arguments: map[string]any{"query": "up"},
	})
	if err != nil {
		t.Fatalf("CallTool(pilot_diagnose_logs) error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("pilot_diagnose_logs with no dashboard group did not return an error: %+v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("error content = %T, want *mcp.TextContent", result.Content[0])
	}
	var toolErr mcpToolError
	if err := json.Unmarshal([]byte(text.Text), &toolErr); err != nil {
		t.Fatalf("parse structured error: %v\nraw: %s", err, text.Text)
	}
	if toolErr.Code != mcpErrInvalidParam {
		t.Fatalf("error code = %q, want %q", toolErr.Code, mcpErrInvalidParam)
	}
}

// TestMCPServe_Integration_DiagnoseSecurityLogsNoDashboardGroupReturnsStructuredError
// confirms pilot_diagnose_security_logs auto-resolves the dashboard group
// itself (no host parameter, every input field optional) and fails closed
// with a structured error rather than silently picking an arbitrary host
// when the inventory has no such group.
func TestMCPServe_Integration_DiagnoseSecurityLogsNoDashboardGroupReturnsStructuredError(t *testing.T) {
	requireRealAnsible(t)
	binary := buildPilotBinary(t)
	inv := writeDiagnoseFixtureInventory(t) // no "dashboard" group

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", t.TempDir(), "--audit-dir", t.TempDir(), "--enable-diagnose", "--diagnose-inventory", inv)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "pilot_diagnose_security_logs",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool(pilot_diagnose_security_logs) error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("pilot_diagnose_security_logs with no dashboard group did not return an error: %+v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("error content = %T, want *mcp.TextContent", result.Content[0])
	}
	var toolErr mcpToolError
	if err := json.Unmarshal([]byte(text.Text), &toolErr); err != nil {
		t.Fatalf("parse structured error: %v\nraw: %s", err, text.Text)
	}
	if toolErr.Code != mcpErrInvalidParam {
		t.Fatalf("error code = %q, want %q", toolErr.Code, mcpErrInvalidParam)
	}
}

// TestMCPServe_Integration_DiagnoseMetricsStartWithoutEndReturnsStructuredError
// confirms the start/end both-or-neither validation runs before any
// inventory resolution — this fixture inventory has no "thanos-query"
// group either, so a bug that skipped straight to inventory resolution
// would surface the wrong error code here.
func TestMCPServe_Integration_DiagnoseMetricsStartWithoutEndReturnsStructuredError(t *testing.T) {
	requireRealAnsible(t)
	binary := buildPilotBinary(t)
	inv := writeDiagnoseFixtureInventory(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", t.TempDir(), "--audit-dir", t.TempDir(), "--enable-diagnose", "--diagnose-inventory", inv)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "pilot_diagnose_metrics",
		Arguments: map[string]any{"query": "up", "start": "2026-01-01T00:00:00Z"},
	})
	if err != nil {
		t.Fatalf("CallTool(pilot_diagnose_metrics) error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("pilot_diagnose_metrics with start but no end did not return an error: %+v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("error content = %T, want *mcp.TextContent", result.Content[0])
	}
	var toolErr mcpToolError
	if err := json.Unmarshal([]byte(text.Text), &toolErr); err != nil {
		t.Fatalf("parse structured error: %v\nraw: %s", err, text.Text)
	}
	if toolErr.Code != mcpErrInvalidParam {
		t.Fatalf("error code = %q, want %q", toolErr.Code, mcpErrInvalidParam)
	}
}

func TestMCPServe_Integration_DiagnoseDetectionRequiresSignalIDOrPilotHost(t *testing.T) {
	requireRealAnsible(t)
	binary := buildPilotBinary(t)
	inv := writeDiagnoseFixtureInventory(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", t.TempDir(), "--audit-dir", t.TempDir(), "--enable-diagnose", "--diagnose-inventory", inv)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "pilot_diagnose_detection",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool(pilot_diagnose_detection) error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("pilot_diagnose_detection with neither signal_id nor pilot_host did not return an error: %+v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("error content = %T, want *mcp.TextContent", result.Content[0])
	}
	var toolErr mcpToolError
	if err := json.Unmarshal([]byte(text.Text), &toolErr); err != nil {
		t.Fatalf("parse structured error: %v\nraw: %s", err, text.Text)
	}
	if toolErr.Code != mcpErrInvalidParam {
		t.Fatalf("error code = %q, want %q", toolErr.Code, mcpErrInvalidParam)
	}
}

func TestMCPServe_Integration_DiagnoseDetectionMalformedSignalIDReturnsStructuredError(t *testing.T) {
	requireRealAnsible(t)
	binary := buildPilotBinary(t)
	inv := writeDiagnoseFixtureInventory(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", t.TempDir(), "--audit-dir", t.TempDir(), "--enable-diagnose", "--diagnose-inventory", inv)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "pilot_diagnose_detection",
		Arguments: map[string]any{"signal_id": "not-a-valid-ulid; rm -rf /"},
	})
	if err != nil {
		t.Fatalf("CallTool(pilot_diagnose_detection) error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("pilot_diagnose_detection with a malformed signal_id did not return an error: %+v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("error content = %T, want *mcp.TextContent", result.Content[0])
	}
	var toolErr mcpToolError
	if err := json.Unmarshal([]byte(text.Text), &toolErr); err != nil {
		t.Fatalf("parse structured error: %v\nraw: %s", err, text.Text)
	}
	if toolErr.Code != mcpErrInvalidParam {
		t.Fatalf("error code = %q, want %q", toolErr.Code, mcpErrInvalidParam)
	}
}

// TestMCPServe_Integration_DiagnoseInventoryDefaultsToDirInventoryYml proves
// omitting --diagnose-inventory falls back to <dir>/inventory.yml (the file
// pilot edit --dir <dir> / pilot inventory generate actually write there),
// instead of the old "requires --diagnose-inventory" hard startup failure —
// this is what makes the flag-value-swallowing typo class of misconfig
// (`--diagnose-inventory --dir /path`, where pflag hands --dir's value to
// --diagnose-inventory and the real --dir value is silently dropped as a
// stray positional arg) harmless in the common case where both flags would
// have pointed at the same directory anyway.
func TestMCPServe_Integration_DiagnoseInventoryDefaultsToDirInventoryYml(t *testing.T) {
	requireRealAnsible(t)
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	auditDir := t.TempDir()
	inv := `all:
  hosts:
    web1: {ansible_connection: local, ansible_host: 127.0.0.1}
`
	if err := os.WriteFile(filepath.Join(dir, "inventory.yml"), []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir, "--enable-diagnose")}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	// A deliberately-unknown host: if the <dir>/inventory.yml default had
	// NOT been picked up, inventory resolution itself would fail first
	// (mcpErrInvalidParam, "resolve inventory: ..."). Getting
	// mcpErrHostNotFound instead proves ansible-inventory successfully
	// read <dir>/inventory.yml with no --diagnose-inventory flag at all.
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "pilot_diagnose_sudo",
		Arguments: map[string]any{"host": "doesnotexist", "user": "alice"},
	})
	if err != nil {
		t.Fatalf("CallTool(pilot_diagnose_sudo) error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("pilot_diagnose_sudo with unknown host did not return an error: %+v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("error content = %T, want *mcp.TextContent", result.Content[0])
	}
	var toolErr mcpToolError
	if err := json.Unmarshal([]byte(text.Text), &toolErr); err != nil {
		t.Fatalf("parse structured error: %v\nraw: %s", err, text.Text)
	}
	if toolErr.Code != mcpErrHostNotFound {
		t.Fatalf("error code = %q, want %q (raw: %s)", toolErr.Code, mcpErrHostNotFound, text.Text)
	}
}

// TestMCPServe_Integration_DiagnoseWithoutInventoryFlagOrFileDegradesAtCallTime
// confirms that with neither --diagnose-inventory nor a <dir>/inventory.yml
// present, the server still starts successfully (tools list fine) — the
// missing-inventory case surfaces as a structured per-call tool error, not a
// startup crash — and that the error is a clear invalid_param "inventory file
// not found: <path>" rather than host_not_found. Without
// resolveDiagnoseInventory's explicit os.Stat check, this would come back as
// host_not_found instead: `ansible-inventory --list -i <missing-file>` does
// not error — it warns on stderr and falls back to an empty "only implicit
// localhost is available" inventory (exit 0) — which would be
// indistinguishable from the inventory genuinely lacking that host.
func TestMCPServe_Integration_DiagnoseWithoutInventoryFlagOrFileDegradesAtCallTime(t *testing.T) {
	requireRealAnsible(t)
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	auditDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir, "--enable-diagnose")}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	if _, err := session.ListTools(ctx, nil); err != nil {
		t.Fatalf("ListTools() error = %v (server should start even with no inventory available)", err)
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "pilot_diagnose_sudo",
		Arguments: map[string]any{"host": "doesnotexist", "user": "alice"},
	})
	if err != nil {
		t.Fatalf("CallTool(pilot_diagnose_sudo) error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("pilot_diagnose_sudo with no inventory available did not return an error: %+v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("error content = %T, want *mcp.TextContent", result.Content[0])
	}
	var toolErr mcpToolError
	if err := json.Unmarshal([]byte(text.Text), &toolErr); err != nil {
		t.Fatalf("parse structured error: %v\nraw: %s", err, text.Text)
	}
	if toolErr.Code != mcpErrInvalidParam {
		t.Fatalf("error code = %q, want %q (raw: %s)", toolErr.Code, mcpErrInvalidParam, text.Text)
	}
	if !strings.Contains(toolErr.Message, "inventory file not found") {
		t.Fatalf("error message = %q, want it to mention \"inventory file not found\"", toolErr.Message)
	}
}

// TestMCPServe_Integration_DiagnoseRunIsIndependentOfEnableDiagnose confirms
// pilot_diagnose_run is gated by its own flag, not folded into
// --enable-diagnose: with only --enable-diagnose set, pilot_diagnose_run
// must not be listed; with only --enable-diagnose-raw set, it must be.
func TestMCPServe_Integration_DiagnoseRunIsIndependentOfEnableDiagnose(t *testing.T) {
	requireRealAnsible(t)
	binary := buildPilotBinary(t)
	inv := writeDiagnoseFixtureInventory(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", t.TempDir(), "--audit-dir", t.TempDir(), "--enable-diagnose", "--diagnose-inventory", inv)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	toolsResult, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	for _, tool := range toolsResult.Tools {
		if tool.Name == "pilot_diagnose_run" {
			t.Fatalf("ListTools() included pilot_diagnose_run with only --enable-diagnose set, got %+v", toolsResult.Tools)
		}
	}
}

func TestMCPServe_Integration_DiagnoseRunListedWhenRawEnabled(t *testing.T) {
	requireRealAnsible(t)
	binary := buildPilotBinary(t)
	inv := writeDiagnoseFixtureInventory(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", t.TempDir(), "--audit-dir", t.TempDir(), "--enable-diagnose-raw", "--diagnose-inventory", inv)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	toolsResult, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	found := false
	for _, tool := range toolsResult.Tools {
		if tool.Name == "pilot_diagnose_run" {
			found = true
		}
		if tool.Name == "pilot_diagnose_sudo" || tool.Name == "pilot_diagnose_dns" {
			t.Fatalf("ListTools() included %q with only --enable-diagnose-raw set, got %+v", tool.Name, toolsResult.Tools)
		}
	}
	if !found {
		t.Fatalf("expected pilot_diagnose_run to be listed with --enable-diagnose-raw, got %+v", toolsResult.Tools)
	}
}

func TestMCPServe_Integration_DiagnoseRunUnknownHostReturnsStructuredError(t *testing.T) {
	requireRealAnsible(t)
	binary := buildPilotBinary(t)
	inv := writeDiagnoseFixtureInventory(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, "mcp", "serve", "--dir", t.TempDir(), "--audit-dir", t.TempDir(), "--enable-diagnose-raw", "--diagnose-inventory", inv)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "pilot_diagnose_run",
		Arguments: map[string]any{"host": "doesnotexist", "command": "id alice"},
	})
	if err != nil {
		t.Fatalf("CallTool(pilot_diagnose_run) error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("pilot_diagnose_run on an unknown host did not return an error: %+v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("error content = %T, want *mcp.TextContent", result.Content[0])
	}
	var toolErr mcpToolError
	if err := json.Unmarshal([]byte(text.Text), &toolErr); err != nil {
		t.Fatalf("parse structured error: %v\nraw: %s", err, text.Text)
	}
	if toolErr.Code != mcpErrHostNotFound {
		t.Fatalf("error code = %q, want %q", toolErr.Code, mcpErrHostNotFound)
	}
}
