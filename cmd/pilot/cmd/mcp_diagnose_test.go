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
	"os/exec"
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
		if tool.Name == "pilot_diagnose_sudo" || tool.Name == "pilot_diagnose_dns" {
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
	wantTools := map[string]bool{"pilot_diagnose_sudo": false, "pilot_diagnose_dns": false}
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

func TestMCPServe_EnableDiagnoseWithoutInventoryFailsClosedAtStartup(t *testing.T) {
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	auditDir := t.TempDir()

	cmd := exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir, "--enable-diagnose")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected --enable-diagnose without --diagnose-inventory to fail closed at startup, got no error; output: %s", out)
	}
}

func TestMCPServe_EnableDiagnoseRawWithoutInventoryFailsClosedAtStartup(t *testing.T) {
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	auditDir := t.TempDir()

	cmd := exec.Command(binary, "mcp", "serve", "--dir", dir, "--audit-dir", auditDir, "--enable-diagnose-raw")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected --enable-diagnose-raw without --diagnose-inventory to fail closed at startup, got no error; output: %s", out)
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
