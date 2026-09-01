//go:build linux || darwin || freebsd

// mcp_repair_gate_test.go spawns the real, compiled `pilot` binary and
// proves Agent Monitoring Phase 3's central authority-separation
// invariant (design doc §2/§3): an MCP session started with
// --enable-diagnose alone — exactly the session an external Agent
// Runtime is meant to receive — must NEVER see any pilot_repair_* tool,
// regardless of what else is enabled. --enable-repair is the only flag
// that exposes the family, and it does so independently of
// --enable-diagnose/--enable-diagnose-raw/--allow-write.
package cmd

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var repairToolNames = []string{"pilot_repair_capabilities", "pilot_repair_plan", "pilot_repair_apply"}

func listToolNames(t *testing.T, ctx context.Context, binary string, args ...string) map[string]bool {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-repair-gate-test", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binary, args...)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()
	result, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	names := map[string]bool{}
	for _, tool := range result.Tools {
		names[tool.Name] = true
	}
	return names
}

func TestMCPServe_Integration_RepairToolsAbsentWithNoFlags(t *testing.T) {
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	names := listToolNames(t, ctx, binary, "mcp", "serve", "--dir", dir, "--audit-dir", t.TempDir())
	for _, want := range repairToolNames {
		if names[want] {
			t.Fatalf("ListTools() included %q with no flags set, got %v", want, names)
		}
	}
}

// TestMCPServe_Integration_RepairToolsAbsentFromObserveOnlyDiagnoseSession
// is THE test that matters most for Phase 3's own stated safety
// invariant: an Agent Runtime session (--enable-diagnose, exactly what
// spec §11 says the Agent connects through) must never gain repair
// capability just because diagnose happens to be on.
func TestMCPServe_Integration_RepairToolsAbsentFromObserveOnlyDiagnoseSession(t *testing.T) {
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	inv := writeDiagnoseFixtureInventory(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	names := listToolNames(t, ctx, binary, "mcp", "serve", "--dir", dir, "--audit-dir", t.TempDir(),
		"--enable-diagnose", "--diagnose-inventory", inv)
	for _, want := range repairToolNames {
		if names[want] {
			t.Fatalf("ListTools() included %q in an --enable-diagnose-only (observe) session — the Agent must NEVER see repair capability; got %v", want, names)
		}
	}
	if !names["pilot_diagnose_sudo"] {
		t.Fatal("sanity check failed: --enable-diagnose should still list its own tools")
	}
}

func TestMCPServe_Integration_RepairToolsListedWhenEnabled(t *testing.T) {
	binary := buildPilotBinary(t)
	dir := t.TempDir()
	inv := writeDiagnoseFixtureInventory(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	names := listToolNames(t, ctx, binary, "mcp", "serve", "--dir", dir, "--audit-dir", t.TempDir(),
		"--enable-repair", "--diagnose-inventory", inv)
	for _, want := range repairToolNames {
		if !names[want] {
			t.Fatalf("ListTools() missing %q with --enable-repair set, got %v", want, names)
		}
	}
	// --enable-repair alone must not also turn on diagnose or raw-write.
	if names["pilot_diagnose_sudo"] {
		t.Error("--enable-repair must not also enable pilot_diagnose_* — the two flags are independent")
	}
}
