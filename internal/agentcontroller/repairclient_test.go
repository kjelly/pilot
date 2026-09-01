package agentcontroller

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var (
	repairPilotBinaryOnce sync.Once
	repairPilotBinaryPath string
	repairPilotBinaryErr  error
)

// buildRealPilotBinary compiles the real cmd/pilot binary once (shared
// across this package's tests) so RepairClient can be tested against
// pilot's OWN actual repair MCP tools — a real subprocess, real stdio
// MCP handshake, real tool schema — not a mock of the protocol.
func buildRealPilotBinary(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("ansible"); err != nil {
		t.Skip("ansible not installed; skipping real-pilot-binary repair client test")
	}
	repairPilotBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "pilot-repairclient")
		if err != nil {
			repairPilotBinaryErr = err
			return
		}
		out := filepath.Join(dir, "pilot")
		repoRoot, err := repoRootForRepairClientTest()
		if err != nil {
			repairPilotBinaryErr = err
			return
		}
		cmd := exec.Command("go", "build", "-o", out, "./cmd/pilot")
		cmd.Dir = repoRoot
		combined, err := cmd.CombinedOutput()
		if err != nil {
			repairPilotBinaryErr = fmt.Errorf("build pilot binary: %w\n%s", err, combined)
			return
		}
		repairPilotBinaryPath = out
	})
	if repairPilotBinaryErr != nil {
		t.Fatalf("%v", repairPilotBinaryErr)
	}
	return repairPilotBinaryPath
}

func repoRootForRepairClientTest() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}

func writeRepairClientFixtureInventory(t *testing.T, groups map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	content := "all:\n  hosts:\n"
	for _, host := range groups {
		content += "    " + host + ": {ansible_connection: local, ansible_host: 127.0.0.1}\n"
	}
	if len(groups) > 0 {
		content += "  children:\n"
		for group, host := range groups {
			content += "    " + group + ":\n      hosts:\n        " + host + ": {}\n"
		}
	}
	path := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRepairClient_CapabilitiesAndPlan_RealSubprocess(t *testing.T) {
	binary := buildRealPilotBinary(t)
	repoRoot, err := repoRootForRepairClientTest()
	if err != nil {
		t.Fatal(err)
	}
	inv := writeRepairClientFixtureInventory(t, map[string]string{"prometheus": "web1"})

	client := &RepairClient{PilotBinary: binary, Dir: repoRoot, Inventory: inv}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	caps, err := client.Capabilities(ctx)
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	found := false
	for _, c := range caps {
		if c.Component == "prometheus" && c.Host == "web1" && c.ActionID == "restart" {
			found = true
		}
		if c.Risk != "R1" {
			t.Errorf("capability %+v has non-R1 risk", c)
		}
	}
	if !found {
		t.Fatalf("capabilities = %+v, want a prometheus/web1/restart R1 capability", caps)
	}

	plan, err := client.Plan(ctx, "inc-1", "web1", "prometheus", "restart")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.ExecutorKind != "docker_restart" || plan.ExecutorTarget != "pilot-prometheus" {
		t.Errorf("plan executor = %s/%s", plan.ExecutorKind, plan.ExecutorTarget)
	}
	if plan.PlanHash == "" {
		t.Error("PlanHash is empty")
	}
}

func TestRepairClient_Plan_UnknownComponentSurfacesAsError(t *testing.T) {
	binary := buildRealPilotBinary(t)
	repoRoot, err := repoRootForRepairClientTest()
	if err != nil {
		t.Fatal(err)
	}
	inv := writeRepairClientFixtureInventory(t, map[string]string{"prometheus": "web1"})
	client := &RepairClient{PilotBinary: binary, Dir: repoRoot, Inventory: inv}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := client.Plan(ctx, "inc-1", "web1", "not-a-real-component", "restart"); err == nil {
		t.Fatal("expected an error for an unknown component")
	}
}
