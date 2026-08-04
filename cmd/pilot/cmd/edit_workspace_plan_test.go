package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanEditScenario_ReturnsDiffAndLeavesRealWorkspaceUntouched(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-01"},
		{Action: "set_host_field", Host: "web-01", Field: "ansible_host", Value: "10.0.0.9"},
		{Action: "save_hosts"},
	}}

	beforeRevision, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	result, err := planEditScenario(dir, scenario, editAgentSessionOptions{})
	if err != nil {
		t.Fatalf("planEditScenario() error = %v", err)
	}

	if result.BaseRevision != beforeRevision {
		t.Fatalf("BaseRevision = %q, want the pre-plan revision %q", result.BaseRevision, beforeRevision)
	}
	found := false
	for _, f := range result.AffectedFiles {
		if f == "hosts.yml" {
			found = true
		}
	}
	if !found {
		t.Fatalf("AffectedFiles = %v, want it to include hosts.yml", result.AffectedFiles)
	}
	if !strings.Contains(result.Diff, "web-01") || !strings.Contains(result.Diff, "10.0.0.9") {
		t.Fatalf("expected diff to mention the new host and field, got:\n%s", result.Diff)
	}

	// The real workspace must never see this scenario's write.
	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); !os.IsNotExist(err) {
		t.Fatalf("expected dir/hosts.yml to still not exist after a plan run, stat error = %v", err)
	}
	afterRevision, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	if afterRevision != beforeRevision {
		t.Fatal("expected the real workspace's revision to be unchanged after a plan run")
	}
}

func TestPlanEditScenario_InvalidScenarioLeavesWorkspaceUntouched(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	beforeRevision, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	// enable_role on a host that doesn't exist — the scenario is
	// well-formed JSON but fails once the driver actually runs it.
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "enable_role", Host: "no-such-host", Role: "docker"},
	}}
	if _, err := planEditScenario(dir, scenario, editAgentSessionOptions{}); err == nil {
		t.Fatal("expected an error for a scenario targeting a nonexistent host")
	}

	afterRevision, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	if afterRevision != beforeRevision {
		t.Fatal("expected the real workspace to be untouched after a failed plan run")
	}
}

func TestPlanEditScenario_EmptyScenarioIsRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := planEditScenario(dir, editScenario{Version: 1}, editAgentSessionOptions{}); err == nil {
		t.Fatal("expected an empty scenario to be rejected by validateEditScenario before any temp copy is made")
	}
}
