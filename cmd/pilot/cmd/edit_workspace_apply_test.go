package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestApplyEditScenario_MutatesRealWorkspace(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-01"},
		{Action: "set_host_field", Host: "web-01", Field: "ansible_host", Value: "10.0.0.9"},
		{Action: "save_hosts"},
	}}

	result, err := applyEditScenario(dir, "session-a", scenario, editAgentSessionOptions{})
	if err != nil {
		t.Fatalf("applyEditScenario() error = %v", err)
	}
	if result.RolledBack {
		t.Fatal("expected a clean apply, not a rollback")
	}
	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("expected hosts.yml to exist for real: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v", err)
	}
	if len(hf.Hosts) != 1 || hf.Hosts[0].Name != "web-01" || hf.Hosts[0].AnsibleHost != "10.0.0.9" {
		t.Fatalf("hosts = %+v", hf.Hosts)
	}
	if result.RevisionBefore == result.RevisionAfter {
		t.Fatal("expected the revision to change after a real mutation")
	}
}

func TestApplyEditScenario_FailurePartwayRollsBackAndLeavesWorkspaceUntouched(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	revisionBefore, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-01"},
		// Second step targets a host that will never exist under this
		// name, forcing a mid-scenario failure after the first step's
		// in-memory router mutation but before any save_hosts call.
		{Action: "enable_role", Host: "no-such-host", Role: "docker"},
	}}

	result, err := applyEditScenario(dir, "session-b", scenario, editAgentSessionOptions{})
	if err != nil {
		t.Fatalf("applyEditScenario() error = %v", err)
	}
	if !result.RolledBack {
		t.Fatal("expected a rolled-back result for a mid-scenario failure")
	}
	if result.ScenarioErr == nil {
		t.Fatal("expected ScenarioErr to be set")
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	if string(data) != "hosts: {}\n" {
		t.Fatalf("hosts.yml = %q, want the untouched pre-apply content", data)
	}
	revisionAfter, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	if revisionAfter != revisionBefore {
		t.Fatal("expected the workspace revision to be restored after rollback")
	}
}

// TestApplyEditScenario_RollsBackAfterAnEarlierStepAlreadySaved is the
// scenario spec's Mutation Lock and Rollback section describes
// specifically: "如果 scenario 已成功儲存 hosts.yml，但後續 group_vars
// action 失敗" — a real prior write to disk (not just an in-memory
// router mutation) must be undone, not merely a step that never wrote
// anything in the first place.
func TestApplyEditScenario_RollsBackAfterAnEarlierStepAlreadySaved(t *testing.T) {
	dir := t.TempDir()
	revisionBefore, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-01"},
		{Action: "save_hosts"}, // a real write to hosts.yml happens here
		{Action: "set_group_var", File: "no-such-stem.yml", Key: "x", Value: "y"}, // fails: no such file/stem
	}}

	result, err := applyEditScenario(dir, "session-d", scenario, editAgentSessionOptions{})
	if err != nil {
		t.Fatalf("applyEditScenario() error = %v", err)
	}
	if !result.RolledBack {
		t.Fatal("expected a rolled-back result")
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); !os.IsNotExist(err) {
		t.Fatalf("expected hosts.yml (created by the rolled-back apply) to no longer exist, stat error = %v", err)
	}
	revisionAfter, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	if revisionAfter != revisionBefore {
		t.Fatal("expected the workspace revision to be restored to its pre-apply (empty) state")
	}
}

func TestApplyEditScenario_FailsClosedWhenWorkspaceIsLocked(t *testing.T) {
	dir := t.TempDir()
	lock, err := acquireWorkspaceLock(dir, "holder")
	if err != nil {
		t.Fatalf("acquireWorkspaceLock() error = %v", err)
	}
	defer lock.release()

	scenario := editScenario{Version: 1, Steps: []editAction{{Action: "create_host", Host: "web-01"}}}
	_, err = applyEditScenario(dir, "session-c", scenario, editAgentSessionOptions{})
	if !errors.Is(err, errWorkspaceLocked) {
		t.Fatalf("applyEditScenario() error = %v, want errWorkspaceLocked", err)
	}
}
