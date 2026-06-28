package tools

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestPlanOperationsRequiresTitle(t *testing.T) {
	tc := &PlanOperationsTool{Store: openTestStore(t)}
	_, err := tc.Execute(context.Background(), json.RawMessage(`{"operations":[{"tool":"read_file","args":{},"rationale":"x"}]}`))
	if err == nil {
		t.Fatal("expected error for missing title")
	}
}

func TestPlanOperationsRequiresAtLeastOneOp(t *testing.T) {
	tc := &PlanOperationsTool{Store: openTestStore(t)}
	_, err := tc.Execute(context.Background(), json.RawMessage(`{"title":"x","operations":[]}`))
	if err == nil {
		t.Fatal("expected error for empty operations")
	}
}

func TestPlanOperationsRequiresStore(t *testing.T) {
	tc := &PlanOperationsTool{Store: nil}
	res, err := tc.Execute(context.Background(), json.RawMessage(`{"title":"x","operations":[{"tool":"r","args":{},"rationale":"y"}]}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected error result, got: %s", res.Content)
	}
}

func TestPlanOperationsWritesPlan(t *testing.T) {
	st := openTestStore(t)
	tc := &PlanOperationsTool{Store: st}
	args := json.RawMessage(`{
	  "title":"Disable root SSH",
	  "summary":"Apply CIS 5.2.1",
	  "operations":[
	    {"tool":"run_ansible","args":{"playbook":"ssh.yml"},"rationale":"Disable PermitRootLogin","risk_level":"medium","cis_control":"5.2.1"},
	    {"tool":"run_ansible","args":{"playbook":"restart.yml"},"rationale":"Restart sshd","risk_level":"high"}
	  ]
	}`)
	res, err := tc.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", res.Content)
	}
	if !strings.Contains(res.Content, "Plan submitted for approval") {
		t.Errorf("missing submitted message: %s", res.Content)
	}
	// Pull the plan back via ListPlans.
	plans, err := st.ListPlans("", "pending", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 {
		t.Fatalf("got %d plans, want 1", len(plans))
	}
	if plans[0].Title != "Disable root SSH" {
		t.Errorf("got title %q", plans[0].Title)
	}
	if len(plans[0].Operations) != 2 {
		t.Errorf("got %d ops, want 2", len(plans[0].Operations))
	}
	// Second op's risk should be 'high' (preserved).
	if plans[0].Operations[1].RiskLevel != "high" {
		t.Errorf("second op risk = %q, want high", plans[0].Operations[1].RiskLevel)
	}
}

func TestPlanOperationsNormalisesUnknownRisk(t *testing.T) {
	st := openTestStore(t)
	tc := &PlanOperationsTool{Store: st}
	args := json.RawMessage(`{"title":"x","operations":[{"tool":"r","args":{},"rationale":"y","risk_level":"unknown"}]}`)
	if _, err := tc.Execute(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	plans, _ := st.ListPlans("", "", 0)
	if len(plans) != 1 || plans[0].Operations[0].RiskLevel != "medium" {
		t.Errorf("unknown risk should normalise to medium, got: %+v", plans)
	}
}

func TestPlanOperationsRejectsOpWithoutTool(t *testing.T) {
	st := openTestStore(t)
	tc := &PlanOperationsTool{Store: st}
	args := json.RawMessage(`{"title":"x","operations":[{"args":{},"rationale":"y"}]}`)
	res, _ := tc.Execute(context.Background(), args)
	if !res.IsError {
		t.Errorf("expected error result, got: %s", res.Content)
	}
}
