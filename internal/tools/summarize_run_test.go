package tools

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/anomalyco/pilot/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "history.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestBuildRunSummary_AggregatesCounts(t *testing.T) {
	run := &store.Run{
		ID:        "run-1",
		StartedAt: time.Now().Add(-time.Minute),
		Mode:      "audit",
		Playbook:  "user goal: harden sshd",
		Status:    "completed",
	}
	mk := func(status, cis string) *store.Proposal {
		return &store.Proposal{
			ID:         "p-" + status + "-" + cis,
			RunID:      "run-1",
			Status:     status,
			CISControl: cis,
			Args:       json.RawMessage(`{"path":"/etc/ssh/sshd_config"}`),
		}
	}
	proposals := []*store.Proposal{
		mk("approved", "5.2.1"),
		mk("approved", "5.2.10"),
		mk("applied", "5.2.1"),
		mk("rejected", "5.3.1"),
		mk("failed", "5.4.1"),
	}
	summary := buildRunSummary(run, proposals, "sshd_config hardened; sshd restarted")
	if summary.ProposalsTotal != 5 {
		t.Errorf("ProposalsTotal = %d", summary.ProposalsTotal)
	}
	if summary.ProposalsApproved != 3 {
		t.Errorf("ProposalsApproved = %d (approved + applied)", summary.ProposalsApproved)
	}
	if summary.ProposalsRejected != 1 {
		t.Errorf("ProposalsRejected = %d", summary.ProposalsRejected)
	}
	if summary.ProposalsFailed != 1 {
		t.Errorf("ProposalsFailed = %d", summary.ProposalsFailed)
	}
	if summary.ProposalsApplied != 1 {
		t.Errorf("ProposalsApplied = %d", summary.ProposalsApplied)
	}
	// CIS set: 5.2.1, 5.2.10, 5.3.1, 5.4.1 (unique)
	if len(summary.CISAddressed) != 4 {
		t.Errorf("CISAddressed = %v, want 4 unique", summary.CISAddressed)
	}
	// File path extracted from args
	if len(summary.FilesChanged) != 1 || summary.FilesChanged[0] != "/etc/ssh/sshd_config" {
		t.Errorf("FilesChanged = %v", summary.FilesChanged)
	}
}

func TestBuildRunSummary_NoProposals_NoCrash(t *testing.T) {
	run := &store.Run{ID: "run-empty", Status: "completed"}
	s := buildRunSummary(run, nil, "")
	if s.ProposalsTotal != 0 {
		t.Errorf("expected zero counts")
	}
	if len(s.NextSteps) == 0 {
		t.Errorf("expected at least one default next_step")
	}
}

func TestBuildRunSummary_FilesFromNestedArgs(t *testing.T) {
	run := &store.Run{ID: "r", Status: "ok"}
	// Nested args with a path under /etc
	args := json.RawMessage(`{"destinations":[{"path":"/etc/audit/auditd.conf"}]}`)
	proposals := []*store.Proposal{{
		ID: "p", RunID: "r", Status: "approved", Args: args,
	}}
	s := buildRunSummary(run, proposals, "")
	found := false
	for _, f := range s.FilesChanged {
		if f == "/etc/audit/auditd.conf" {
			found = true
		}
	}
	if !found {
		t.Errorf("nested path not extracted: %v", s.FilesChanged)
	}
}

func TestSummarizeRunTool_NoStore_Errors(t *testing.T) {
	t1 := &SummarizeRunTool{} // no store
	res, err := t1.Execute(context.TODO(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected error when store missing")
	}
}

func TestSummarizeRunTool_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	run := &store.Run{
		ID:        "run-rt",
		StartedAt: time.Now(),
		Mode:      "audit",
		Playbook:  "harden sshd",
		Status:    "completed",
	}
	if err := s.CreateRun(run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if err := s.SaveProposal(&store.Proposal{
		ID: "p1", RunID: "run-rt", Status: "approved",
		CISControl: "5.2.1",
		Args:       json.RawMessage(`{"path":"/etc/ssh/sshd_config"}`),
	}); err != nil {
		t.Fatalf("SaveProposal: %v", err)
	}
	t1 := &SummarizeRunTool{Store: s}
	res, err := t1.Execute(context.TODO(), json.RawMessage(`{"run_id":"run-rt","outcome":"done"}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success: %s", res.Content)
	}
	var payload RunSummary
	if err := json.Unmarshal([]byte(res.Content), &payload); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, res.Content)
	}
	if payload.RunID != "run-rt" {
		t.Errorf("RunID = %q", payload.RunID)
	}
	if payload.Outcome != "done" {
		t.Errorf("Outcome = %q", payload.Outcome)
	}
	if payload.ProposalsApproved != 1 {
		t.Errorf("ProposalsApproved = %d", payload.ProposalsApproved)
	}
}

func TestLooksLikePath(t *testing.T) {
	cases := map[string]bool{
		"/etc/passwd":      true,
		"/etc/ssh/cfg":     true,
		"/var/log/syslog":  true,
		"/opt/app/x":       true,
		"/tmp/pilot/x.yml": true,
		"/usr/bin/foo":     false,
		"relative/path":    false,
		"":                 false,
	}
	for in, want := range cases {
		if got := looksLikePath(in); got != want {
			t.Errorf("looksLikePath(%q) = %v, want %v", in, got, want)
		}
	}
}
