package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestListAndGetRunsAreReadOnlyViews(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	w, err := StartRun(context.Background(), s, RunStarted{
		RunID: "run-query", Hosts: []string{"host-a"}, Stage: "staging",
		Component: "docker", Components: []string{"docker", "dashboard"},
		Metadata: map[string]any{"git_revision": "abc123", "authorization": "confirmed"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AppendEvidence(context.Background(), []VerifyEvidence{{SpecPath: "spec.md", RowID: "C1", Host: "host-a", Attempt: 1, OperationID: "e1", Command: "true", Expected: "present", ProbeStatus: "ok", Verdict: "pass"}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Finish(context.Background(), RunFinished{Outcome: "success", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	runs, err := s.ListRuns(RunFilter{Limit: 10, Host: "host-a", Component: "dashboard"})
	if err != nil || len(runs) != 1 || runs[0].RunID != "run-query" {
		t.Fatalf("runs=%+v err=%v", runs, err)
	}
	if runs[0].Stage != "staging" || len(runs[0].Components) != 2 || runs[0].Metadata["git_revision"] != "abc123" {
		t.Fatalf("run metadata=%+v", runs[0])
	}
	run, evidence, err := s.GetRun("run-query")
	if err != nil || run.Outcome != "success" || len(evidence) != 1 || evidence[0].Host != "host-a" {
		t.Fatalf("run=%+v evidence=%+v err=%v", run, evidence, err)
	}
	last, err := s.LastSuccess("host-a")
	if err != nil || last.RunID != "run-query" {
		t.Fatalf("last=%+v err=%v", last, err)
	}
	pending, err := s.PendingSpec("spec.md")
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
	diffs, err := s.DiffRuns("run-query", "run-query")
	if err != nil || len(diffs) != 0 {
		t.Fatalf("diffs=%+v err=%v", diffs, err)
	}
}

func TestPendingSpecAndDiffExposeOnlyChangedImmutableEvidence(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	for _, sample := range []struct{ id, verdict string }{{"before", "pass"}, {"after", "fail"}} {
		writer, err := StartRun(ctx, s, RunStarted{RunID: sample.id, Hosts: []string{"host-a"}, Component: "docker"})
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.AppendEvidence(ctx, []VerifyEvidence{{SpecPath: "spec.md", RowID: "C1", Host: "host-a", Attempt: 1, OperationID: "evidence-" + sample.id, Command: "true", Expected: "present", ProbeStatus: "ok", Verdict: sample.verdict}}); err != nil {
			t.Fatal(err)
		}
		if err := writer.Finish(ctx, RunFinished{Outcome: "success", ExitCode: 0}); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := s.PendingSpec("spec.md")
	if err != nil || len(pending) != 1 || pending[0].Verdict != "fail" || pending[0].RunID != "after" {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
	diffs, err := s.DiffRuns("before", "after")
	if err != nil || len(diffs) != 1 || diffs[0].Before != "pass" || diffs[0].After != "fail" {
		t.Fatalf("diffs=%+v err=%v", diffs, err)
	}
}
