package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// startFinishedRun records one finished run of host with the metadata scope and the outcome
// given, started at the offset so that the order of runs is the order of the calls.
func startFinishedRun(t *testing.T, s *Store, id, scope, outcome string, offset time.Duration) {
	t.Helper()
	meta := map[string]any{"engine": "test"}
	if scope != "" {
		meta["scope"] = scope
	}
	w, err := StartRun(context.Background(), s, RunStarted{
		RunID: id, Hosts: []string{"host-a"}, Component: "freeipa-identity", Components: []string{"freeipa-identity"},
		Metadata: meta, StartedAt: time.Date(2026, 11, 7, 1, 0, 0, 0, time.UTC).Add(offset),
	})
	if err != nil {
		t.Fatal(err)
	}
	exit := 0
	if outcome != "success" && outcome != "partial_success" {
		exit = 1
	}
	if err := w.Finish(context.Background(), RunFinished{Outcome: outcome, ExitCode: exit}); err != nil {
		t.Fatal(err)
	}
}

// Q6 (default taken before the maintainer confirmed it): the last successful delivery of a host is
// not a run of the Go identity engine's users-groups scope, which ran no playbook; a flag counts it.
// I4: a run that ended partial_failed is never a success, with or without the flag.
func TestLastSuccessSkipsUsersGroupsRunsUnlessAsked(t *testing.T) {
	open := func(t *testing.T) *Store {
		t.Helper()
		s, err := Open(filepath.Join(t.TempDir(), "history.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	last := func(t *testing.T, s *Store, include bool) (string, error) {
		t.Helper()
		run, err := s.LastSuccessWith("host-a", LastSuccessOptions{IncludeUsersGroups: include})
		return run.RunID, err
	}

	t.Run("a newer users-groups success does not stand for the last delivery", func(t *testing.T) {
		s := open(t)
		startFinishedRun(t, s, "full-old", "", "success", 0)
		startFinishedRun(t, s, "ug-new", ScopeUsersGroups, "success", time.Minute)
		if got, err := last(t, s, false); err != nil || got != "full-old" {
			t.Fatalf("default: %q, %v, want the older full run", got, err)
		}
		if run, err := s.LastSuccess("host-a"); err != nil || run.RunID != "full-old" {
			t.Fatalf("LastSuccess: %q, %v, want the older full run (the default form skips them too)", run.RunID, err)
		}
		if got, err := last(t, s, true); err != nil || got != "ug-new" {
			t.Fatalf("included: %q, %v, want the newer users-groups run", got, err)
		}
	})

	t.Run("a run of another scope counts either way", func(t *testing.T) {
		s := open(t)
		startFinishedRun(t, s, "full-old", "", "success", 0)
		startFinishedRun(t, s, "mixed-new", "full", "success", time.Minute)
		for _, include := range []bool{false, true} {
			if got, err := last(t, s, include); err != nil || got != "mixed-new" {
				t.Fatalf("include=%v: %q, %v, want the mixed run", include, got, err)
			}
		}
	})

	t.Run("partial_failed is never a success (I4)", func(t *testing.T) {
		s := open(t)
		startFinishedRun(t, s, "full-old", "", "success", 0)
		startFinishedRun(t, s, "ug-ok", ScopeUsersGroups, "success", time.Minute)
		startFinishedRun(t, s, "ug-owed", ScopeUsersGroups, "partial_failed", 2*time.Minute)
		startFinishedRun(t, s, "mixed-owed", "full", "partial_failed", 3*time.Minute)
		startFinishedRun(t, s, "mixed-failed", "full", "failed", 4*time.Minute)
		if got, err := last(t, s, false); err != nil || got != "full-old" {
			t.Fatalf("default: %q, %v, want the full run: no partial_failed or failed run is one", got, err)
		}
		if got, err := last(t, s, true); err != nil || got != "ug-ok" {
			t.Fatalf("included: %q, %v, want the newest users-groups SUCCESS, not the partial_failed after it", got, err)
		}
	})

	t.Run("only users-groups successes: the default says why there is none", func(t *testing.T) {
		s := open(t)
		startFinishedRun(t, s, "ug-ok", ScopeUsersGroups, "success", 0)
		startFinishedRun(t, s, "ug-owed", ScopeUsersGroups, "partial_failed", time.Minute)
		_, err := last(t, s, false)
		if err == nil || !strings.Contains(err.Error(), "no successful delivery") || !strings.Contains(err.Error(), "1 successful users-groups-scope run") {
			t.Fatalf("error = %v, want one that says a users-groups success was not counted", err)
		}
		if got, err := last(t, s, true); err != nil || got != "ug-ok" {
			t.Fatalf("included: %q, %v", got, err)
		}
	})

	t.Run("no runs at all", func(t *testing.T) {
		s := open(t)
		for _, include := range []bool{false, true} {
			if _, err := last(t, s, include); err == nil || strings.Contains(err.Error(), "not counted") {
				t.Fatalf("include=%v: error = %v, want the plain no-delivery error", include, err)
			}
		}
	})
}
