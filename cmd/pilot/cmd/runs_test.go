package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/store"
)

func TestRunsCommandsQueryEvidenceWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PILOT_DATA_DIR", dir)
	s, err := store.Open(filepath.Join(dir, "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	writer, err := store.StartRun(context.Background(), s, store.RunStarted{RunID: "run-cli", Hosts: []string{"host-a"}, Component: "docker", Components: []string{"docker"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AppendEvidence(context.Background(), []store.VerifyEvidence{{SpecPath: "spec.md", RowID: "C1", Host: "host-a", Attempt: 1, OperationID: "row", Command: "true", Expected: "present", ProbeStatus: "ok", Verdict: "pass"}}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Finish(context.Background(), store.RunFinished{Outcome: "success", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	oldLimit, oldHost, oldComponent := runsLimit, runsHost, runsComponent
	t.Cleanup(func() { runsLimit, runsHost, runsComponent = oldLimit, oldHost, oldComponent })
	runsLimit, runsHost, runsComponent = 10, "host-a", "docker"
	var output bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&output)
	if err := runRunsList(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "run-cli\tsuccess") {
		t.Fatalf("list output=%q", got)
	}
	output.Reset()
	if err := runRunsShow(cmd, []string{"run-cli"}); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "components: docker") || !strings.Contains(got, "spec.md\tC1\thost-a") {
		t.Fatalf("show output=%q", got)
	}
}

// pilot runs last-success (Q6): the run of a users-groups scope is not a host's last delivery unless
// --include-users-groups says so, and a partial_failed run is never one. The flag is parsed by the real
// command tree, from a history.db with the three runs.
func TestRunsLastSuccessSkipsTheUsersGroupsScopeUnlessAsked(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PILOT_DATA_DIR", dir)
	s, err := store.Open(filepath.Join(dir, "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	record := func(id, scope, outcome string, minute int) {
		t.Helper()
		w, err := store.StartRun(context.Background(), s, store.RunStarted{
			RunID: id, Hosts: []string{"host-a"}, Component: "freeipa-identity", Components: []string{"freeipa-identity"},
			Metadata:  map[string]any{"engine": "golang", "scope": scope},
			StartedAt: time.Date(2026, 11, 7, 1, minute, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Finish(context.Background(), store.RunFinished{Outcome: outcome}); err != nil {
			t.Fatal(err)
		}
	}
	record("run-full", "full", "success", 0)
	record("run-ug-ok", store.ScopeUsersGroups, "success", 1)
	record("run-ug-owed", store.ScopeUsersGroups, "partial_failed", 2)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	last := func(extra ...string) string {
		t.Helper()
		// pflag keeps a flag's value and Changed state across Execute calls of the same command.
		defer func() {
			rootCmd.SetArgs(nil)
			rootCmd.SetOut(nil)
			rootCmd.SetErr(nil)
			_ = runsLastSuccessCmd.Flags().Set("include-users-groups", "false")
			runsLastSuccessCmd.Flags().Lookup("include-users-groups").Changed = false
			runsLastSuccessCmd.Flags().Lookup("host").Changed = false
			runsHost = ""
		}()
		var out bytes.Buffer
		rootCmd.SetArgs(append([]string{"runs", "last-success", "--host", "host-a"}, extra...))
		rootCmd.SetOut(&out)
		rootCmd.SetErr(&out)
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("runs last-success %v: %v\n%s", extra, err, out.String())
		}
		return out.String()
	}
	if got := last(); !strings.Contains(got, "run-full") || strings.Contains(got, "run-ug") {
		t.Fatalf("default: %q, want the full run: a users-groups run ran no playbook", got)
	}
	if got := last("--include-users-groups"); !strings.Contains(got, "run-ug-ok") || strings.Contains(got, "run-ug-owed") {
		t.Fatalf("--include-users-groups: %q, want the newest users-groups SUCCESS, not the partial_failed run after it", got)
	}
	if got := last(); !strings.Contains(got, "run-full") {
		t.Fatalf("a second default call: %q: the flag of the call before must not stay set", got)
	}
}
