package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/store"
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
