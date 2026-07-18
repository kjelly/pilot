package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/store"
)

func TestExecuteRecordedDeploymentPersistsTransactionAfterAuthorization(t *testing.T) {
	root := repoRootForTest(t)
	t.Chdir(root)
	dataDir := t.TempDir()
	t.Setenv("PILOT_DATA_DIR", dataDir)
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte("#!/bin/sh\nprintf '%s\\n' '{\"_meta\": {\"hostvars\": {\"host-a\": {}}}, \"docker\": {\"hosts\": [\"host-a\"]}}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "ansible"), []byte("#!/bin/sh\nprintf '%s\\n' '  hosts (1):' '    host-a'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	inv := filepath.Join(t.TempDir(), "inventory.yml")
	if err := os.WriteFile(inv, []byte("all:\n  hosts:\n    host-a: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := ansible.NewRunner()
	runner.Binary = writeExitFixture(t, 0)
	runner.Timeout = 5 * time.Second
	restore := stubDeploymentConfirm(t, false, true)
	defer restore()
	if err := executeRecordedDeployment(context.Background(), runner, &bytes.Buffer{}, "playbooks/apply/docker-apply.yml", inv, "", "", []string{"stage=sandbox", "example=value"}, vaultInput{}, "sandbox", []string{"docker"}); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(dataDir, "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	runs, err := s.ListRuns(store.RunFilter{Component: "docker"})
	if err != nil || len(runs) != 1 || runs[0].Outcome != "success" {
		t.Fatalf("runs=%+v err=%v", runs, err)
	}
	if runs[0].Stage != "sandbox" || len(runs[0].Hosts) != 1 || runs[0].Hosts[0] != "host-a" {
		t.Fatalf("run=%+v", runs[0])
	}
}
