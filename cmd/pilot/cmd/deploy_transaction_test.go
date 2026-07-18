package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/contract"
	"github.com/anomalyco/pilot/internal/delivery"
	"github.com/anomalyco/pilot/internal/spec"
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
	ansibleFixture := `#!/bin/sh
case "$*" in
  *--list-hosts*) printf '%s\n' '  hosts (1):' '    host-a'; exit 0 ;;
  *dpkg-query*) out=1 ;;
  *'systemctl is-active'*) out=active ;;
  *'docker --version'*) out='Docker version 1.0' ;;
  *'stat -c'*) out='660 root docker /var/run/docker.sock' ;;
  *'docker run --rm'*) out='Hello from Docker' ;;
  *'docker ps -aq'*) out='' ;;
  *'docker network ls'*) out=bridge ;;
  *'docker compose version'*) out='Docker Compose version v2' ;;
  *'docker info'*) out=' Cgroup Driver: cgroupfs' ;;
  *) out=unknown ;;
esac
printf '{"plays":[{"tasks":[{"hosts":{"host-a":{"stdout":"%s","rc":0}}}]}]}\n' "$out"
`
	if err := os.WriteFile(filepath.Join(binDir, "ansible"), []byte(ansibleFixture), 0o755); err != nil {
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
	encoded, err := json.Marshal(runs[0].Metadata)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("value")) {
		t.Fatalf("metadata leaked extra-var value: %s", encoded)
	}
	if runs[0].Metadata["source_revision"] == "" || runs[0].Metadata["artifact_sha256"] == nil {
		t.Fatalf("supply-chain metadata missing: %s", encoded)
	}
}

func TestScopeVerificationPlansUsesContractTraceability(t *testing.T) {
	root := repoRootForTest(t)
	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	plans := []delivery.VerificationPlan{{
		Component: "docker",
		SpecPath:  "docs/verification/docker.md",
		Rows:      []spec.Row{{ID: "C1"}, {ID: "C2"}, {ID: "C3"}},
	}}
	scoped, err := scopeVerificationPlans(catalog, plans, "docker-C1")
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 1 || len(scoped[0].Rows) != 2 || scoped[0].Rows[0].ID != "C1" || scoped[0].Rows[1].ID != "C3" {
		t.Fatalf("scoped=%+v", scoped)
	}
	if _, err := scopeVerificationPlans(catalog, plans, "unknown-tag"); err == nil {
		t.Fatal("unknown tag unexpectedly broadened verification scope")
	}
}
