package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/store"
)

// writeRaceResultFixture writes an ansible-playbook stand-in that appends
// resultLines (each a JSON-lines record a real ansible_callback/pilot_result.py
// would have written) to $PILOT_ANSIBLE_RESULT_FILE, when set, then exits
// with exitCode. Simulating pilot_result.py's output this way tests the Go
// classifier/wiring in isolation from the Python callback, which is
// covered separately by ansible_callback/test_pilot_result.py.
func writeRaceResultFixture(t *testing.T, exitCode int, resultLines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ansible-playbook")
	script := "#!/bin/sh\n" +
		"if [ -n \"$PILOT_ANSIBLE_RESULT_FILE\" ]; then\n"
	for _, line := range resultLines {
		script += "  printf '%s\\n' '" + line + "' >> \"$PILOT_ANSIBLE_RESULT_FILE\"\n"
	}
	script += "fi\n" +
		"exit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write race result fixture: %v", err)
	}
	return path
}

// setUpRaceDeploymentFixtures fakes ansible-inventory (one "docker" host
// with the given deployment_availability policy) and ansible --list-hosts,
// following the same convention as
// TestExecuteRecordedDeploymentPersistsTransactionAfterAuthorization, and
// returns the resolved inventory path plus the run-history data dir.
func setUpRaceDeploymentFixtures(t *testing.T, policy string) (inv, dataDir string) {
	t.Helper()
	root := repoRootForTest(t)
	t.Chdir(root)
	dataDir = t.TempDir()
	t.Setenv("PILOT_DATA_DIR", dataDir)
	binDir := t.TempDir()
	hostvars := `{}`
	if policy != "" {
		hostvars = `{"deployment_availability": "` + policy + `"}`
	}
	invScript := "#!/bin/sh\nprintf '%s\\n' '{\"_meta\": {\"hostvars\": {\"host-a\": " + hostvars + "}}, \"docker\": {\"hosts\": [\"host-a\"]}}'\n"
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte(invScript), 0o755); err != nil {
		t.Fatal(err)
	}
	// Mirrors TestExecuteRecordedDeploymentPersistsTransactionAfterAuthorization's
	// ansibleFixture verbatim — autoDeployVerify runs docker's real verify
	// checklist against "host-a", which needs every one of these canned
	// responses to pass, not just --list-hosts.
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
	inv = filepath.Join(t.TempDir(), "inventory.yml")
	if err := os.WriteFile(inv, []byte("all:\n  hosts:\n    host-a: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return inv, dataDir
}

// ctxWithAnsibleRuntime wraps context.Background() with a real
// prepareDeployAnsibleRuntime-created runtime, exactly as
// runDeployInteractive/runReconcileInteractive do before ever calling
// executeRecordedDeployment. deploy_outcome.go's prepareDeploymentResultFile
// needs deployAnsibleRuntimeFromContext(ctx).TempDir to be non-empty to
// create the mid-run race result file at all — without this, the race
// classifier stays disabled and the apply step falls back to raw-exit-code
// behavior, which is a legitimate degrade path in production (the ctx just
// never happens to lack a runtime there) but would make these tests
// exercise the wrong code path.
func ctxWithAnsibleRuntime(t *testing.T) context.Context {
	t.Helper()
	runtime, err := prepareDeployAnsibleRuntime(t.TempDir())
	if err != nil {
		t.Fatalf("prepareDeployAnsibleRuntime: %v", err)
	}
	return withDeployAnsibleRuntime(context.Background(), runtime)
}

// TestExecuteRecordedDeployment_RuntimeUnreachableOptionalHostIsDeferred
// covers spec §28.8's race integration scenario: host-a is optional and
// reachable at Phase 5's pre-run probe, but the actual ansible-playbook
// apply run reports it transport-unreachable (zero task failures, valid
// final stats) — the mid-run shutdown race. Pilot must exit success with
// host-a reported deferred, not fail the deployment.
func TestExecuteRecordedDeployment_RuntimeUnreachableOptionalHostIsDeferred(t *testing.T) {
	inv, dataDir := setUpRaceDeploymentFixtures(t, "optional")
	stubDeploymentAvailabilityAllReachable(t) // reachable at the pre-run probe

	runner := ansible.NewRunner()
	runner.Binary = writeRaceResultFixture(t, 2,
		`{"event":"unreachable","host":"host-a","reason":"connection_refused"}`,
		`{"event":"stats","hosts":{"host-a":{"ok":0,"changed":0,"failures":0,"unreachable":1,"skipped":0,"rescued":0,"ignored":0}}}`,
	)
	runner.Timeout = 5 * time.Second
	restore := stubDeploymentConfirm(t, false, true)
	defer restore()

	err := executeRecordedDeployment(ctxWithAnsibleRuntime(t), runner, &bytes.Buffer{}, "playbooks/apply/docker-apply.yml", inv, "", "", []string{"stage=sandbox"}, vaultInput{}, "sandbox", []string{"docker"})
	if err != nil {
		t.Fatalf("executeRecordedDeployment() error = %v, want nil (tolerated mid-run transport disappearance on an optional host)", err)
	}

	s, openErr := store.Open(filepath.Join(dataDir, "history.db"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer s.Close()
	runs, listErr := s.ListRuns(store.RunFilter{Component: "docker"})
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(runs) != 1 || runs[0].Outcome != "success" {
		t.Fatalf("runs = %+v, want exactly one successful run despite the raw non-zero ansible-playbook exit", runs)
	}
}

// TestExecuteRecordedDeployment_RuntimeTaskFailureRemainsFatal is the
// paired negative case from spec §28.8: same setup, but the apply run
// reports a real task failure alongside the unreachable event. This must
// never be excused — the deployment stays a failure.
func TestExecuteRecordedDeployment_RuntimeTaskFailureRemainsFatal(t *testing.T) {
	inv, dataDir := setUpRaceDeploymentFixtures(t, "optional")
	stubDeploymentAvailabilityAllReachable(t)

	runner := ansible.NewRunner()
	runner.Binary = writeRaceResultFixture(t, 2,
		`{"event":"failed","host":"host-a","task":"Install package"}`,
		`{"event":"stats","hosts":{"host-a":{"ok":0,"changed":0,"failures":1,"unreachable":0,"skipped":0,"rescued":0,"ignored":0}}}`,
	)
	runner.Timeout = 5 * time.Second
	restore := stubDeploymentConfirm(t, false, true)
	defer restore()

	err := executeRecordedDeployment(ctxWithAnsibleRuntime(t), runner, &bytes.Buffer{}, "playbooks/apply/docker-apply.yml", inv, "", "", []string{"stage=sandbox"}, vaultInput{}, "sandbox", []string{"docker"})
	if err == nil {
		t.Fatal("executeRecordedDeployment() error = nil, want a failure for a real task failure, even alongside an unreachable event")
	}

	s, openErr := store.Open(filepath.Join(dataDir, "history.db"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer s.Close()
	runs, listErr := s.ListRuns(store.RunFilter{Component: "docker"})
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(runs) != 1 || runs[0].Outcome == "success" {
		t.Fatalf("runs = %+v, want exactly one non-success run", runs)
	}
}
