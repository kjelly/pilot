package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/networkcheck"
)

// requireRealAnsible skips the test when the real ansible/ansible-inventory
// binaries this command shells out to are not on PATH — the same guard
// cmd/pilot/cmd/preflight_check_test.go already uses for its real-ansible
// tests.
func requireRealAnsible(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible"); err != nil {
		t.Skipf("ansible not installed: %v", err)
	}
	if _, err := exec.LookPath("ansible-inventory"); err != nil {
		t.Skipf("ansible-inventory not installed: %v", err)
	}
}

// listenOnLoopback opens a real TCP listener on an OS-assigned loopback
// port and returns it plus the concrete port number, so tests can probe
// something that is genuinely reachable without any ansible/docker/VM
// target — just the real socket code path networkcheck.Probe drives.
func listenOnLoopback(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// closedLoopbackPort returns a port that was briefly bound and then
// released, so it is very likely still free (and therefore connection
// refused, i.e. reliably "closed") for the life of the test.
func closedLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// writeNetworkCheckFixture builds a minimal two-component contract catalog
// (provider with an "open" and a "closed" tcp endpoint; consumer with a
// required providerEndpoint dependency on both, bound to a non-secret
// input) plus a two-host, ansible_connection=local inventory, and points
// PILOT_ROOT at it. Both hosts are "local" so the real ansible ad-hoc `-m
// script` round-trip runs against this machine's own loopback interface —
// a faithful exercise of the real code path without needing docker/VM
// infrastructure.
func writeNetworkCheckFixture(t *testing.T, openPort, closedPort int) string {
	t.Helper()
	root := t.TempDir()
	contractsDir := filepath.Join(root, "contracts")
	if err := os.MkdirAll(contractsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	provider := `schemaVersion: 1
id: provider
role: provider
specs: [{path: "fake.md", rows: {all: true}}]
playbooks: {apply: "fake-apply.yml"}
dependencies: []
endpoints:
  - {name: open, scheme: tcp, port: ` + strconv.Itoa(openPort) + `}
  - {name: closed, scheme: tcp, port: ` + strconv.Itoa(closedPort) + `}
hostCardinality: exactly-one
resources: {minCPU: 1, minRAMMiB: 1, minDiskGiB: 1}
stagePolicy: {variable: stage, default: sandbox}
evidenceRequirement: {targetTest: vm, idempotency: required}
verification: {autoDeploy: false}
site: {include: false, order: 1, vars: {}, tags: [], optIn: true}
`
	consumer := `schemaVersion: 1
id: consumer
role: consumer
specs: [{path: "fake.md", rows: {all: true}}]
playbooks: {apply: "fake-apply.yml"}
dependencies:
  - {component: provider, required: true, relation: providerEndpoint}
bindings:
  - input: target_host
    requiredWhenDependencySelected: true
    sourceSelection: exactlyOne
    from: {component: provider, endpoint: open}
groupVars:
  - {name: target_host, type: string, required: false, secret: false}
hostCardinality: exactly-one
resources: {minCPU: 1, minRAMMiB: 1, minDiskGiB: 1}
stagePolicy: {variable: stage, default: sandbox}
evidenceRequirement: {targetTest: vm, idempotency: required}
verification: {autoDeploy: false}
site: {include: false, order: 1, vars: {}, tags: [], optIn: true}
`
	// ghostprovider/secretconsumer: a provider with zero inventory hosts,
	// consumed through a *secret* bound input holding a canary value — the
	// external-override path (see networkcheck.resolveExternalOverride)
	// must SKIP this edge rather than ever resolving that secret as a probe
	// target. Exercises the JSON renderer's secret-safety, not just the
	// planner's (already covered by internal/networkcheck's own tests).
	ghostProvider := `schemaVersion: 1
id: ghostprovider
role: ghostprovider
specs: [{path: "fake.md", rows: {all: true}}]
playbooks: {apply: "fake-apply.yml"}
dependencies: []
endpoints:
  - {name: svc, scheme: tcp, port: 9999}
hostCardinality: exactly-one
resources: {minCPU: 1, minRAMMiB: 1, minDiskGiB: 1}
stagePolicy: {variable: stage, default: sandbox}
evidenceRequirement: {targetTest: vm, idempotency: required}
verification: {autoDeploy: false}
site: {include: false, order: 1, vars: {}, tags: [], optIn: true}
`
	secretConsumer := `schemaVersion: 1
id: secretconsumer
role: consumer
specs: [{path: "fake.md", rows: {all: true}}]
playbooks: {apply: "fake-apply.yml"}
dependencies:
  - {component: ghostprovider, required: true, relation: providerEndpoint}
bindings:
  - input: secret_target
    requiredWhenDependencySelected: true
    sourceSelection: exactlyOne
    from: {component: ghostprovider, endpoint: svc}
groupVars:
  - {name: secret_target, type: string, required: false, secret: true}
hostCardinality: exactly-one
resources: {minCPU: 1, minRAMMiB: 1, minDiskGiB: 1}
stagePolicy: {variable: stage, default: sandbox}
evidenceRequirement: {targetTest: vm, idempotency: required}
verification: {autoDeploy: false}
site: {include: false, order: 1, vars: {}, tags: [], optIn: true}
`
	if err := os.WriteFile(filepath.Join(contractsDir, "provider.yaml"), []byte(provider), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contractsDir, "consumer.yaml"), []byte(consumer), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contractsDir, "ghostprovider.yaml"), []byte(ghostProvider), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contractsDir, "secretconsumer.yaml"), []byte(secretConsumer), 0o600); err != nil {
		t.Fatal(err)
	}
	// secretconsumer shares the "consumer" role/group deliberately — the
	// role only decides which inventory hosts a component runs from, and
	// this canary must resolve for the SAME source host the other tests use.
	inventory := `all:
  children:
    consumer:
      hosts:
        srcbox: {ansible_connection: local, ansible_host: 127.0.0.1, secret_target: "SECRET-CANARY-VALUE"}
    provider:
      hosts:
        tgtbox: {ansible_connection: local, ansible_host: 127.0.0.1}
`
	invPath := filepath.Join(root, "inventory.yml")
	if err := os.WriteFile(invPath, []byte(inventory), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_ROOT", root)
	t.Setenv("PILOT_DATA_DIR", filepath.Join(root, "data"))
	return invPath
}

// runNetworkCheckCLI drives the real, registered `network-check` command
// through cobra's normal SetArgs/Execute path (same pattern as
// docker_target_test.go) rather than calling runNetworkCheck directly, so
// flag parsing and defaults are exercised too. stdout/stderr are kept
// separate, matching a real shell invocation — cobra's own "Error: ...\n
// Usage: ..." noise on a RunE error goes to stderr, never polluting stdout
// (which is where --format json's payload must stay parseable).
//
// rootCmd and its flag values are process-wide singletons, so every
// StringArrayVar flag (--component) must be reset before each call: pflag's
// stringArrayValue only *overwrites* on the first Set() after the flag was
// registered — every Execute() after the first `--component` anywhere in
// this test binary's lifetime would otherwise silently append instead of
// replace.
func runNetworkCheckCLI(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	networkCheckComponentsFlag = nil
	networkCheckAllowSkippedFlag = false
	var stdoutBuf, stderrBuf bytes.Buffer
	rootCmd.SetArgs(append([]string{"network-check"}, args...))
	rootCmd.SetOut(&stdoutBuf)
	rootCmd.SetErr(&stderrBuf)
	err = rootCmd.Execute()
	return stdoutBuf.String(), err
}

func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var withCode ExitCoder
	if !errors.As(err, &withCode) {
		t.Fatalf("error does not carry an ExitCoder: %v", err)
	}
	return withCode.ExitCode()
}

func TestRunNetworkCheck_RealAnsible_PassAndFailAgainstRealSockets(t *testing.T) {
	requireRealAnsible(t)
	_, openPort := listenOnLoopback(t)
	closedPort := closedLoopbackPort(t)
	invPath := writeNetworkCheckFixture(t, openPort, closedPort)

	out, err := runNetworkCheckCLI(t, "--inventory", invPath, "--timeout", "2s")
	if exitCodeOf(t, err) != 1 {
		t.Fatalf("exit code = %d (err=%v), want 1 (the closed port is required and must FAIL): stdout=%s", exitCodeOf(t, err), err, out)
	}
	if !strings.Contains(out, "PASS tcp") || !strings.Contains(out, "provider/open") {
		t.Fatalf("open port did not report PASS:\n%s", out)
	}
	if !strings.Contains(out, "FAIL tcp") || !strings.Contains(out, "provider/closed") {
		t.Fatalf("closed port did not report FAIL:\n%s", out)
	}
	if !strings.Contains(out, "hint:") {
		t.Fatalf("FAIL result is missing an actionable hint:\n%s", out)
	}
}

func TestRunNetworkCheck_RealAnsible_JSONOutputShape(t *testing.T) {
	requireRealAnsible(t)
	_, openPort := listenOnLoopback(t)
	closedPort := closedLoopbackPort(t)
	invPath := writeNetworkCheckFixture(t, openPort, closedPort)

	out, err := runNetworkCheckCLI(t, "--inventory", invPath, "--timeout", "2s", "--format", "json", "--component", "consumer")
	if exitCodeOf(t, err) != 1 {
		t.Fatalf("exit code = %d, want 1: %s", exitCodeOf(t, err), out)
	}
	var rows []map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &rows); jsonErr != nil {
		t.Fatalf("--format json did not produce parseable JSON: %v\n%s", jsonErr, out)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	for _, row := range rows {
		for _, key := range []string{"requirement", "consumerComponent", "providerComponent", "endpoint", "source", "target", "protocol", "port", "status"} {
			if _, ok := row[key]; !ok {
				t.Fatalf("row missing required field %q: %+v", key, row)
			}
		}
	}
}

// TestRunNetworkCheck_RealAnsible_SecretInputNeverAppearsInOutput exercises
// the JSON *renderer*'s secret safety end-to-end (the planner's own
// non-leak guarantee already has direct unit tests in internal/networkcheck
// — this proves the CLI layer doesn't reintroduce a leak on top of it).
func TestRunNetworkCheck_RealAnsible_SecretInputNeverAppearsInOutput(t *testing.T) {
	requireRealAnsible(t)
	_, openPort := listenOnLoopback(t)
	closedPort := closedLoopbackPort(t)
	invPath := writeNetworkCheckFixture(t, openPort, closedPort)

	for _, format := range []string{"text", "json"} {
		out, err := runNetworkCheckCLI(t, "--inventory", invPath, "--timeout", "2s", "--format", format, "--component", "secretconsumer", "--allow-skipped")
		if err != nil {
			t.Fatalf("[%s] unexpected error: %v\n%s", format, err, out)
		}
		if !strings.Contains(out, "SKIP") {
			t.Fatalf("[%s] expected the secret-backed edge to SKIP:\n%s", format, out)
		}
		if strings.Contains(out, "SECRET-CANARY-VALUE") {
			t.Fatalf("[%s] secret canary leaked into output:\n%s", format, out)
		}
	}
}

func TestRunNetworkCheck_UnknownComponentIsExitCode2(t *testing.T) {
	_, openPort := listenOnLoopback(t)
	closedPort := closedLoopbackPort(t)
	invPath := writeNetworkCheckFixture(t, openPort, closedPort)

	out, err := runNetworkCheckCLI(t, "--inventory", invPath, "--component", "does-not-exist")
	if exitCodeOf(t, err) != 2 {
		t.Fatalf("exit code = %d, want 2: err=%v out=%s", exitCodeOf(t, err), err, out)
	}
}

func TestRunNetworkCheck_InvalidFormatIsExitCode2(t *testing.T) {
	_, openPort := listenOnLoopback(t)
	closedPort := closedLoopbackPort(t)
	invPath := writeNetworkCheckFixture(t, openPort, closedPort)

	_, err := runNetworkCheckCLI(t, "--inventory", invPath, "--format", "yaml")
	if exitCodeOf(t, err) != 2 {
		t.Fatalf("exit code = %d, want 2: err=%v", exitCodeOf(t, err), err)
	}
}

func TestBlockingNetworkCheckResults(t *testing.T) {
	results := []networkcheck.Result{
		{Edge: networkcheck.Edge{Required: true}, Status: networkcheck.StatusPass},
		{Edge: networkcheck.Edge{Required: true}, Status: networkcheck.StatusFail},
		{Edge: networkcheck.Edge{Required: true}, Status: networkcheck.StatusError},
		{Edge: networkcheck.Edge{Required: true}, Status: networkcheck.StatusReachableUnconfirmed},
		{Edge: networkcheck.Edge{Required: true}, Status: networkcheck.StatusSkip},
		{Edge: networkcheck.Edge{Required: false}, Status: networkcheck.StatusFail},
	}
	blocking := blockingNetworkCheckResults(results, false)
	if len(blocking) != 3 {
		t.Fatalf("got %d blocking results, want 3 (FAIL+ERROR+required-SKIP): %+v", len(blocking), blocking)
	}
	for _, r := range blocking {
		if r.Status == networkcheck.StatusReachableUnconfirmed {
			t.Fatal("REACHABLE-UNCONFIRMED must never block — UDP has no health signal to gate on")
		}
		if !r.Edge.Required {
			t.Fatal("a non-required edge must never block")
		}
	}

	allowSkipped := blockingNetworkCheckResults(results, true)
	if len(allowSkipped) != 2 {
		t.Fatalf("got %d blocking results with --allow-skipped, want 2 (FAIL+ERROR only): %+v", len(allowSkipped), allowSkipped)
	}
}
