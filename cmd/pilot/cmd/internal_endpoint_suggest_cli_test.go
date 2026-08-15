package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeInternalEndpointSuggestFixture builds a minimal two-component contract
// catalog (dashboard, with one autoPublish-eligible http endpoint; a bare
// reverse-proxy component) plus a matching two-group ansible inventory, and
// points PILOT_ROOT at it — same fixture shape as
// writeNetworkCheckFixture/network_check_test.go, reused here since
// `internal-endpoint suggest` shells out to the same real ansible-inventory
// code path (resolveInventoryGroups).
func writeInternalEndpointSuggestFixture(t *testing.T) (root, invPath string) {
	t.Helper()
	root = t.TempDir()
	contractsDir := filepath.Join(root, "contracts")
	if err := os.MkdirAll(contractsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dashboard := `schemaVersion: 1
id: dashboard
role: dashboard
specs: [{path: "fake.md", rows: {all: true}}]
playbooks: {apply: "fake-apply.yml"}
dependencies: []
endpoints:
  - {name: grafana, scheme: http, port: 3000, autoPublish: {eligible: true, subdomain: grafana}}
hostCardinality: exactly-one
resources: {minCPU: 1, minRAMMiB: 1, minDiskGiB: 1}
stagePolicy: {variable: stage, default: sandbox}
evidenceRequirement: {targetTest: vm, idempotency: required}
verification: {autoDeploy: false}
site: {include: false, order: 1, vars: {}, tags: [], optIn: true}
`
	reverseProxy := `schemaVersion: 1
id: reverse-proxy
role: reverse-proxy
specs: [{path: "fake.md", rows: {all: true}}]
playbooks: {apply: "fake-apply.yml"}
dependencies: []
hostCardinality: one-or-more
resources: {minCPU: 1, minRAMMiB: 1, minDiskGiB: 1}
stagePolicy: {variable: stage, default: sandbox}
evidenceRequirement: {targetTest: vm, idempotency: required}
verification: {autoDeploy: false}
site: {include: false, order: 1, vars: {}, tags: [], optIn: true}
`
	if err := os.WriteFile(filepath.Join(contractsDir, "dashboard.yaml"), []byte(dashboard), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contractsDir, "reverse-proxy.yaml"), []byte(reverseProxy), 0o600); err != nil {
		t.Fatal(err)
	}
	inv := `all:
  children:
    dashboard:
      hosts:
        nexus: {ansible_connection: local}
    reverse-proxy:
      hosts:
        nexus: {}
`
	invPath = filepath.Join(root, "inventory.yml")
	if err := os.WriteFile(invPath, []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_ROOT", root)
	t.Setenv("PILOT_DATA_DIR", filepath.Join(root, "data"))
	return root, invPath
}

// resetIEPSuggestFlags clears the suggest subcommand's package-level flag
// vars before each test — plain string flags don't reset themselves between
// rootCmd.Execute() calls in the same test binary (only the value explicitly
// passed on the next SetArgs sticks), same caveat runNetworkCheckCLI's own
// doc comment describes for --component.
func resetIEPSuggestFlags() {
	iepSuggestInventoryFlag = ""
	iepSuggestManifestFlag = ""
	iepSuggestFreeIPADNSManifestFlag = ""
	iepSuggestZoneFlag = ""
	iepSuggestProxyHostFlag = ""
}

func TestInternalEndpointSuggestCmd_PrintsCandidate(t *testing.T) {
	requireRealAnsible(t)
	resetIEPSuggestFlags()
	_, invPath := writeInternalEndpointSuggestFixture(t)

	out, err := iepCLIRun(t, "internal-endpoint", "suggest", "--inventory", invPath, "--zone", "it.pilot.internal.")
	if err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out)
	}
	if !strings.Contains(out, "grafana.it.pilot.internal") {
		t.Fatalf("output = %q, want it to mention grafana.it.pilot.internal", out)
	}
	if !strings.Contains(out, "reverse_proxy") {
		t.Fatalf("output = %q, want route.mode reverse_proxy", out)
	}
	if !strings.Contains(out, "freeipa") {
		t.Fatalf("output = %q, want tls.mode freeipa", out)
	}
}

func TestInternalEndpointSuggestCmd_RequiresZoneOrDNSManifest(t *testing.T) {
	requireRealAnsible(t)
	resetIEPSuggestFlags()
	_, invPath := writeInternalEndpointSuggestFixture(t)

	out, err := iepCLIRun(t, "internal-endpoint", "suggest", "--inventory", invPath)
	if err == nil {
		t.Fatalf("expected an error when neither --zone nor --freeipa-dns-manifest is set, output: %s", out)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "zone") {
		t.Fatalf("error = %v, want it to mention zone", err)
	}
}

func TestInternalEndpointSuggestCmd_AmbiguousProxyHostErrors(t *testing.T) {
	requireRealAnsible(t)
	resetIEPSuggestFlags()
	root, _ := writeInternalEndpointSuggestFixture(t)

	inv := `all:
  children:
    dashboard:
      hosts:
        nexus: {}
    reverse-proxy:
      hosts:
        nexus: {}
        nexus2: {}
`
	invPath := filepath.Join(root, "inventory-ambiguous.yml")
	if err := os.WriteFile(invPath, []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := iepCLIRun(t, "internal-endpoint", "suggest", "--inventory", invPath, "--zone", "it.pilot.internal.")
	if err == nil {
		t.Fatalf("expected an error for an ambiguous reverse-proxy host, output: %s", out)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "ambiguous") {
		t.Fatalf("error = %v, want it to mention ambiguous", err)
	}
}

func TestInternalEndpointSuggestCmd_ExplicitProxyHostOverridesAmbiguity(t *testing.T) {
	requireRealAnsible(t)
	resetIEPSuggestFlags()
	root, _ := writeInternalEndpointSuggestFixture(t)

	inv := `all:
  children:
    dashboard:
      hosts:
        nexus: {}
    reverse-proxy:
      hosts:
        nexus: {}
        nexus2: {}
`
	invPath := filepath.Join(root, "inventory-override.yml")
	if err := os.WriteFile(invPath, []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := iepCLIRun(t, "internal-endpoint", "suggest", "--inventory", invPath, "--zone", "it.pilot.internal.", "--proxy-host", "nexus2")
	if err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out)
	}
	if !strings.Contains(out, "nexus2") {
		t.Fatalf("output = %q, want the explicit --proxy-host nexus2 to be used", out)
	}
}
