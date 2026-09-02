package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeHostDecommissionFixture builds a minimal single-component contract
// catalog plus a matching hosts.yml, and points PILOT_ROOT/PILOT_DATA_DIR
// at an isolated temp tree — same fixture shape as
// writeInternalEndpointSuggestFixture (internal_endpoint_suggest_cli_test.go).
func writeHostDecommissionFixture(t *testing.T) (root, workspaceDir string) {
	t.Helper()
	root = t.TempDir()
	contractsDir := filepath.Join(root, "contracts")
	if err := os.MkdirAll(contractsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	freeipaClient := `schemaVersion: 1
id: freeipa-client
role: freeipa-client
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
	if err := os.WriteFile(filepath.Join(contractsDir, "freeipa-client.yaml"), []byte(freeipaClient), 0o600); err != nil {
		t.Fatal(err)
	}

	workspaceDir = filepath.Join(root, "workspace")
	if err := os.MkdirAll(workspaceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	hostsYAML := `hosts:
  web1:
    ansible_host: "10.0.0.5"
    env: sandbox
    roles:
      - freeipa-client
`
	if err := os.WriteFile(filepath.Join(workspaceDir, "hosts.yml"), []byte(hostsYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PILOT_ROOT", root)
	t.Setenv("PILOT_DATA_DIR", filepath.Join(root, "data"))
	return root, workspaceDir
}

func resetHostDecommissionFlags() {
	hostDecommissionPlanDir = ""
	hostDecommissionPlanHost = ""
	hostDecommissionPlanJSON = false
	hostDecommissionShowID = ""
	hostDecommissionShowJSON = false
}

// TestHostDecommissionPlanCmd_BlockedPlanExitsNonZeroAndPersists proves the
// CLI's Phase 1 shape end to end: `plan` produces a structured blocked
// result (freeipa-client has no registered provider yet — exit non-zero,
// not a crash), persists it, and `show` reads the same plan back.
func TestHostDecommissionPlanCmd_BlockedPlanExitsNonZeroAndPersists(t *testing.T) {
	_, workspaceDir := writeHostDecommissionFixture(t)
	resetHostDecommissionFlags()
	t.Cleanup(resetHostDecommissionFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"host", "decommission", "plan", "--dir", workspaceDir, "--host", "web1"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want non-nil — freeipa-client has no registered decommission provider yet, so this plan must be blocked")
	}
	printed := out.String()
	if !strings.Contains(printed, "status=blocked") {
		t.Fatalf("printed output = %q, want it to report status=blocked", printed)
	}
	if !strings.Contains(printed, "external_state_unsupported") {
		t.Fatalf("printed output = %q, want an external_state_unsupported blocker", printed)
	}

	planID := extractPlanID(t, printed)

	var showOut bytes.Buffer
	rootCmd.SetOut(&showOut)
	rootCmd.SetErr(&showOut)
	rootCmd.SetArgs([]string{"host", "decommission", "show", "--id", planID})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("show Execute() error = %v", err)
	}
	if !strings.Contains(showOut.String(), planID) {
		t.Fatalf("show output = %q, want it to include the plan id %q", showOut.String(), planID)
	}
	if !strings.Contains(showOut.String(), "web1") {
		t.Fatalf("show output = %q, want it to include host web1", showOut.String())
	}
}

// TestHostDecommissionPlanCmd_MissingHostFlagErrors proves --host is
// required (a bad flag is a CLI usage error, not a silent no-op).
func TestHostDecommissionPlanCmd_MissingHostFlagErrors(t *testing.T) {
	_, workspaceDir := writeHostDecommissionFixture(t)
	resetHostDecommissionFlags()
	t.Cleanup(resetHostDecommissionFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"host", "decommission", "plan", "--dir", workspaceDir})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want non-nil when --host is omitted")
	}
}

// TestHostDecommissionPlanCmd_JSONOutputParses proves --json produces
// machine-readable output containing the plan id and blocked status.
func TestHostDecommissionPlanCmd_JSONOutputParses(t *testing.T) {
	_, workspaceDir := writeHostDecommissionFixture(t)
	resetHostDecommissionFlags()
	t.Cleanup(resetHostDecommissionFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"host", "decommission", "plan", "--dir", workspaceDir, "--host", "web1", "--json"})
	_ = rootCmd.Execute() // blocked plan still exits non-zero; only the output shape matters here

	if !strings.Contains(out.String(), `"Status": "blocked"`) {
		t.Fatalf("--json output = %s, want a Status: blocked field", out.String())
	}
	if !strings.Contains(out.String(), `"ID": "hd-`) {
		t.Fatalf("--json output = %s, want an ID field starting with hd-", out.String())
	}
}

// extractPlanID pulls the plan id out of printHostDecommissionPlan's
// human-readable first line: "PLAN <id> host=<host> status=<status> hash=<hash>".
func extractPlanID(t *testing.T, printed string) string {
	t.Helper()
	const prefix = "PLAN "
	idx := strings.Index(printed, prefix)
	if idx < 0 {
		t.Fatalf("printed output = %q, want a line starting with %q", printed, prefix)
	}
	rest := printed[idx+len(prefix):]
	sp := strings.IndexByte(rest, ' ')
	if sp < 0 {
		t.Fatalf("could not parse plan id out of %q", rest)
	}
	return rest[:sp]
}
