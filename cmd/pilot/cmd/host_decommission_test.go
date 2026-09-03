package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/decommission"
	"github.com/kjelly/pilot/internal/decommission/providers"
)

// writeHostDecommissionFixture builds a minimal single-component contract
// catalog plus a matching hosts.yml, and points PILOT_ROOT/PILOT_DATA_DIR
// at an isolated temp tree — same fixture shape as
// writeInternalEndpointSuggestFixture (internal_endpoint_suggest_cli_test.go).
//
// The fixture's role/component id is deliberately "docker", NOT
// "freeipa-client": Phase 3b (spec.md §37 Phase 3, live-target testing)
// wired a REAL providers.FreeIPAClientProvider into
// buildHostDecommissionProviders for any host actually named in a
// workspace's hosts.yml with role freeipa-client — using that real role
// name here would make this purely-CLI-shape test exercise a live
// ansible-playbook subprocess (which fails in this fixture's fake
// PILOT_ROOT with no real playbooks/ tree), not the "no provider
// registered for this component" fallback path this test actually means
// to prove. "docker" has no registered provider by construction, so it
// stays a true external_state_unsupported case exactly like every
// component did before Phase 3 — and, unlike an invented role name, it is
// one of internal/inventory's compiled-in valid role names (roleContracts
// in contracts.go), so hosts.yml still passes Lint when
// buildHostDecommissionProviders regenerates inventory.yml.
func writeHostDecommissionFixture(t *testing.T) (root, workspaceDir string) {
	t.Helper()
	root = t.TempDir()
	contractsDir := filepath.Join(root, "contracts")
	if err := os.MkdirAll(contractsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dockerComponent := `schemaVersion: 1
id: docker
role: docker
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
	if err := os.WriteFile(filepath.Join(contractsDir, "docker.yaml"), []byte(dockerComponent), 0o600); err != nil {
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
      - docker
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

// TestBuildHostDecommissionProviders_RegistersFreeIPAClientForMatchingHost
// proves the CLI wiring gap Phase 3a explicitly deferred: a workspace host
// with role freeipa-client now gets a REAL providers.FreeIPAClientProvider
// registered under decommission.PlanInput.Providers, keyed by the exact
// component id planner.go looks up (providers.FreeIPAClientProviderID).
// This does not itself invoke ansible (no Plan/Verify call here) — it only
// proves the registry is populated, which is what
// TestHostDecommissionPlanCmd_BlockedPlanExitsNonZeroAndPersists's fixture
// switch (role "docker", not "freeipa-client") deliberately avoids
// exercising end to end.
func TestBuildHostDecommissionProviders_RegistersFreeIPAClientForMatchingHost(t *testing.T) {
	root := t.TempDir()
	hostsYAML := `hosts:
  client1:
    ansible_host: "10.0.0.9"
    env: sandbox
    roles:
      - freeipa-client
    freeipa_roster_file: roster.yaml
`
	if err := os.WriteFile(filepath.Join(root, "hosts.yml"), []byte(hostsYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "roster.yaml"), []byte("schema_version: 2\nfreeipa: {server: ipa1.ipa.pilot.internal}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	provs, err := buildHostDecommissionProviders(root, "client1", contract.Catalog{}, io.Discard)
	if err != nil {
		t.Fatalf("buildHostDecommissionProviders: %v", err)
	}
	if _, ok := provs[providers.FreeIPAClientProviderID]; !ok {
		t.Fatalf("providers = %v, want a registered %q provider", provs, providers.FreeIPAClientProviderID)
	}
	if _, statErr := os.Stat(filepath.Join(root, "inventory.yml")); statErr != nil {
		t.Fatalf("expected inventory.yml to be generated alongside hosts.yml: %v", statErr)
	}
}

// TestBuildHostDecommissionProviders_UnknownHostReturnsEmptyRegistry proves
// buildHostDecommissionProviders degrades to an empty (non-nil) map — never
// an error — when the named host doesn't exist in the workspace, so a
// malformed/mismatched --host still surfaces its authoritative error from
// decommission.PlanHost itself, not from this opportunistic helper.
func TestBuildHostDecommissionProviders_UnknownHostReturnsEmptyRegistry(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hosts.yml"), []byte("hosts: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	provs, err := buildHostDecommissionProviders(root, "nonexistent", contract.Catalog{}, io.Discard)
	if err != nil {
		t.Fatalf("buildHostDecommissionProviders: unexpected error %v", err)
	}
	if len(provs) != 0 {
		t.Fatalf("providers = %v, want an empty registry", provs)
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

// TestParseRetentionDispositionFlags_ValidAndInvalid proves the
// --retention <component-id>=<disposition> CLI flag (spec.md §20.1,
// Phase 6) parses valid dispositions and rejects typos/malformed entries
// with a clear error rather than silently leaving a stateful component
// gated.
func TestParseRetentionDispositionFlags_ValidAndInvalid(t *testing.T) {
	t.Run("nil input yields nil map", func(t *testing.T) {
		got, err := parseRetentionDispositionFlags(nil)
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if got != nil {
			t.Fatalf("got = %v, want nil", got)
		}
	})

	t.Run("valid entries", func(t *testing.T) {
		got, err := parseRetentionDispositionFlags([]string{
			"seaweedfs-s3=retain_on_disk",
			"freeipa-nfs-server=destroy_authorized",
		})
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if got["seaweedfs-s3"] != decommission.RetentionDispositionRetainOnDisk {
			t.Errorf("seaweedfs-s3 = %v, want retain_on_disk", got["seaweedfs-s3"])
		}
		if got["freeipa-nfs-server"] != decommission.RetentionDispositionDestroyAuthorized {
			t.Errorf("freeipa-nfs-server = %v, want destroy_authorized", got["freeipa-nfs-server"])
		}
	})

	for _, bad := range []string{"no-equals-sign", "=missing-component", "component=", "component=not-a-real-disposition"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			if _, err := parseRetentionDispositionFlags([]string{bad}); err == nil {
				t.Fatalf("expected an error for malformed/unknown entry %q", bad)
			}
		})
	}
}

// TestRetentionDispositionsFromPlan_RecoversPersistedDispositions proves
// apply/resume can rebuild the SAME retention dispositions the operator
// supplied at plan time without repeating the --retention flag (spec.md
// §9.1).
func TestRetentionDispositionsFromPlan_RecoversPersistedDispositions(t *testing.T) {
	plan := &decommission.Plan{
		RetentionRequirements: []decommission.RetentionRequirement{
			{ComponentID: "freeipa-nfs-server", Required: true, Disposition: decommission.RetentionDispositionRetainOnDisk, Satisfied: true},
			{ComponentID: "unsatisfied-component", Required: true, Disposition: decommission.RetentionDispositionNone, Satisfied: false},
		},
	}
	got := retentionDispositionsFromPlan(plan)
	if got["freeipa-nfs-server"] != decommission.RetentionDispositionRetainOnDisk {
		t.Errorf("freeipa-nfs-server = %v, want retain_on_disk", got["freeipa-nfs-server"])
	}
	if _, ok := got["unsatisfied-component"]; ok {
		t.Errorf("unsatisfied-component should not appear at all (disposition was RetentionDispositionNone), got %v", got["unsatisfied-component"])
	}

	if got := retentionDispositionsFromPlan(&decommission.Plan{}); got != nil {
		t.Errorf("expected nil for a plan with no retention requirements, got %v", got)
	}
}
