package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/store"
)

func TestSameHostsDependencyChain_DirectAndTransitive(t *testing.T) {
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "consumer", Role: "consumer", Dependencies: []contract.Dependency{
			{Component: "middle", Required: true, Relation: "sameHosts"},
		}},
		{ID: "middle", Role: "middle", Dependencies: []contract.Dependency{
			{Component: "leaf", Required: true, Relation: "sameHosts"},
		}},
		{ID: "leaf", Role: "leaf"},
	})
	if err != nil {
		t.Fatal(err)
	}

	chain, err := sameHostsDependencyChain(catalog, []string{"consumer"})
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 || chain[0].ID != "leaf" || chain[1].ID != "middle" {
		t.Fatalf("chain = %v, want [leaf middle]", contractIDs(chain))
	}
}

func TestSameHostsDependencyChain_ExcludesProviderEndpointAndOptional(t *testing.T) {
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "consumer", Role: "consumer", Dependencies: []contract.Dependency{
			{Component: "provider", Required: true, Relation: "providerEndpoint"},
			{Component: "optional-samehosts", Required: false, Relation: "sameHosts"},
		}},
		{ID: "provider", Role: "provider"},
		{ID: "optional-samehosts", Role: "optional-samehosts"},
	})
	if err != nil {
		t.Fatal(err)
	}

	chain, err := sameHostsDependencyChain(catalog, []string{"consumer"})
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 0 {
		t.Fatalf("chain = %v, want empty (providerEndpoint/optional deps never cascade)", contractIDs(chain))
	}
}

func TestSameHostsDependencyChain_AlreadySelectedComponentNeverCascaded(t *testing.T) {
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "consumer", Role: "consumer", Dependencies: []contract.Dependency{
			{Component: "leaf", Required: true, Relation: "sameHosts"},
		}},
		{ID: "leaf", Role: "leaf"},
	})
	if err != nil {
		t.Fatal(err)
	}

	chain, err := sameHostsDependencyChain(catalog, []string{"consumer", "leaf"})
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 0 {
		t.Fatalf("chain = %v, want empty (leaf is already being applied directly)", contractIDs(chain))
	}
}

func TestSameHostsDependencyChain_DetectsCycle(t *testing.T) {
	// The cycle must sit entirely within the dependency graph, not
	// involve "consumer" itself — "consumer" is pre-marked done (it's
	// already being applied directly), so a back-edge straight to it
	// would just be silently skipped rather than exercise the
	// visiting-set cycle guard.
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "consumer", Role: "consumer", Dependencies: []contract.Dependency{{Component: "b", Required: true, Relation: "sameHosts"}}},
		{ID: "b", Role: "b", Dependencies: []contract.Dependency{{Component: "c", Required: true, Relation: "sameHosts"}}},
		{ID: "c", Role: "c", Dependencies: []contract.Dependency{{Component: "b", Required: true, Relation: "sameHosts"}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sameHostsDependencyChain(catalog, []string{"consumer"}); err == nil {
		t.Fatal("sameHostsDependencyChain() error = nil, want cycle detected")
	}
}

// TestExecuteRecordedDeployment_CascadesSameHostsDependencyFirst is the
// end-to-end proof for design layer 2: deploying "consumer" (whose real
// contract fixture mirrors wazuh-manager's required sameHosts dependency
// on "leaf", mirroring docker) must actually apply leaf's own playbook
// first — not merely check that leaf's inventory group is non-empty
// (that was already true before this feature; see layer 1) — before
// consumer's playbook runs. Verified by asserting the evidence store
// recorded a successful run for BOTH components.
func TestExecuteRecordedDeployment_CascadesSameHostsDependencyFirst(t *testing.T) {
	root := writeSameHostsCascadeFixture(t)
	t.Chdir(root)
	// Set the package-level dataDir var directly, not just $PILOT_DATA_DIR
	// — resolvePilotDataDir() checks dataDir first, and it's a
	// package-level var bound to --data-dir that an earlier test's
	// rootCmd.Execute() can leave non-empty for the rest of this test
	// binary (see the pilot-cobra-pflag-changed-state-persists-test-hazard
	// pattern already used by mcp_edit_tools_grants_test.go).
	testDataDir := t.TempDir()
	dataDir = testDataDir
	t.Cleanup(func() { dataDir = "" })

	binDir := t.TempDir()
	invJSON := `{"_meta":{"hostvars":{"host-a":{}}},"leaf":{"hosts":["host-a"]},"consumer":{"hosts":["host-a"]}}`
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte("#!/bin/sh\nprintf '%s\\n' '"+invJSON+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ansibleFixture := `#!/bin/sh
case "$*" in
  *--list-hosts*) printf '%s\n' '  hosts (1):' '    host-a'; exit 0 ;;
  *) printf '{"plays":[{"tasks":[{"hosts":{"host-a":{"stdout":"unknown","rc":0}}}]}]}\n' ;;
esac
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

	oldPrompt := activePromptAutomation
	activePromptAutomation = &promptAutomation{useDefaults: true, forceApply: true}
	t.Cleanup(func() { activePromptAutomation = oldPrompt })
	stubDeploymentAvailabilityAllReachable(t)

	if err := executeRecordedDeployment(context.Background(), runner, os.Stdout, "consumer-apply.yml", inv, "", "", []string{"stage=sandbox"}, vaultInput{}, "sandbox", []string{"consumer"}); err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(filepath.Join(testDataDir, "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	leafRuns, err := s.ListRuns(store.RunFilter{Component: "leaf"})
	if err != nil || len(leafRuns) != 1 || leafRuns[0].Outcome != "success" {
		t.Fatalf("leaf runs=%+v err=%v, want exactly one successful cascaded run", leafRuns, err)
	}
	consumerRuns, err := s.ListRuns(store.RunFilter{Component: "consumer"})
	if err != nil || len(consumerRuns) != 1 || consumerRuns[0].Outcome != "success" {
		t.Fatalf("consumer runs=%+v err=%v, want exactly one successful run", consumerRuns, err)
	}
	// StartedAt is RFC3339Nano, so lexicographic and chronological order agree.
	if leafRuns[0].StartedAt > consumerRuns[0].StartedAt {
		t.Fatalf("leaf run (%s) must not start after consumer's run (%s)", leafRuns[0].StartedAt, consumerRuns[0].StartedAt)
	}
}

// TestApplySameHostsDependencyChain_NoOpForNonApplyPlaybook confirms a
// decommission/rollback/upgrade run never re-provisions a sameHosts
// dependency — only an apply playbook triggers the cascade.
func TestApplySameHostsDependencyChain_NoOpForNonApplyPlaybook(t *testing.T) {
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "consumer", Role: "consumer", Dependencies: []contract.Dependency{
			{Component: "leaf", Required: true, Relation: "sameHosts"},
		}, Playbooks: contract.Playbooks{Apply: "consumer-apply.yml"}},
		{ID: "leaf", Role: "leaf", Playbooks: contract.Playbooks{Apply: "leaf-apply.yml"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A rollback/decommission playbook path never equals any component's
	// Playbooks.Apply, so this must return immediately without touching
	// runner/out/inv/limit/vault at all.
	err = applySameHostsDependencyChain(context.Background(), nil, nil, catalog, []string{"consumer"}, "consumer-decommission.yml", "unused-inv.yml", "", nil, vaultInput{}, "sandbox")
	if err != nil {
		t.Fatalf("applySameHostsDependencyChain() error = %v, want nil (no-op)", err)
	}
}

// writeSameHostsCascadeFixture builds a minimal two-component contract
// catalog — leaf (mirrors docker) and consumer (mirrors wazuh-manager,
// with a required sameHosts dependency on leaf) — under a temp
// PILOT_ROOT, same fixture shape as
// writeInternalEndpointSuggestFixture/network_check_test.go.
func writeSameHostsCascadeFixture(t *testing.T) (root string) {
	t.Helper()
	root = t.TempDir()
	contractsDir := filepath.Join(root, "contracts")
	if err := os.MkdirAll(contractsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	leaf := `schemaVersion: 1
id: leaf
role: leaf
specs: [{path: "fake.md", rows: {all: true}}]
playbooks: {apply: "leaf-apply.yml"}
dependencies: []
hostCardinality: one-or-more
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
playbooks: {apply: "consumer-apply.yml"}
dependencies:
  - {component: leaf, required: true, relation: sameHosts}
hostCardinality: exactly-one
resources: {minCPU: 1, minRAMMiB: 1, minDiskGiB: 1}
stagePolicy: {variable: stage, default: sandbox}
evidenceRequirement: {targetTest: vm, idempotency: required}
verification: {autoDeploy: false}
site: {include: false, order: 1, vars: {}, tags: [], optIn: true}
`
	if err := os.WriteFile(filepath.Join(contractsDir, "leaf.yaml"), []byte(leaf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contractsDir, "consumer.yaml"), []byte(consumer), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_ROOT", root)
	return root
}
