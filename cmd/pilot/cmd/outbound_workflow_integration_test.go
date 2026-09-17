// outbound_workflow_integration_test.go implements design spec §46.6's
// W1-W20 workflow regression tests: end-to-end coverage that a real
// deploy/reconcile/gateway-scope/access-reconcile/breakglass run
// actually publishes exactly one terminal webhook event, on top of the
// pure aggregation-logic unit tests in outbound_workflow_test.go.
//
// Every TestOutboundWorkflow_W<N> function corresponds 1:1 to a row ID
// in docs/verification/outbound-webhook.md's C-checks, whose probes
// `go test -run` this exact function name — so these names are a wire
// contract with that spec file, not just a naming convention.
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/outbound"
)

// --- shared fixture plumbing ------------------------------------------------

// webhookCapture is a minimal httptest.Server request recorder: every
// W-test needs to assert "exactly one HTTP delivery" or inspect the
// envelope body, never more than that.
type webhookCapture struct {
	mu     sync.Mutex
	bodies [][]byte
	status int
}

func newWebhookCapture(status int) *webhookCapture {
	if status == 0 {
		status = http.StatusNoContent
	}
	return &webhookCapture{status: status}
}

func (c *webhookCapture) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.bodies = append(c.bodies, body)
		c.mu.Unlock()
		w.WriteHeader(c.status)
	}
}

func (c *webhookCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

func (c *webhookCapture) last() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.bodies) == 0 {
		return nil
	}
	return c.bodies[len(c.bodies)-1]
}

// writeOutboundWorkflowContracts writes a small, self-contained contract
// catalog under a temp PILOT_ROOT: leaf/consumer mirror
// writeSameHostsCascadeFixture's sameHosts pair (docker/wazuh-manager
// shape), each tagged with a distinct design-spec effect so
// outbound-routing tests have something concrete to match against;
// freeipa-identity/freeipa-dns mirror the two real components W5/W6
// name explicitly.
func writeOutboundWorkflowContracts(t *testing.T) (root string) {
	t.Helper()
	root = t.TempDir()
	contractsDir := filepath.Join(root, "contracts")
	if err := os.MkdirAll(contractsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(contractsDir, name+".yaml"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("leaf", `schemaVersion: 1
id: leaf
role: leaf
effects: [identity.hostgroups]
specs: [{path: "fake.md", rows: {all: true}}]
playbooks: {apply: "playbooks/leaf-apply.yml"}
dependencies: []
hostCardinality: one-or-more
resources: {minCPU: 1, minRAMMiB: 1, minDiskGiB: 1}
stagePolicy: {variable: stage, default: sandbox}
evidenceRequirement: {targetTest: vm, idempotency: required}
verification: {autoDeploy: false}
site: {include: true, order: 1, vars: {}, tags: [], optIn: false}
`)
	write("consumer", `schemaVersion: 1
id: consumer
role: consumer
effects: [access.hbac]
specs: [{path: "fake.md", rows: {all: true}}]
playbooks: {apply: "playbooks/consumer-apply.yml"}
dependencies:
  - {component: leaf, required: true, relation: sameHosts}
hostCardinality: exactly-one
resources: {minCPU: 1, minRAMMiB: 1, minDiskGiB: 1}
stagePolicy: {variable: stage, default: sandbox}
evidenceRequirement: {targetTest: vm, idempotency: required}
verification: {autoDeploy: false}
site: {include: true, order: 2, vars: {}, tags: [], optIn: false}
`)
	write("freeipa-identity", `schemaVersion: 1
id: freeipa-identity
role: freeipa-identity
effects: [identity.users, access.hbac, access.sudo, access.grants]
specs: [{path: "fake.md", rows: {all: true}}]
playbooks: {apply: "freeipa-identity-apply.yml"}
dependencies: []
hostCardinality: one-or-more
resources: {minCPU: 1, minRAMMiB: 1, minDiskGiB: 1}
stagePolicy: {variable: stage, default: sandbox}
evidenceRequirement: {targetTest: vm, idempotency: required}
verification: {autoDeploy: false}
site: {include: false, order: 3, vars: {}, tags: [], optIn: true}
`)
	write("freeipa-dns", `schemaVersion: 1
id: freeipa-dns
role: freeipa-dns
effects: [dns.zones, dns.records]
specs: [{path: "fake.md", rows: {all: true}}]
playbooks: {apply: "freeipa-dns-apply.yml"}
dependencies: []
hostCardinality: one-or-more
resources: {minCPU: 1, minRAMMiB: 1, minDiskGiB: 1}
stagePolicy: {variable: stage, default: sandbox}
evidenceRequirement: {targetTest: vm, idempotency: required}
verification: {autoDeploy: false}
site: {include: false, order: 4, vars: {}, tags: [], optIn: true}
`)
	playbooksDir := filepath.Join(root, "playbooks")
	if err := os.MkdirAll(playbooksDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// site.yml's own import list gates componentsForPlaybook's site-wide
	// resolution (siteYMLImportedPlaybooks) — only leaf/consumer are
	// imported here since only they are Site.Include:true in this fixture.
	siteYML := "- import_playbook: leaf-apply.yml\n- import_playbook: consumer-apply.yml\n"
	if err := os.WriteFile(filepath.Join(playbooksDir, "site.yml"), []byte(siteYML), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_ROOT", root)
	return root
}

// writeOutboundInventoryFixture puts a fake ansible-inventory binary on
// PATH that answers `--list` with groups (role -> hosts), and a fake
// ansible ad-hoc binary that answers any --list-hosts/module call with a
// generic success — the same technique
// TestExecuteCatalogReconcileBatch_CollectsAuthorizationOnceAndScopesDependency
// (deploy_samehosts_cascade_test.go) already relies on.
func writeOutboundInventoryFixture(t *testing.T, binDir string, groups map[string][]string) {
	t.Helper()
	meta := map[string]any{}
	allHosts := map[string]bool{}
	payload := map[string]any{"_meta": map[string]any{"hostvars": meta}}
	for role, hosts := range groups {
		payload[role] = map[string]any{"hosts": hosts}
		for _, h := range hosts {
			meta[h] = map[string]any{}
			allHosts[h] = true
		}
	}
	allList := make([]string, 0, len(allHosts))
	for h := range allHosts {
		allList = append(allList, h)
	}
	payload["all"] = map[string]any{"hosts": allList}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	invScript := "#!/bin/sh\nprintf '%s\\n' '" + string(data) + "'\n"
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte(invScript), 0o755); err != nil {
		t.Fatal(err)
	}
	adhocScript := `#!/bin/sh
case "$*" in
  *--list-hosts*) printf '%s\n' '  hosts (1):' '    host-a'; exit 0 ;;
  *) printf '{"plays":[{"tasks":[{"hosts":{"host-a":{"stdout":"unknown","rc":0}}}]}]}\n' ;;
esac
`
	if err := os.WriteFile(filepath.Join(binDir, "ansible"), []byte(adhocScript), 0o755); err != nil {
		t.Fatal(err)
	}
	// A generic, always-succeeding ansible-playbook on PATH — for callers
	// that build their own ansible.NewRunner() internally rather than
	// accepting an injected *ansible.Runner (e.g.
	// accessgrants.ReconcileOnce), which always resolves the bare
	// "ansible-playbook" name via PATH. Tests that need a specific exit
	// code pass runner.Binary as an absolute path instead, which takes
	// precedence over this PATH entry.
	if err := os.WriteFile(filepath.Join(binDir, "ansible-playbook"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// writeOutboundWorkflowIntegrationsYAML writes an integrations.yaml whose
// single webhook's events[] block is exactly eventsYAML (already
// indented as `      - operation: ...` lines, mirroring
// webhook_test.go's writeIntegrationsYAML).
func writeOutboundWorkflowIntegrationsYAML(t *testing.T, dir, endpoint, eventsYAML string) {
	t.Helper()
	content := "schema_version: 1\nsource_id: w-test-source\nwebhooks:\n" +
		"  - name: w-test-hook\n    enabled: true\n    endpoint: " + endpoint + "\n" +
		"    projection: user_host_access_v1\n    events:\n" + eventsYAML +
		"    auth:\n      type: bearer\n      secret_env: PILOT_W_TEST_TOKEN\n" +
		"    tls:\n      allow_insecure_http: true\n"
	if err := os.WriteFile(filepath.Join(dir, "integrations.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const invalidIntegrationsYAML = `schema_version: 1
source_id: w-test-source
webhooks:
  - name: w-test-hook
    enabled: true
    endpoint: https://example.invalid/hook
    projection: user_host_access_v1
    events:
      - operation: deploy
        result: success
        payload: snapshot
    auth:
      type: not_a_real_auth_type
      secret_env: PILOT_W_TEST_TOKEN
`

// outboundWorkflowEnv bundles the fixture pieces every W-test needs:
// contract catalog, workspace (inventory.yml + integrations.yaml),
// isolated data dir, and a capture server standing in for the external
// webhook consumer.
type outboundWorkflowEnv struct {
	t         *testing.T
	workspace string
	inv       string
	capture   *webhookCapture
	server    *httptest.Server
}

// newOutboundWorkflowEnv wires PILOT_ROOT, PATH (fake ansible-inventory
// + ansible), an isolated data dir/PILOT_DATA_DIR, and a capture server
// whose endpoint is written into workspace/integrations.yaml with
// eventsYAML as its events[] block. groups maps contract role -> hosts,
// same shape writeOutboundInventoryFixture takes.
func newOutboundWorkflowEnv(t *testing.T, groups map[string][]string, eventsYAML string, status int) *outboundWorkflowEnv {
	t.Helper()
	writeOutboundWorkflowContracts(t)

	binDir := t.TempDir()
	writeOutboundInventoryFixture(t, binDir, groups)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	workspace := t.TempDir()
	inv := filepath.Join(workspace, "inventory.yml")
	if err := os.WriteFile(inv, []byte("all:\n  hosts:\n    host-a: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	capture := newWebhookCapture(status)
	server := httptest.NewServer(capture.handler())
	t.Cleanup(server.Close)
	if eventsYAML != "" {
		writeOutboundWorkflowIntegrationsYAML(t, workspace, server.URL, eventsYAML)
	}
	t.Setenv("PILOT_W_TEST_TOKEN", "w-test-secret")

	testDataDir := t.TempDir()
	oldDataDir := dataDir
	dataDir = testDataDir
	t.Setenv("PILOT_DATA_DIR", testDataDir)
	t.Cleanup(func() { dataDir = oldDataDir })

	oldPrompt := activePromptAutomation
	activePromptAutomation = &promptAutomation{useDefaults: true, forceApply: true}
	t.Cleanup(func() { activePromptAutomation = oldPrompt })

	stubDeploymentAvailabilityAllReachable(t)

	return &outboundWorkflowEnv{t: t, workspace: workspace, inv: inv, capture: capture, server: server}
}

// eventsYAMLFor is the standard single-rule events[] block most W-tests
// use: it matches one (operation, result) pair unconditionally.
func eventsYAMLFor(operation outbound.OperationKind, result outbound.ResultClass) string {
	return fmt.Sprintf("      - operation: %s\n        result: %s\n        payload: snapshot\n", operation, result)
}

// newRunnerWithExitCode returns an ansible.Runner whose ansible-playbook
// binary unconditionally exits with code (0 = success), the same
// writeExitFixture technique deploy_exitcode_regression_test.go uses.
func newRunnerWithExitCode(t *testing.T, code int) *ansible.Runner {
	runner := ansible.NewRunner()
	runner.Binary = writeExitFixture(t, code)
	runner.Timeout = 5 * time.Second
	return runner
}

func loadOutboundWorkflowCatalog(t *testing.T) contract.Catalog {
	t.Helper()
	root, err := resolveContractRoot("")
	if err != nil {
		t.Fatal(err)
	}
	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func deployPlaybookEntry(id, playbook string) deployPlaybook {
	return deployPlaybook{Key: id, Label: id, Playbook: playbook, StageVar: "stage"}
}

// --- W1-W3: deploy-side "exactly one event" ---------------------------------

// TestOutboundWorkflow_W1 locks: one-component deploy => exactly one
// terminal event (design spec §46.6 W1).
func TestOutboundWorkflow_W1(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultSuccess), 0)
	catalog := loadOutboundWorkflowCatalog(t)
	runner := newRunnerWithExitCode(t, 0)

	err := runCatalogPlaybookDeployEntry(context.Background(), runner, &bytes.Buffer{}, env.inv, "apply", catalog,
		deployPlaybookEntry("leaf", "leaf-apply.yml"), nil, deployInventorySnapshot{}, false, nil)
	if err != nil {
		t.Fatalf("runCatalogPlaybookDeployEntry: %v", err)
	}
	if got := env.capture.count(); got != 1 {
		t.Fatalf("webhook deliveries = %d, want exactly 1", got)
	}
}

// TestOutboundWorkflow_W2 locks: multi-component deploy => exactly one
// event (design spec §46.6 W2) — driven via a site.yml deploy, the only
// deploy-side path that resolves more than one component per workflow
// (see runSiteDeploy's own doc comment: "Site deploy's requested/executed
// component sets are exactly what the site.yml transaction itself
// resolved").
func TestOutboundWorkflow_W2(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}, "consumer": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultSuccess), 0)
	runner := newRunnerWithExitCode(t, 0)

	err := runSiteDeploy(context.Background(), runner, &bytes.Buffer{}, env.inv, deployInventorySnapshot{})
	if err != nil {
		t.Fatalf("runSiteDeploy: %v", err)
	}
	if got := env.capture.count(); got != 1 {
		t.Fatalf("webhook deliveries = %d, want exactly 1 for a multi-component site deploy", got)
	}
}

// TestOutboundWorkflow_W3 locks: a sameHosts auto-cascaded dependency
// still counts as one workflow => one event (design spec §46.6 W3):
// deploying "consumer" alone must cascade leaf's apply first (design
// spec §28.2/INV-1), but still publish exactly one terminal event for
// the whole cascade.
func TestOutboundWorkflow_W3(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}, "consumer": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultSuccess), 0)
	catalog := loadOutboundWorkflowCatalog(t)
	runner := newRunnerWithExitCode(t, 0)

	err := runCatalogPlaybookDeployEntry(context.Background(), runner, &bytes.Buffer{}, env.inv, "apply", catalog,
		deployPlaybookEntry("consumer", "consumer-apply.yml"), nil, deployInventorySnapshot{}, false, nil)
	if err != nil {
		t.Fatalf("runCatalogPlaybookDeployEntry: %v", err)
	}
	if got := env.capture.count(); got != 1 {
		t.Fatalf("webhook deliveries = %d, want exactly 1 for consumer+cascaded leaf", got)
	}
}

// --- W4-W6: reconcile-side aggregation and effects_any matching -------------

// reconcileEventsYAMLEffectsAny builds an operation=reconcile events[]
// rule gated on effects_any — the only rule shape §7.5/validateEffectsAny
// allow effects_any on at all (a deploy-operation rule may never carry
// it).
func reconcileEventsYAMLEffectsAny(result outbound.ResultClass, effects ...string) string {
	return fmt.Sprintf("      - operation: reconcile\n        result: %s\n        effects_any: [%s]\n        payload: snapshot\n",
		result, strings.Join(effects, ", "))
}

func reconcileRequest(componentID, playbook string) catalogDeploymentRequest {
	return catalogDeploymentRequest{playbook: playbook, componentHints: []string{componentID}, stage: "sandbox"}
}

// TestOutboundWorkflow_W4 locks: multi-component reconcile => one event
// (design spec §46.6 W4).
func TestOutboundWorkflow_W4(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"freeipa-identity": {"host-a"}, "freeipa-dns": {"host-a"}},
		eventsYAMLFor(outbound.OperationReconcile, outbound.ResultSuccess), 0)
	runner := newRunnerWithExitCode(t, 0)

	requests := []catalogDeploymentRequest{
		reconcileRequest("freeipa-identity", "freeipa-identity-apply.yml"),
		reconcileRequest("freeipa-dns", "freeipa-dns-apply.yml"),
	}
	for i := range requests {
		requests[i].inv = env.inv
		requests[i].workspaceDir = env.workspace
	}
	if err := executeCatalogReconcileBatch(context.Background(), runner, &bytes.Buffer{}, requests); err != nil {
		t.Fatalf("executeCatalogReconcileBatch: %v", err)
	}
	if got := env.capture.count(); got != 1 {
		t.Fatalf("webhook deliveries = %d, want exactly 1 for a 2-component reconcile batch", got)
	}
}

// TestOutboundWorkflow_W5 locks: freeipa-identity matches an
// identity-scoped reconcile subscription (design spec §46.6 W5).
func TestOutboundWorkflow_W5(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"freeipa-identity": {"host-a"}},
		reconcileEventsYAMLEffectsAny(outbound.ResultSuccess, "identity.users"), 0)
	runner := newRunnerWithExitCode(t, 0)

	requests := []catalogDeploymentRequest{reconcileRequest("freeipa-identity", "freeipa-identity-apply.yml")}
	requests[0].inv = env.inv
	requests[0].workspaceDir = env.workspace
	if err := executeCatalogReconcileBatch(context.Background(), runner, &bytes.Buffer{}, requests); err != nil {
		t.Fatalf("executeCatalogReconcileBatch: %v", err)
	}
	if got := env.capture.count(); got != 1 {
		t.Fatalf("webhook deliveries = %d, want exactly 1 (freeipa-identity's identity.users effect must match)", got)
	}
}

// TestOutboundWorkflow_W6 locks: freeipa-dns (dns.* effects only) does
// NOT match an identity-only reconcile subscription (design spec §46.6
// W6) — MatchEventRule's effects_any gate must actually exclude it, not
// just default-match every reconcile success.
func TestOutboundWorkflow_W6(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"freeipa-dns": {"host-a"}},
		reconcileEventsYAMLEffectsAny(outbound.ResultSuccess, "identity.users"), 0)
	runner := newRunnerWithExitCode(t, 0)

	requests := []catalogDeploymentRequest{reconcileRequest("freeipa-dns", "freeipa-dns-apply.yml")}
	requests[0].inv = env.inv
	requests[0].workspaceDir = env.workspace
	if err := executeCatalogReconcileBatch(context.Background(), runner, &bytes.Buffer{}, requests); err != nil {
		t.Fatalf("executeCatalogReconcileBatch: %v", err)
	}
	if got := env.capture.count(); got != 0 {
		t.Fatalf("webhook deliveries = %d, want 0 (freeipa-dns's dns.* effects must not match an identity-only subscription)", got)
	}
}

// --- W7, W9, W10: failure classification and INV-2 (webhook status never
// changes the real operation outcome) ---------------------------------------

// TestOutboundWorkflow_W7 locks: an apply failure emits a failure event
// (design spec §46.6 W7).
func TestOutboundWorkflow_W7(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultFailure), 0)
	catalog := loadOutboundWorkflowCatalog(t)
	runner := newRunnerWithExitCode(t, 2)

	err := runCatalogPlaybookDeployEntry(context.Background(), runner, &bytes.Buffer{}, env.inv, "apply", catalog,
		deployPlaybookEntry("leaf", "leaf-apply.yml"), nil, deployInventorySnapshot{}, false, nil)
	if err == nil {
		t.Fatal("runCatalogPlaybookDeployEntry() error = nil, want an apply failure")
	}
	if got := env.capture.count(); got != 1 {
		t.Fatalf("webhook deliveries = %d, want exactly 1 failure event", got)
	}
	var body map[string]any
	if err := json.Unmarshal(env.capture.last(), &body); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	op, _ := body["operation"].(map[string]any)
	if op["result"] != "failure" {
		t.Fatalf("envelope operation.result = %v, want failure", op["result"])
	}
}

// TestOutboundWorkflow_W9 locks INV-2: a 503 from the webhook endpoint
// after a successful deploy must never flip the deploy's own result
// (design spec §46.6 W9) — the deploy's returned error reflects only the
// real ansible outcome.
func TestOutboundWorkflow_W9(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultSuccess), http.StatusServiceUnavailable)
	catalog := loadOutboundWorkflowCatalog(t)
	runner := newRunnerWithExitCode(t, 0)

	err := runCatalogPlaybookDeployEntry(context.Background(), runner, &bytes.Buffer{}, env.inv, "apply", catalog,
		deployPlaybookEntry("leaf", "leaf-apply.yml"), nil, deployInventorySnapshot{}, false, nil)
	if err != nil {
		t.Fatalf("runCatalogPlaybookDeployEntry() error = %v, want nil — a 503 from the webhook must not affect deploy's own result (INV-2)", err)
	}
}

// TestOutboundWorkflow_W10 locks INV-2 from the other direction: a 204
// (accepted) from the webhook endpoint after a FAILED deploy must never
// paper over the real failure (design spec §46.6 W10).
func TestOutboundWorkflow_W10(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultFailure), http.StatusNoContent)
	catalog := loadOutboundWorkflowCatalog(t)
	runner := newRunnerWithExitCode(t, 2)

	err := runCatalogPlaybookDeployEntry(context.Background(), runner, &bytes.Buffer{}, env.inv, "apply", catalog,
		deployPlaybookEntry("leaf", "leaf-apply.yml"), nil, deployInventorySnapshot{}, false, nil)
	if err == nil {
		t.Fatal("runCatalogPlaybookDeployEntry() error = nil, want the real apply failure preserved despite the webhook's 204 ack (INV-2)")
	}
}

// --- W13: invalid integrations.yaml fails closed before any mutation --------

// TestOutboundWorkflow_W13 locks INV-3: a semantically invalid
// integrations.yaml must block the whole operation before any mutation
// starts (design spec §46.6 W13) — proven here by asserting the fake
// ansible-playbook binary was never even invoked. Driven through
// runSiteDeploy specifically: webhookReadiness lives at each entrypoint's
// own top (runSiteDeploy/runCatalogPlaybookDeploy), not inside
// runCatalogPlaybookDeployEntry, which only ever runs after that gate
// already passed.
func TestOutboundWorkflow_W13(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}, "consumer": {"host-a"}}, "", 0)
	if err := os.WriteFile(filepath.Join(env.workspace, "integrations.yaml"), []byte(invalidIntegrationsYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(t.TempDir(), "ansible-playbook-args")
	runner := ansible.NewRunner()
	runner.Binary = writeArgsFixture(t, argsPath)
	runner.Timeout = 5 * time.Second

	err := runSiteDeploy(context.Background(), runner, &bytes.Buffer{}, env.inv, deployInventorySnapshot{})
	if err == nil {
		t.Fatal("runSiteDeploy() error = nil, want a hard failure for an invalid integrations.yaml")
	}
	if _, statErr := os.Stat(argsPath); !os.IsNotExist(statErr) {
		t.Fatalf("ansible-playbook was invoked (args file exists) — mutation must never start before webhookReadiness passes")
	}
	if got := env.capture.count(); got != 0 {
		t.Fatalf("webhook deliveries = %d, want 0", got)
	}
}

// --- W16-W18: dedicated frontends (gateway-scope, access reconcile,
// breakglass) each publish their own single reconcile event -----------------

// TestOutboundWorkflow_W16 locks: gateway-scope reconcile/enable-auto/
// disable-auto each emit exactly one reconcile event (design spec §46.6
// W16) — these have no delivery.Transaction at all, unlike W1-W10.
func TestOutboundWorkflow_W16(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"freeipa-client": {"host-a"}}, eventsYAMLFor(outbound.OperationReconcile, outbound.ResultSuccess), 0)

	origDir, origScope, origHosts, origInv, origGroup, origVault := gatewayScopeDirFlag, gatewayScopeFlag, gatewayScopeHostsFlag, gatewayScopeInventory, gatewayScopeTargetGroup, gatewayScopeVaultFile
	t.Cleanup(func() {
		gatewayScopeDirFlag, gatewayScopeFlag, gatewayScopeHostsFlag = origDir, origScope, origHosts
		gatewayScopeInventory, gatewayScopeTargetGroup, gatewayScopeVaultFile = origInv, origGroup, origVault
	})
	vaultFile := filepath.Join(env.workspace, "vault.yaml")
	if err := os.WriteFile(vaultFile, []byte("ipa_admin_password: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gatewayScopeDirFlag = env.workspace
	gatewayScopeFlag = "gpu"
	gatewayScopeHostsFlag = []string{"host-a"}
	gatewayScopeInventory = "inventory.yml"
	gatewayScopeTargetGroup = "host-a"
	gatewayScopeVaultFile = vaultFile

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&bytes.Buffer{})

	if err := runGatewayScope(cmd, false); err != nil {
		t.Fatalf("runGatewayScope(reconcile): %v", err)
	}
	if got := env.capture.count(); got != 1 {
		t.Fatalf("after gateway-scope reconcile: webhook deliveries = %d, want 1", got)
	}
	if err := runGatewayScopeAutomember(cmd, true); err != nil {
		t.Fatalf("runGatewayScopeAutomember(enable): %v", err)
	}
	if got := env.capture.count(); got != 2 {
		t.Fatalf("after enable-auto: webhook deliveries = %d, want 2", got)
	}
	if err := runGatewayScopeAutomember(cmd, false); err != nil {
		t.Fatalf("runGatewayScopeAutomember(disable): %v", err)
	}
	if got := env.capture.count(); got != 3 {
		t.Fatalf("after disable-auto: webhook deliveries = %d, want 3", got)
	}
}

// TestOutboundWorkflow_W17 locks: `pilot access reconcile` emits one
// reconcile event whose effects are the fixed §1 access-only subset,
// never the full freeipa-identity effect set (design spec §46.6 W17).
func TestOutboundWorkflow_W17(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"host-a": {"host-a"}},
		reconcileEventsYAMLEffectsAny(outbound.ResultSuccess, "access.hbac"), 0)
	rosterPath := writeAccessCLIFixture(t, accessCLIFixtureRoster)

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "reconcile", rosterPath, "--once", "--inventory", env.inv})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("pilot access reconcile: %v, output=%s", err, out.String())
	}
	if got := env.capture.count(); got != 1 {
		t.Fatalf("webhook deliveries = %d, want exactly 1", got)
	}
	var body map[string]any
	if err := json.Unmarshal(env.capture.last(), &body); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	state, _ := body["state"].(map[string]any)
	confirmed, _ := state["confirmed_effects"].([]any)
	got := make([]string, len(confirmed))
	for i, e := range confirmed {
		got[i] = fmt.Sprint(e)
	}
	want := []string{"access.grants", "access.hbac", "access.sudo"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("confirmed_effects = %v, want exactly the access-only subset %v (never the full freeipa-identity effect set)", got, want)
	}
}

// TestOutboundWorkflow_W18 locks: breakglass activate/deactivate each
// emit one bounded reconcile event (design spec §46.6 W18) — "bounded"
// meaning empty component sets plus an operation.subject naming the
// grant, per design spec §1's table row for breakglass.
func TestOutboundWorkflow_W18(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"host-a": {"host-a"}},
		reconcileEventsYAMLEffectsAny(outbound.ResultSuccess, "access.hbac"), 0)
	rosterPath := writeAccessCLIFixture(t, accessBreakglassCLIFixtureRoster)

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "breakglass", "activate", rosterPath, "infra-emergency",
		"--duration", "30m", "--reason", "test", "--ticket", "T-1", "--inventory", env.inv})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("pilot access breakglass activate: %v, output=%s", err, out.String())
	}
	rootCmd.SetArgs(nil)
	if got := env.capture.count(); got != 1 {
		t.Fatalf("after activate: webhook deliveries = %d, want 1", got)
	}
	var activateBody map[string]any
	if err := json.Unmarshal(env.capture.last(), &activateBody); err != nil {
		t.Fatalf("unmarshal activate envelope: %v", err)
	}
	if op, _ := activateBody["operation"].(map[string]any); len(op["requested_components"].([]any)) != 0 {
		t.Fatalf("activate operation.requested_components = %v, want empty (bounded, per §1)", op["requested_components"])
	}

	rootCmd.SetArgs([]string{"access", "breakglass", "deactivate", rosterPath, "infra-emergency", "--inventory", env.inv})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("pilot access breakglass deactivate: %v, output=%s", err, out.String())
	}
	if got := env.capture.count(); got != 2 {
		t.Fatalf("after deactivate: webhook deliveries = %d, want 2", got)
	}
}

// --- W15: cancellation before vs. after workflow-ID assignment --------------

// TestOutboundWorkflow_W15 locks design spec §46.6 W15's two halves.
//
// "pre-workflow cancellation emits no event" is proven structurally: every
// wired entrypoint (runCatalogPlaybookDeployEntry/runSiteDeploy/
// executeCatalogReconcileBatch) generates workflowID and reaches
// publishTerminalWorkflow only near its own end, after every input-gathering
// prompt — any prompt failure/abort before that line (here: an infra-role
// select with no scripted automation answer, standing in for a real Ctrl-C,
// which resolves through the identical "return err before workflowID" path)
// must return before ever contacting the webhook.
//
// "post-workflow-ID cancellation follows subscription" is fully genuine:
// rejecting the real apply-confirmation prompt produces a real
// delivery.OutcomeCancelled, and the resulting cancelled-result event is
// asserted end-to-end against a subscription for it.
func TestOutboundWorkflow_W15(t *testing.T) {
	t.Run("pre-workflow", func(t *testing.T) {
		env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultCancelled), 0)
		catalog := loadOutboundWorkflowCatalog(t)
		runner := newRunnerWithExitCode(t, 0)

		oldPrompt := activePromptAutomation
		activePromptAutomation = &promptAutomation{}
		t.Cleanup(func() { activePromptAutomation = oldPrompt })

		entry := deployPlaybookEntry("leaf", "leaf-apply.yml")
		entry.InfraRoles = []string{"role-a", "role-b"}
		err := runCatalogPlaybookDeployEntry(context.Background(), runner, &bytes.Buffer{}, env.inv, "apply", catalog,
			entry, nil, deployInventorySnapshot{}, false, nil)
		if err == nil {
			t.Fatal("runCatalogPlaybookDeployEntry() error = nil, want the unanswered infra-role prompt to abort before the workflow starts")
		}
		if got := env.capture.count(); got != 0 {
			t.Fatalf("webhook deliveries = %d, want 0 for a pre-workflow abort", got)
		}
	})

	t.Run("post-workflow-id", func(t *testing.T) {
		env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultCancelled), 0)
		catalog := loadOutboundWorkflowCatalog(t)
		runner := newRunnerWithExitCode(t, 0)

		// useDefaults alone (no forceApply) reproduces a genuine,
		// unscripted cancellation: every prompt's own hardcoded default
		// applies, which for this wizard means "do a --check --diff
		// preview first" (defaults to yes) followed by "apply the real
		// change now that preview looked fine?" — which defaults to NO —
		// i.e. exactly the same confirm an operator declining that
		// question at the terminal would produce, without needing to
		// script every intermediate prompt's answer by hand.
		oldPrompt := activePromptAutomation
		activePromptAutomation = &promptAutomation{useDefaults: true}
		t.Cleanup(func() { activePromptAutomation = oldPrompt })

		var out bytes.Buffer
		err := runCatalogPlaybookDeployEntry(context.Background(), runner, &out, env.inv, "apply", catalog,
			deployPlaybookEntry("leaf", "leaf-apply.yml"), nil, deployInventorySnapshot{}, false, nil)
		if err == nil {
			t.Fatal("runCatalogPlaybookDeployEntry() error = nil, want a cancellation when the apply confirmation is rejected")
		}
		if got := env.capture.count(); got != 1 {
			t.Fatalf("webhook deliveries = %d, want exactly 1 cancelled-result event; err=%v output:\n%s", got, err, out.String())
		}
		var body map[string]any
		if err := json.Unmarshal(env.capture.last(), &body); err != nil {
			t.Fatalf("unmarshal envelope: %v", err)
		}
		op, _ := body["operation"].(map[string]any)
		if op["result"] != "cancelled" {
			t.Fatalf("envelope operation.result = %v, want cancelled", op["result"])
		}
	})
}

// --- W11, W12: --actions/--force route through the same instrumented
// entrypoints as the interactive wizard -------------------------------------

// deployFlagFixture saves/restores every package-level deploy flag var
// W11/W12 touch.
func deployFlagFixture(t *testing.T) {
	t.Helper()
	origInv, origDir, origAction := deployInventoryFlag, deployDirFlag, deployActionFlag
	t.Cleanup(func() {
		deployInventoryFlag, deployDirFlag, deployActionFlag = origInv, origDir, origAction
	})
}

// TestOutboundWorkflow_W11 locks: `pilot deploy --actions` follows
// identical webhook-publication semantics to the interactive wizard
// (design spec §46.6 W11) — proven by driving runAutomatedDeploymentStep
// itself (the exact function runStandalonePromptWorkflow/--actions
// calls), with every prompt answered via the stable prompt_id contract
// (prompt_schema.go) rather than useDefaults, since --actions never sets
// useDefaults in production either.
func TestOutboundWorkflow_W11(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}, "consumer": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultSuccess), 0)

	deployFlagFixture(t)
	deployDirFlag = env.workspace
	deployActionFlag = "apply"

	no := false
	yes := true
	step := editAction{
		Action:    "deploy",
		Inventory: "inventory.yml",
		Answers: []promptAnswer{
			{PromptID: "inventory", Text: "inventory.yml"},
			{PromptID: "topology_preview", Confirm: &no},
			{PromptID: "preflight", Select: "skip"},
			{PromptID: "scope", Select: "site"},
			{PromptID: "stage", Select: "sandbox"},
			{PromptID: "limit", Text: ""},
			{PromptID: "tags", Text: ""},
			{PromptID: "extra_vars", Text: ""},
			{PromptID: "vault.need_file", Select: "none"},
			{PromptID: "become_password", Confirm: &no},
			{PromptID: "execution.preview", Confirm: &no},
			{PromptID: "execution.confirm_apply", Confirm: &yes},
		},
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runAutomatedDeploymentStep(cmd, step, false, &out, nil); err != nil {
		t.Fatalf("runAutomatedDeploymentStep: %v, output=%s", err, out.String())
	}
	if got := env.capture.count(); got != 1 {
		t.Fatalf("webhook deliveries = %d, want exactly 1 for an --actions-driven site deploy", got)
	}
}

// TestOutboundWorkflow_W12 locks: `pilot deploy --force` follows
// identical webhook-publication semantics to the interactive wizard
// (design spec §46.6 W12) — proven by reproducing --force's own real
// code (deploy.go: `activePromptAutomation = &promptAutomation{
// useDefaults: true, forceApply: true}` before calling
// runDeployInteractive) directly, rather than going through cobra's flag
// parsing.
func TestOutboundWorkflow_W12(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}, "consumer": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultSuccess), 0)

	deployFlagFixture(t)
	deployDirFlag = env.workspace
	deployInventoryFlag = "inventory.yml"
	deployActionFlag = "apply"

	oldPrompt := activePromptAutomation
	activePromptAutomation = &promptAutomation{useDefaults: true, forceApply: true}
	t.Cleanup(func() { activePromptAutomation = oldPrompt })

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := runDeployInteractive(cmd, nil); err != nil {
		t.Fatalf("runDeployInteractive (--force path): %v, output=%s", err, out.String())
	}
	if got := env.capture.count(); got != 1 {
		t.Fatalf("webhook deliveries = %d, want exactly 1 for a --force-driven site deploy", got)
	}
}

// --- W14: site.yml deploy's resolved component sets on the wire -------------

// TestOutboundWorkflow_W14 locks: a site.yml deploy's single terminal
// event carries the ACTUAL resolved component set (both leaf and
// consumer), not an empty or single-component set (design spec §46.6
// W14) — runSiteDeploy's own doc comment states this is exactly what
// componentIDsFromResults(execResult.Results) resolves to.
func TestOutboundWorkflow_W14(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}, "consumer": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultSuccess), 0)
	runner := newRunnerWithExitCode(t, 0)

	if err := runSiteDeploy(context.Background(), runner, &bytes.Buffer{}, env.inv, deployInventorySnapshot{}); err != nil {
		t.Fatalf("runSiteDeploy: %v", err)
	}
	if got := env.capture.count(); got != 1 {
		t.Fatalf("webhook deliveries = %d, want exactly 1", got)
	}
	var body map[string]any
	if err := json.Unmarshal(env.capture.last(), &body); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	op, _ := body["operation"].(map[string]any)
	requested, _ := op["requested_components"].([]any)
	got := make([]string, len(requested))
	for i, c := range requested {
		got[i] = fmt.Sprint(c)
	}
	want := []string{"consumer", "leaf"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("operation.requested_components = %v, want %v (the full site.yml-resolved set)", got, want)
	}
}

// --- W8: verify failure emits a failure event --------------------------------

// TestOutboundWorkflow_W8 locks: a verify failure emits a failure event
// (design spec §46.6 W8). NARROWED coverage: reproducing a genuine
// verify-step failure end-to-end would require a real spec/SSH-driven
// evidence check (internal/spec), which this fixture harness (fake
// ansible binaries, no real target host) cannot exercise honestly. This
// test instead drives the real, unmodified aggregateDeploymentResult +
// publishTerminalWorkflow production code directly with a
// ComponentDeliveryResult shaped exactly like a real verify failure
// (Outcome=OutcomeFailed, FailedStep="verify") — the same shape
// TestOutboundWorkflow_FailureInfo (outbound_workflow_test.go) already
// locks at the pure-function level — confirming the full HTTP delivery
// or the resulting failure event's class is "verify_failed" end-to-end.
func TestOutboundWorkflow_W8(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultFailure), 0)
	catalog := loadOutboundWorkflowCatalog(t)

	results := []ComponentDeliveryResult{{ComponentIDs: []string{"leaf"}, RunID: "run-leaf", Outcome: delivery.OutcomeFailed, FailedStep: "verify"}}
	agg := aggregateDeploymentResult(results)
	publishTerminalWorkflow(context.Background(), &bytes.Buffer{}, PublishTerminalWorkflowInput{
		WorkspaceDir: env.workspace, Inventory: env.inv,
		Operation: outbound.OperationDeploy, WorkflowID: newWorkflowID(),
		RequestedComponents: []string{"leaf"}, ExecutedComponents: []string{"leaf"},
		CompletedComponents: agg.CompletedComponents, FailedComponent: agg.FailedComponent,
		Effects: outboundWorkflowEffects(catalog, []string{"leaf"}), ConfirmedEffects: agg.ConfirmedEffects,
		Result: agg.Result, ApplicationConsistency: agg.ApplicationConsistency,
		DeliveryRuns: agg.DeliveryRuns, Failure: agg.Failure,
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if got := env.capture.count(); got != 1 {
		t.Fatalf("webhook deliveries = %d, want exactly 1 failure event", got)
	}
	var body map[string]any
	if err := json.Unmarshal(env.capture.last(), &body); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	failure, _ := body["failure"].(map[string]any)
	if failure["class"] != "verify_failed" {
		t.Fatalf("failure.class = %v, want verify_failed", failure["class"])
	}
}

// --- W19: ConfirmedEffects never overclaims an incomplete component ---------

// TestOutboundWorkflow_W19 locks design spec §46.6 W19's two halves: (a)
// a success snapshot's state.basis is "pilot_declared" — already locked
// at the unit level by internal/outbound/event_test.go's
// TestBuildEnvelope-style assertion on env.State.Basis — and (b) a
// partially-completed multi-component workflow's confirmed_effects only
// ever includes the components that actually completed, never one that
// was requested but failed, which this test proves end-to-end over real
// HTTP.
func TestOutboundWorkflow_W19(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultFailure), 0)
	catalog := loadOutboundWorkflowCatalog(t)

	// leaf completed (identity.hostgroups); freeipa-dns was requested but
	// failed (dns.zones/dns.records) — confirmed_effects must contain
	// only leaf's effect, never freeipa-dns's.
	results := []ComponentDeliveryResult{
		{ComponentIDs: []string{"leaf"}, RunID: "run-leaf", Outcome: delivery.OutcomeSuccess},
		{ComponentIDs: []string{"freeipa-dns"}, RunID: "run-freeipa-dns", Outcome: delivery.OutcomeFailed, FailedStep: "apply"},
	}
	agg := aggregateDeploymentResult(results)
	publishTerminalWorkflow(context.Background(), &bytes.Buffer{}, PublishTerminalWorkflowInput{
		WorkspaceDir: env.workspace, Inventory: env.inv,
		Operation: outbound.OperationDeploy, WorkflowID: newWorkflowID(),
		RequestedComponents: []string{"leaf", "freeipa-dns"}, ExecutedComponents: []string{"leaf", "freeipa-dns"},
		CompletedComponents: agg.CompletedComponents, FailedComponent: agg.FailedComponent,
		Effects: outboundWorkflowEffects(catalog, []string{"leaf", "freeipa-dns"}), ConfirmedEffects: agg.ConfirmedEffects,
		Result: agg.Result, ApplicationConsistency: agg.ApplicationConsistency,
		DeliveryRuns: agg.DeliveryRuns, Failure: agg.Failure,
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if got := env.capture.count(); got != 1 {
		t.Fatalf("webhook deliveries = %d, want exactly 1", got)
	}
	var body map[string]any
	if err := json.Unmarshal(env.capture.last(), &body); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	state, _ := body["state"].(map[string]any)
	if state["basis"] != "pilot_declared" {
		t.Fatalf("state.basis = %v, want pilot_declared", state["basis"])
	}
	confirmed, _ := state["confirmed_effects"].([]any)
	got := make([]string, len(confirmed))
	for i, e := range confirmed {
		got[i] = fmt.Sprint(e)
	}
	if strings.Join(got, ",") != "identity.hostgroups" {
		t.Fatalf("confirmed_effects = %v, want only [identity.hostgroups] (never freeipa-dns's effects, which never completed)", got)
	}
}

// --- W20: a local enqueue failure after mutation never surfaces as an
// operation-level error -------------------------------------------------

// TestOutboundWorkflow_W20 locks design spec §46.6 W20. publishTerminalWorkflow
// itself has no error return (`func publishTerminalWorkflow(ctx, out,
// in)`), so by construction nothing it does internally — including a
// local enqueue failure — can ever change a caller's already-captured
// deployErr; every wired call site (runSiteDeploy,
// runCatalogPlaybookDeployEntry, executeCatalogReconcileBatch) assigns
// deployErr from executeRecordedDeploymentResult BEFORE calling
// publishTerminalWorkflow and returns that same value afterward. This
// test proves the enqueue-failure half directly: publishTerminalWorkflow
// with an unwritable data dir must not panic, must print a "operation
// result unaffected" warning, and must never reach HTTP (no request
// reaches the capture server, since delivery never even got to enqueue).
func TestOutboundWorkflow_W20(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"leaf": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultSuccess), 0)

	// A file where publishTerminalWorkflow expects to os.MkdirAll a
	// directory: MkdirAll fails with ENOTDIR, standing in for any local
	// enqueue failure (disk full, permission denied, corrupt history.db).
	blocked := filepath.Join(t.TempDir(), "blocked-data-dir")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldDataDir := dataDir
	dataDir = blocked
	t.Cleanup(func() { dataDir = oldDataDir })

	var out bytes.Buffer
	publishTerminalWorkflow(context.Background(), &out, PublishTerminalWorkflowInput{
		WorkspaceDir: env.workspace, Inventory: env.inv,
		Operation: outbound.OperationDeploy, WorkflowID: newWorkflowID(),
		RequestedComponents: []string{"leaf"}, ExecutedComponents: []string{"leaf"},
		CompletedComponents: []string{"leaf"}, Effects: []string{"identity.hostgroups"}, ConfirmedEffects: []string{"identity.hostgroups"},
		Result: outbound.ResultSuccess, ApplicationConsistency: "confirmed_for_effects",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if !strings.Contains(out.String(), "operation result unaffected") {
		t.Fatalf("expected a local-enqueue-failure warning naming the operation as unaffected, got: %s", out.String())
	}
	if got := env.capture.count(); got != 0 {
		t.Fatalf("webhook deliveries = %d, want 0 (enqueue never reached HTTP dispatch)", got)
	}
}
