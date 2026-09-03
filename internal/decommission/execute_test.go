package decommission

import (
	"context"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/decommission/providers"
)

// fakeStepExecutor is a trivial in-package StepExecutor: converged is
// fixed at construction, execute is recorded.
type fakeStepExecutor struct {
	converged bool
	executed  *int
	failWith  error
}

func (e *fakeStepExecutor) Inspect(ctx context.Context) (bool, error) { return e.converged, nil }
func (e *fakeStepExecutor) Execute(ctx context.Context) error {
	if e.executed != nil {
		*e.executed++
	}
	return e.failWith
}

// fakeProvider is an in-package fake providers.Provider + StepRunner
// whose Plan/Verify/ExecutorForStep are all test-supplied closures — used
// to exercise execute.go's orchestration (executeComponents/
// collectVerifications) without any real ansible/FreeIPA/Wazuh provider.
type fakeProvider struct {
	id          string
	steps       []providers.Step
	verifyCalls []providers.VerifyInput
	verifyFn    func(in providers.VerifyInput) ([]providers.Verification, error)
}

func (f *fakeProvider) ID() string { return f.id }
func (f *fakeProvider) Inspect(ctx context.Context, in providers.InspectInput) (providers.Inspection, error) {
	return providers.Inspection{}, nil
}
func (f *fakeProvider) Plan(ctx context.Context, in providers.PlanInput) ([]providers.Step, error) {
	return f.steps, nil
}
func (f *fakeProvider) Verify(ctx context.Context, in providers.VerifyInput) ([]providers.Verification, error) {
	f.verifyCalls = append(f.verifyCalls, in)
	if f.verifyFn != nil {
		return f.verifyFn(in)
	}
	return []providers.Verification{{Provider: f.id, Kind: "test", Identity: in.HostName, Status: "pass"}}, nil
}
func (f *fakeProvider) ExecutorForStep(step providers.Step) (providers.StepExecutor, error) {
	return &fakeStepExecutor{converged: false}, nil
}

func fakeComponentContract(id, role string) contract.Contract {
	return contract.Contract{ID: id, Role: role}
}

// TestExecute_RunsStepsAndCollectsVerification proves the common,
// single-identity case (matching FreeIPAClientProvider/WazuhAgentProvider
// shape): every step targets the retiring host itself, so Verify is
// called exactly once with that identity.
func TestExecute_RunsStepsAndCollectsVerification(t *testing.T) {
	hostName := "single-identity-host"
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML(hostName, "10.0.0.5", []string{"fake-role"}, ""))
	catalog := newCatalog(t, fakeComponentContract("fake-component", "fake-role"))

	fp := &fakeProvider{
		id: "fake-component",
		steps: []providers.Step{
			{Provider: "fake-component", Phase: "local_cleanup", Action: "noop", TargetIdentity: hostName},
		},
	}
	provs := map[string]providers.Provider{"fake-component": fp}

	planIn := PlanInput{WorkspaceDir: dir, HostName: hostName, Catalog: catalog, Providers: provs, Now: fixedNow}
	plan, err := PlanHost(context.Background(), planIn)
	if err != nil {
		t.Fatalf("PlanHost: %v", err)
	}
	if plan.Blocked() {
		t.Fatalf("expected an executable plan, got blockers: %+v", plan.Blockers)
	}

	if err := executeComponents(context.Background(), plan, provs); err != nil {
		t.Fatalf("executeComponents: %v", err)
	}
	verifs, err := collectVerifications(context.Background(), plan, provs)
	if err != nil {
		t.Fatalf("collectVerifications: %v", err)
	}
	if len(verifs) != 1 {
		t.Fatalf("expected exactly 1 verification, got %d: %+v", len(verifs), verifs)
	}
	if len(fp.verifyCalls) != 1 || fp.verifyCalls[0].HostName != hostName {
		t.Errorf("expected exactly 1 Verify call for %q, got %+v", hostName, fp.verifyCalls)
	}
}

// TestExecute_MultiIdentityProviderVerifiesEachDistinctIdentity proves
// the internal-endpoint shape (Phase 4): a component whose planned steps
// target DIFFERENT identities (referenced endpoint fqdns, never the
// retiring host's own name) gets Verify called once per distinct
// identity, not once against the retiring host.
func TestExecute_MultiIdentityProviderVerifiesEachDistinctIdentity(t *testing.T) {
	hostName := "multi-identity-host"
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML(hostName, "10.0.0.6", []string{"fake-role"}, ""))
	catalog := newCatalog(t, fakeComponentContract("fake-component", "fake-role"))

	fp := &fakeProvider{
		id: "fake-component",
		steps: []providers.Step{
			{Provider: "fake-component", Phase: "central_cleanup", Action: "step-a", TargetIdentity: "endpoint-a.example.com"},
			{Provider: "fake-component", Phase: "central_cleanup", Action: "step-b", TargetIdentity: "endpoint-a.example.com"},
			{Provider: "fake-component", Phase: "central_cleanup", Action: "step-c", TargetIdentity: "endpoint-b.example.com"},
		},
	}
	provs := map[string]providers.Provider{"fake-component": fp}

	plan, err := PlanHost(context.Background(), PlanInput{WorkspaceDir: dir, HostName: hostName, Catalog: catalog, Providers: provs, Now: fixedNow})
	if err != nil {
		t.Fatalf("PlanHost: %v", err)
	}
	if plan.Blocked() {
		t.Fatalf("expected an executable plan, got blockers: %+v", plan.Blockers)
	}

	if err := executeComponents(context.Background(), plan, provs); err != nil {
		t.Fatalf("executeComponents: %v", err)
	}
	verifs, err := collectVerifications(context.Background(), plan, provs)
	if err != nil {
		t.Fatalf("collectVerifications: %v", err)
	}
	if len(fp.verifyCalls) != 2 {
		t.Fatalf("expected exactly 2 Verify calls (one per distinct endpoint identity), got %d: %+v", len(fp.verifyCalls), fp.verifyCalls)
	}
	seen := map[string]bool{}
	for _, c := range fp.verifyCalls {
		seen[c.HostName] = true
		if c.HostName == hostName {
			t.Errorf("Verify must never be called with the retiring host's own identity for a multi-identity provider, got %q", c.HostName)
		}
	}
	if !seen["endpoint-a.example.com"] || !seen["endpoint-b.example.com"] {
		t.Errorf("expected Verify calls for both endpoint-a and endpoint-b, got %+v", fp.verifyCalls)
	}
	if len(verifs) != 2 {
		t.Errorf("expected 2 verification results, got %d: %+v", len(verifs), verifs)
	}
}

// TestExecute_MissingProviderFailsClosed proves a component with planned
// Steps but no registered provider (a caller passing a different
// Providers map than `plan` used) fails closed rather than silently
// skipping execution.
func TestExecute_MissingProviderFailsClosed(t *testing.T) {
	plan := &Plan{
		Components: []ComponentPlan{
			{ComponentID: "fake-component", ProviderRegistered: true, Steps: []providers.Step{
				{Provider: "fake-component", Action: "noop", TargetIdentity: "x"},
			}},
		},
		TeardownOrder: []string{"fake-component"},
	}
	err := executeComponents(context.Background(), plan, map[string]providers.Provider{})
	if err == nil {
		t.Fatalf("expected an error when no provider is registered for a component with planned steps")
	}
	if ClassOf(err) != ErrCleanupFailedTerminal {
		t.Errorf("expected ErrCleanupFailedTerminal, got %v (%v)", ClassOf(err), err)
	}
}
