package decommission

import (
	"context"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/decommission/providers"
)

// fakePlannerProvider is a minimal in-package providers.Provider fake —
// deliberately NOT the real FreeIPA client provider (that has its own
// dedicated fixture tests in providers/freeipa_client_test.go) — used only
// to prove planner.go's registry wiring itself: a component with a
// REGISTERED provider is no longer unconditionally
// external_state_unsupported (spec.md §37 Phase 3), regardless of which
// concrete provider implementation is registered.
type fakePlannerProvider struct {
	id       string
	planErr  error
	planFunc func(providers.PlanInput) ([]providers.Step, error)
}

func (f *fakePlannerProvider) ID() string { return f.id }
func (f *fakePlannerProvider) Inspect(context.Context, providers.InspectInput) (providers.Inspection, error) {
	return providers.Inspection{}, nil
}
func (f *fakePlannerProvider) Plan(_ context.Context, in providers.PlanInput) ([]providers.Step, error) {
	if f.planFunc != nil {
		return f.planFunc(in)
	}
	if f.planErr != nil {
		return nil, f.planErr
	}
	return []providers.Step{{Provider: f.id, Phase: "local_cleanup", Action: "fake_action", TargetIdentity: in.HostName}}, nil
}
func (f *fakePlannerProvider) Verify(context.Context, providers.VerifyInput) ([]providers.Verification, error) {
	return nil, nil
}

// TestPlanner_RegisteredProviderStopsUnconditionalBlock proves the wiring
// spec.md §37 Phase 3 asks for: PlanInput.Providers is consulted by
// planComponent, and a component whose ID has a registered provider is no
// longer unconditionally external_state_unsupported — it may still block,
// but only for a reason the PROVIDER itself reports (or the unrelated
// retention gate), never the generic "no provider registered" detail.
func TestPlanner_RegisteredProviderStopsUnconditionalBlock(t *testing.T) {
	catalog := newCatalog(t, contract.Contract{ID: "freeipa-client", Role: "freeipa-client"})
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("web1", "10.0.0.5", []string{"freeipa-client"}, ""))

	provider := &fakePlannerProvider{id: "freeipa-client"}
	plan, err := PlanHost(context.Background(), PlanInput{
		WorkspaceDir: dir, HostName: "web1", Catalog: catalog, Now: fixedNow,
		Providers: map[string]providers.Provider{"freeipa-client": provider},
	})
	if err != nil {
		t.Fatalf("PlanHost() error = %v", err)
	}
	if plan.Blocked() {
		t.Fatalf("plan = %+v, want NOT blocked once a provider is registered and it plans cleanly", plan)
	}
	if len(plan.Components) != 1 {
		t.Fatalf("Components = %+v, want exactly 1", plan.Components)
	}
	cp := plan.Components[0]
	if !cp.ProviderRegistered {
		t.Fatal("expected ProviderRegistered=true")
	}
	if len(cp.Steps) != 1 || cp.Steps[0].Action != "fake_action" {
		t.Fatalf("Steps = %+v, want the provider's planned step", cp.Steps)
	}
	for _, b := range cp.Blockers {
		if b.Code == ErrExternalStateUnsupported {
			t.Fatalf("still has an external_state_unsupported blocker with a provider registered: %+v", cp.Blockers)
		}
	}
}

// TestPlanner_RegisteredProviderCanStillBlockForItsOwnReason proves a
// registered provider is not a blanket bypass: if Plan itself errors
// (e.g. an unknown service principal, HD12), the component still blocks
// — just with a provider-specific reason, not the generic "unsupported"
// one.
func TestPlanner_RegisteredProviderCanStillBlockForItsOwnReason(t *testing.T) {
	catalog := newCatalog(t, contract.Contract{ID: "freeipa-client", Role: "freeipa-client"})
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("web1", "10.0.0.5", []string{"freeipa-client"}, ""))

	provider := &fakePlannerProvider{id: "freeipa-client", planErr: providers.ErrUnknownServicePrincipal}
	plan, err := PlanHost(context.Background(), PlanInput{
		WorkspaceDir: dir, HostName: "web1", Catalog: catalog, Now: fixedNow,
		Providers: map[string]providers.Provider{"freeipa-client": provider},
	})
	if err != nil {
		t.Fatalf("PlanHost() error = %v", err)
	}
	if !plan.Blocked() {
		t.Fatal("expected the plan to be blocked by the provider's own error")
	}
	cp := plan.Components[0]
	if len(cp.Blockers) != 1 || cp.Blockers[0].Code != ErrOwnershipUnknown {
		t.Fatalf("Blockers = %+v, want exactly 1 ownership_unknown blocker", cp.Blockers)
	}
}

// TestPlanner_UnregisteredComponentStillBlocksUnconditionally is a
// regression guard for the existing Phase 1/2 behavior: a role whose
// component has NO registered provider (Providers nil/missing entry)
// keeps the exact prior unconditional external_state_unsupported block —
// this is what TestPlanner_UnsupportedExternalStateBlocks already locks,
// re-asserted here specifically alongside the new registry field to make
// the "opt-in, not a silent behavior change" contract explicit in one
// place.
func TestPlanner_UnregisteredComponentStillBlocksUnconditionally(t *testing.T) {
	catalog := newCatalog(t, contract.Contract{ID: "wazuh-fim", Role: "wazuh-fim"})
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("h1", "10.0.0.1", []string{"wazuh-fim"}, ""))

	plan, err := PlanHost(context.Background(), PlanInput{
		WorkspaceDir: dir, HostName: "h1", Catalog: catalog, Now: fixedNow,
		Providers: map[string]providers.Provider{"freeipa-client": &fakePlannerProvider{id: "freeipa-client"}},
	})
	if err != nil {
		t.Fatalf("PlanHost() error = %v", err)
	}
	if !plan.Blocked() {
		t.Fatal("expected the plan to remain blocked — no provider is registered for wazuh-fim")
	}
	cp := plan.Components[0]
	if cp.ProviderRegistered {
		t.Fatal("ProviderRegistered should be false — no provider is registered for this component ID")
	}
	found := false
	for _, b := range cp.Blockers {
		if b.Code == ErrExternalStateUnsupported {
			found = true
		}
	}
	if !found {
		t.Fatalf("Blockers = %+v, want external_state_unsupported", cp.Blockers)
	}
}
