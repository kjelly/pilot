package decommission

import (
	"context"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/decommission/providers"
)

// noopRunner satisfies the provider's ansible seam; planning never runs a
// playbook (Plan performs no live query).
type noopRunner struct{ calls int }

func (r *noopRunner) Run(context.Context, ...string) (*ansible.Result, error) {
	r.calls++
	return &ansible.Result{}, nil
}

func loginProbeProviders(probes ...string) (map[string]providers.Provider, *noopRunner) {
	r := &noopRunner{}
	p := providers.NewLoginProbeTargetsProvider(providers.LoginProbeTargetsProviderConfig{
		Executor:      r,
		QueryPlaybook: "playbooks/decommission/login-probe-target-query.yml",
		ApplyPlaybook: "playbooks/apply/login-probe-apply.yml",
		ProbeHosts:    probes,
	})
	return map[string]providers.Provider{
		"freeipa-client":                      &fakePlannerProvider{id: "freeipa-client"},
		providers.LoginProbeTargetsProviderID: p,
	}, r
}

func loginProbeComponent(plan *Plan) *ComponentPlan {
	for i := range plan.Components {
		if plan.Components[i].ComponentID == providers.LoginProbeTargetsProviderID {
			return &plan.Components[i]
		}
	}
	return nil
}

// A FreeIPA client retiring while a login-probe host exists gets a central
// step that re-renders the probe hosts without it (spec.md §19), the plan
// stays executable, and planning itself runs no playbook.
func TestPlanner_LoginProbeTargetsAddedForAProbeTarget(t *testing.T) {
	catalog := newCatalog(t, contract.Contract{ID: "freeipa-client", Role: "freeipa-client"})
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("web1", "10.0.0.5", []string{"freeipa-client"}, ""))
	provs, runner := loginProbeProviders("mon1")

	plan, err := PlanHost(context.Background(), PlanInput{WorkspaceDir: dir, HostName: "web1", Catalog: catalog, Now: fixedNow, Providers: provs})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Blocked() {
		t.Fatalf("plan blocked: %+v", plan.Blockers)
	}
	cp := loginProbeComponent(plan)
	if cp == nil {
		t.Fatalf("no %s component in %+v", providers.LoginProbeTargetsProviderID, plan.Components)
	}
	if len(cp.Steps) != 1 || cp.Steps[0].Phase != "central_cleanup" || cp.Steps[0].Action != providers.ActionLoginProbeTargetRemove || cp.Steps[0].TargetIdentity != "web1" {
		t.Fatalf("steps = %+v", cp.Steps)
	}
	if cp.RequiresReachableHost {
		t.Error("the step runs on the probe hosts; it must not require the retiring host to be reachable")
	}
	found := false
	for _, id := range plan.TeardownOrder {
		if id == providers.LoginProbeTargetsProviderID {
			found = true
		}
	}
	if !found {
		t.Errorf("teardown order %v must include the component, or apply never executes it", plan.TeardownOrder)
	}
	if runner.calls != 0 {
		t.Errorf("planning ran %d playbooks; Plan must stay read-only and offline", runner.calls)
	}
}

func TestPlanner_LoginProbeTargetsNotAddedWithoutProbeHosts(t *testing.T) {
	catalog := newCatalog(t, contract.Contract{ID: "freeipa-client", Role: "freeipa-client"})
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("web1", "10.0.0.5", []string{"freeipa-client"}, ""))
	provs, _ := loginProbeProviders()
	plan, err := PlanHost(context.Background(), PlanInput{WorkspaceDir: dir, HostName: "web1", Catalog: catalog, Now: fixedNow, Providers: provs})
	if err != nil {
		t.Fatal(err)
	}
	if cp := loginProbeComponent(plan); cp != nil {
		t.Fatalf("no login-probe hosts: component %+v must not be planned", cp)
	}
}

// A retiring login-probe host is handled by the role loop (which fails
// closed for it); the reference-driven component must not mask that.
func TestPlanner_LoginProbeTargetsSkippedForAProbeHostItself(t *testing.T) {
	catalog := newCatalog(t,
		contract.Contract{ID: "freeipa-client", Role: "freeipa-client"},
		contract.Contract{ID: "login-probe", Role: "login-probe"},
	)
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("mon1", "10.0.0.9", []string{"freeipa-client", "login-probe"}, ""))
	provs, _ := loginProbeProviders("mon1", "mon2")
	plan, err := PlanHost(context.Background(), PlanInput{WorkspaceDir: dir, HostName: "mon1", Catalog: catalog, Now: fixedNow, Providers: provs})
	if err != nil {
		t.Fatal(err)
	}
	if cp := loginProbeComponent(plan); cp != nil {
		t.Fatalf("retiring probe host: reference component %+v must not be added", cp)
	}
	if !plan.Blocked() {
		t.Fatal("decommissioning a login-probe host must stay blocked until it has local decommission support")
	}
}
