package providers

import (
	"context"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

// TestGenericComponentProvider_FullCycle proves the Phase 5 generic
// contract-driven executor: plan -> execute -> converged -> verify, for
// an arbitrary component that only needs local cleanup (spec.md §15).
func TestGenericComponentProvider_FullCycle(t *testing.T) {
	enrolled := true
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		if !argsContain(args, "--limit") || !argsContain(args, "node1") {
			t.Errorf("every call must be limited to the target host, got %v", args)
		}
		if argsContain(args, "--tags") {
			if enrolled {
				return &ansible.Result{Stdout: "PILOT_COMPONENT_DECOMMISSIONED=false"}, nil
			}
			return &ansible.Result{Stdout: "PILOT_COMPONENT_DECOMMISSIONED=true"}, nil
		}
		// the real mutating run
		enrolled = false
		return &ansible.Result{}, nil
	}}
	p := NewGenericComponentProvider(GenericComponentProviderConfig{
		Executor:             fake,
		ComponentID:          "host-monitoring",
		Inventory:            "inventory.yml",
		DecommissionPlaybook: "playbooks/decommission/host-monitoring-decommission.yml",
	})

	if p.ID() != "host-monitoring" {
		t.Fatalf("ID() = %q, want host-monitoring", p.ID())
	}

	steps, err := p.Plan(context.Background(), PlanInput{HostName: "node1"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(steps) != 1 || steps[0].TargetIdentity != "node1" {
		t.Fatalf("expected exactly 1 step targeting node1, got %+v", steps)
	}

	se, err := p.ExecutorForStep(steps[0])
	if err != nil {
		t.Fatalf("ExecutorForStep: %v", err)
	}
	converged, err := se.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if converged {
		t.Fatalf("expected not-yet-converged while still enrolled")
	}
	if err := se.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	verifs, err := p.Verify(context.Background(), VerifyInput{HostName: "node1"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(verifs) != 1 || verifs[0].Active {
		t.Fatalf("expected 1 verification with Active=false after cleanup, got %+v", verifs)
	}
}

func TestGenericComponentProvider_UnknownStepActionErrors(t *testing.T) {
	p := NewGenericComponentProvider(GenericComponentProviderConfig{ComponentID: "host-monitoring"})
	if _, err := p.ExecutorForStep(Step{Action: "not-a-real-action"}); err == nil {
		t.Fatalf("expected an error for an unrecognized step action")
	}
}

func TestGenericComponentProvider_AnsibleFailureIsNotTreatedAsDecommissioned(t *testing.T) {
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		return &ansible.Result{ExitCode: 1, Stderr: "unreachable"}, nil
	}}
	p := NewGenericComponentProvider(GenericComponentProviderConfig{Executor: fake, ComponentID: "host-monitoring"})
	if _, err := p.Verify(context.Background(), VerifyInput{HostName: "node1"}); err == nil {
		t.Fatalf("expected a genuinely failed ansible-playbook run to surface as an error, not a silent pass")
	}
}
