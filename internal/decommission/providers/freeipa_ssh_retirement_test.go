package providers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

func TestFreeIPAProvider_InterruptedRetirementRequiresJournalReceipt(t *testing.T) {
	const fqdn = "retired.ipa.pilot.internal"
	for _, observation := range []string{"SSH_RETIREMENT=pending", "SSH_RETIREMENT=settled", "", "SSH_RETIREMENT=unknown"} {
		t.Run(observation, func(t *testing.T) {
			exec := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
				if queryKind(args) == "host_object" {
					return &ansible.Result{Stdout: "HOST_INSPECT[" + fqdn + "]: ipa: ERROR: " + fqdn + ": host not found"}, nil
				}
				if !hasArgs(args, []string{"-e", `{"pilot_decommission_target_alias":"client-old"}`}) {
					t.Fatalf("query lost persisted inventory alias: %v", args)
				}
				return &ansible.Result{Stdout: "HOST_INSPECT[" + fqdn + "]: " + observation}, nil
			}}
			p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{Executor: exec})
			step, err := p.ExecutorForStep(Step{Action: ActionFreeIPAIdentityApplyConverge,
				TargetIdentity: fqdn, Params: map[string]string{"inventory_alias": "client-old"}})
			if err != nil {
				t.Fatal(err)
			}
			converged, err := step.Inspect(context.Background())
			wantError := observation == "" || strings.HasSuffix(observation, "unknown")
			if (err != nil) != wantError || converged != (observation == "SSH_RETIREMENT=settled") {
				t.Fatalf("Inspect = (%v, %v), observation %q", converged, err, observation)
			}
			if len(exec.calls) != 2 {
				t.Fatalf("host absence skipped journal recovery oracle: %v", exec.calls)
			}
		})
	}
}

func TestFreeIPAProvider_RetirementAliasSurvivesPlanSerialization(t *testing.T) {
	p, _ := testProvider(t, func(args []string) (*ansible.Result, error) {
		return &ansible.Result{Stdout: hostShowClean}, nil
	})
	steps, err := p.Plan(context.Background(), PlanInput{HostName: "transport-alias", FQDN: "web1.ipa.pilot.internal"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(steps)
	if err != nil {
		t.Fatal(err)
	}
	var restored []Step
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	step, err := p.ExecutorForStep(restored[2])
	if err != nil {
		t.Fatal(err)
	}
	exec := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		if !hasArgs(args, []string{"-e", `{"pilot_decommission_retiring_alias":"transport-alias","pilot_decommission_retiring_fqdn":"web1.ipa.pilot.internal"}`}) {
			t.Fatalf("identity mutation lost authorized exact alias/FQDN binding: %v", args)
		}
		return &ansible.Result{}, nil
	}}
	p.cfg.Executor = exec
	if err := step.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(exec.calls) != 1 {
		t.Fatal("central mutation did not execute")
	}
}

func TestFreeIPAProvider_OldRetirementPlanNeedsTrustedAlias(t *testing.T) {
	for _, alias := range []string{"", "original-transport"} {
		p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{InventoryAlias: alias,
			Executor: &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
				if queryKind(args) == "host_object" {
					return &ansible.Result{Stdout: "HOST_INSPECT[retired.ipa.test]: host not found"}, nil
				}
				if !hasArgs(args, []string{"-e", `{"pilot_decommission_target_alias":"original-transport"}`}) {
					t.Fatalf("recovery did not bind trusted original alias: %v", args)
				}
				return &ansible.Result{Stdout: "HOST_INSPECT[retired.ipa.test]: SSH_RETIREMENT=pending"}, nil
			}}})
		step, err := p.ExecutorForStep(Step{Action: ActionFreeIPAIdentityApplyConverge, TargetIdentity: "retired.ipa.test"})
		if err != nil {
			t.Fatal(err)
		}
		done, err := step.Inspect(context.Background())
		if done || (err != nil) != (alias == "") {
			t.Fatalf("alias=%q Inspect=%v,%v", alias, done, err)
		}
		if alias == "" && !strings.Contains(err.Error(), "original inventory alias missing") {
			t.Fatalf("wrong recovery refusal: %v", err)
		}
	}
}
