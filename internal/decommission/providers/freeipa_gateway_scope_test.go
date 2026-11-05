package providers

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

func gatewayPreflightProvider(t *testing.T, response func() *ansible.Result) (*FreeIPAClientProvider, *fakeAnsibleExecutor, *int) {
	t.Helper()
	uninstalls := new(int)
	executor := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		fqdn := queryControl(args, "pilot_decommission_target_fqdn")
		switch queryKind(args) {
		case "host_object":
			return &ansible.Result{Stdout: fmt.Sprintf("HOST_INSPECT[%s]: Host name: keep.ipa227.test\nPrincipal name: host/keep.ipa227.test@IPA227.TEST\n", fqdn)}, nil
		case "gateway_scope":
			return response(), nil
		default:
			*uninstalls++
			return &ansible.Result{}, nil
		}
	}}
	return NewFreeIPAClientProvider(FreeIPAClientProviderConfig{Executor: executor,
		InventoryFQDN: "keep.ipa227.test", DecommissionPlaybook: "client-uninstall.yml",
		IdentityApplyPlaybook: "identity.yml"}), executor, uninstalls
}

// The preflight is a product contract emitted only after the native ownership
// helper succeeds. These are protocol observations, not invented IPA output.
func TestFreeIPAGatewayOwnershipBlocksPlanAndUninstallBeforeClientMutation(t *testing.T) {
	for _, failure := range []ansible.Result{
		{ExitCode: 2, Stderr: "unproven hostgroup ownership: pilot-target-foreign; explicitly adopt its exact live ipauniqueid"},
		{ExitCode: 2, Stderr: "ownership probe unavailable"},
		{Stdout: "HOST_INSPECT[other.ipa227.test]: GATEWAY_SCOPE_READY=true"},
		{Stdout: "HOST_INSPECT[keep.ipa227.test]: ownership not observed"},
	} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			p, _, uninstalls := gatewayPreflightProvider(t, func() *ansible.Result { return &failure })
			steps, err := p.Plan(context.Background(), PlanInput{HostName: "short-alias", FQDN: "keep.ipa227.test"})
			if err == nil || len(steps) != 0 || !strings.Contains(err.Error(), "gateway scope ownership preflight") {
				t.Fatalf("Plan returned steps=%v err=%v", steps, err)
			}
			executor, err := p.ExecutorForStep(Step{Action: ActionFreeIPAClientUninstall, TargetIdentity: "short-alias"})
			if err != nil {
				t.Fatal(err)
			}
			if err := executor.Execute(context.Background()); err == nil {
				t.Fatal("uninstall accepted unproven current gateway ownership")
			}
			if *uninstalls != 0 {
				t.Fatalf("client mutation occurred before ownership refusal: %d", *uninstalls)
			}
		})
	}
}

func TestFreeIPAGatewayOwnershipRevalidatedAfterSuccessfulPlan(t *testing.T) {
	allowed := true
	p, calls, uninstalls := gatewayPreflightProvider(t, func() *ansible.Result {
		if !allowed {
			return &ansible.Result{ExitCode: 2, Stderr: "unproven hostgroup ownership: new-foreign"}
		}
		return &ansible.Result{Stdout: "HOST_INSPECT[keep.ipa227.test]: GATEWAY_SCOPE_READY=true"}
	})
	steps, err := p.Plan(context.Background(), PlanInput{HostName: "short-alias", FQDN: "keep.ipa227.test"})
	if err != nil || len(steps) != 3 {
		t.Fatalf("Plan=%v/%v", steps, err)
	}
	allowed = false
	executor, err := p.ExecutorForStep(steps[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background()); err == nil || *uninstalls != 0 {
		t.Fatalf("changed ownership must stop preplanned uninstall: err=%v uninstalls=%d", err, *uninstalls)
	}
	allowed = true
	if err := executor.Execute(context.Background()); err != nil || *uninstalls != 1 {
		t.Fatalf("proven ownership must allow uninstall: err=%v uninstalls=%d", err, *uninstalls)
	}
	if last := calls.calls[len(calls.calls)-1]; last[0] != "client-uninstall.yml" {
		t.Fatalf("last call was not the authorized client uninstall: %v", last)
	}
}
