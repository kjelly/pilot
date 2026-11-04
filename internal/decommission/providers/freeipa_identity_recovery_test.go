package providers

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

func TestFreeIPARetirementCanonicalBoundaryMatchesNativeHelper(t *testing.T) {
	helper, err := filepath.Abs("../../../playbooks/apply/files/freeipa-gateway-scope.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"CLIENT.Example.TEST.", " a-b.a-2.test ", strings.Repeat("a", 63) + ".test",
		"client", "10.0.0.9", "::1", ".example.test", "host..example", "-host.test", "host-.test", "host_01.example", "münchen.example", strings.Repeat("a", 64) + ".test", strings.Repeat("a.", 128) + "test"} {
		t.Run(value, func(t *testing.T) {
			got, goErr := CanonicalFreeIPAFQDN(value)
			out, nativeErr := exec.Command("python3", "-c", "import runpy,sys; print(runpy.run_path(sys.argv[1])['fqdn'](sys.argv[2]))", helper, value).CombinedOutput()
			if nativeErr != nil && !strings.Contains(string(out), "ValueError:") {
				t.Fatalf("native boundary did not execute: %v: %s", nativeErr, out)
			}
			if (goErr == nil) != (nativeErr == nil) || (goErr == nil && got != strings.TrimSpace(string(out))) {
				t.Fatalf("Go/native boundary mismatch: %q/%v, %q/%v", got, goErr, out, nativeErr)
			}
		})
	}
}

func TestFreeIPARetirementRecoveryRequiresConfirmedNativeAbsence(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		rc         int
		wantOK     bool
		wantError  string
	}{
		{"native NotFound", "ipa: ERROR: Client: host not found", 0, true, ""},
		{"same live canonical", "Host name: CLIENT.Example.TEST\n0 services matched", 0, true, ""},
		{"different live canonical", "Host name: other.example.test\n0 services matched", 0, false, "live FreeIPA identity differs"},
		{"query error", "ipa: ERROR: connection unavailable", 2, false, "ansible-playbook exited 2"},
		{"rc0 missing name", "Number of entries returned 0", 0, false, "no unambiguous native host identity"},
		{"rc0 malformed name", "Host name: Client\n0 services matched", 0, false, "malformed live FreeIPA host identity"},
		{"unrelated not-found text", "certificate not found", 0, false, "no unambiguous native host identity"},
		{"contradictory identity", "Host name: client.example.test\nipa: ERROR: Client: host not found", 0, false, "no unambiguous native host identity"},
		{"duplicate identity", "Host name: client.example.test\nHost name: client.example.test", 0, false, "no unambiguous native host identity"},
		{"unknown service principal", "Host name: client.example.test\nPrincipal name: HTTP/client.example.test@EXAMPLE.TEST", 0, false, "unknown/unproven service principal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gateway []string
			executor := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
				if len(args) == 0 || args[0] != "current-identity.yml" || !argsContain(args, "current-server.yml") || !argsContain(args, "freeipa_server_fqdn=current.ipa.test") {
					t.Fatalf("recovery retargeted the current provider configuration: %v", args)
				}
				target := queryControl(args, "pilot_decommission_target_fqdn")
				switch queryKind(args) {
				case "host_object":
					return &ansible.Result{ExitCode: tc.rc, Stdout: fmt.Sprintf("HOST_INSPECT[%s]: %s", target, tc.body)}, nil
				case "gateway_scope":
					gateway = append(gateway, target)
					return &ansible.Result{Stdout: "HOST_INSPECT[" + target + "]: GATEWAY_SCOPE_READY=true"}, nil
				default:
					t.Fatalf("unexpected mutating/nonidentity call: %v", args)
					return nil, nil
				}
			}}
			p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{Executor: executor, InventoryAlias: "Client", RetirementStage: "sandbox",
				ServerInventory: "current-server.yml", IdentityApplyPlaybook: "current-identity.yml", ExtraArgs: []string{"-e", "freeipa_server_fqdn=current.ipa.test"}})
			steps, err := p.Plan(context.Background(), PlanInput{HostName: "Client", FQDN: "Client",
				RetirementIdentity: &RetirementIdentity{InventoryAlias: "Client", Stage: "sandbox", FQDN: "client.example.test"}})
			if (err == nil) != tc.wantOK {
				t.Fatalf("Plan = %v/%v, want success=%v", steps, err, tc.wantOK)
			}
			if !tc.wantOK && !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("Plan refused for the wrong reason: %v, want %q", err, tc.wantError)
			}
			if tc.wantOK {
				if len(steps) != 3 || len(gateway) != 1 || gateway[0] != "client.example.test" || steps[1].TargetIdentity != "client.example.test" {
					t.Fatalf("canonical identity was not carried into preflight/steps: %v %v", steps, gateway)
				}
			} else if len(steps) != 0 || len(gateway) != 0 {
				t.Fatalf("unproven identity reached a gateway probe: %v %v", steps, gateway)
			}
		})
	}
}

func TestFreeIPARetirementUninstallRevalidatesPlannedCanonicalIdentity(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprint(present), func(t *testing.T) {
			uninstalls := 0
			var gateway []string
			e := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
				target := queryControl(args, "pilot_decommission_target_fqdn")
				switch queryKind(args) {
				case "host_object":
					body := "ipa: ERROR: Client: host not found"
					if present {
						body = "Host name: changed.example.test\n0 services matched"
					}
					return &ansible.Result{Stdout: "HOST_INSPECT[" + target + "]: " + body}, nil
				case "gateway_scope":
					gateway = append(gateway, target)
					return &ansible.Result{Stdout: "HOST_INSPECT[" + target + "]: GATEWAY_SCOPE_READY=true"}, nil
				default:
					uninstalls++
					return &ansible.Result{}, nil
				}
			}}
			p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{Executor: e, InventoryAlias: "Client", RetirementStage: "sandbox"})
			step, err := p.ExecutorForStep(Step{Action: ActionFreeIPAClientUninstall, TargetIdentity: "Client", Params: map[string]string{
				"retirement_fqdn": "client.example.test", "retirement_stage": "sandbox",
			}})
			if err != nil {
				t.Fatal(err)
			}
			err = step.Execute(context.Background())
			if present {
				if err == nil || uninstalls != 0 || len(gateway) != 0 {
					t.Fatalf("changed live identity reached uninstall: %v %d %v", err, uninstalls, gateway)
				}
			} else if err != nil || uninstalls != 1 || len(gateway) != 1 || gateway[0] != "client.example.test" {
				t.Fatalf("planned canonical identity did not survive absence: %v %d %v", err, uninstalls, gateway)
			}
		})
	}
}
