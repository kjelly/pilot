package decommission

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/decommission/providers"
)

func recoveryIdentityFixture(t *testing.T) (PlanInput, *Plan, *identityIPAProvider, *identityIPAExecutor) {
	t.Helper()
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("Client", "10.0.0.9", []string{"freeipa-client"}, ""))
	executor := &identityIPAExecutor{present: true}
	provider := &identityIPAProvider{FreeIPAClientProvider: providers.NewFreeIPAClientProvider(providers.FreeIPAClientProviderConfig{
		Executor: executor, InventoryAlias: "Client", RetirementStage: "sandbox",
	}), executor: executor}
	in := PlanInput{WorkspaceDir: dir, HostName: "Client", Now: fixedNow,
		Catalog:   newCatalog(t, fakeComponentContract("freeipa-client", "freeipa-client")),
		Providers: map[string]providers.Provider{"freeipa-client": provider}}
	plan, err := PlanHost(context.Background(), in)
	if err != nil || plan.Blocked() {
		t.Fatalf("initial native-backed plan = %+v, %v", plan, err)
	}
	return in, plan, provider, executor
}

func TestHostIdentity_InitialUnboundDiscoveryRemainsAuthoritative(t *testing.T) {
	in, _, provider, executor := recoveryIdentityFixture(t)
	executor.fqdn = "NEW.Example.TEST"
	plan, err := PlanHost(context.Background(), in)
	if err != nil || plan.Blocked() || plan.FQDN != "new.example.test" || provider.cleanupTarget != "" {
		t.Fatalf("new unbound discovery = %+v, %v", plan, err)
	}
	assertGatewayScopeQueriesTarget(t, executor.gatewayTargets[len(executor.gatewayTargets)-1:], "new.example.test")
}

func TestHostIdentity_RecoveryRejectsUnboundOrInconsistentPersistedIdentity(t *testing.T) {
	for _, name := range []string{
		"short metadata", "IP metadata", "metadata conflicts with steps", "missing all canonical identity",
		"ambiguous legacy steps", "malformed legacy step", "step alias drift", "step stage drift",
		"local identity drift", "snapshot alias drift", "environment drift", "missing inventory binding",
	} {
		t.Run(name, func(t *testing.T) {
			in, plan, provider, executor := recoveryIdentityFixture(t)
			approvedHash := plan.PlanHash
			switch name {
			case "short metadata":
				plan.FQDN = "Client"
			case "IP metadata":
				plan.FQDN = "10.0.0.9"
			case "metadata conflicts with steps":
				plan.FQDN = "other.example.test"
			case "missing all canonical identity":
				plan.FQDN = ""
				for i := range plan.Components[0].Steps {
					step := &plan.Components[0].Steps[i]
					if step.Action != providers.ActionFreeIPAClientUninstall {
						step.TargetIdentity = ""
					}
					delete(step.Params, "retirement_fqdn")
				}
			case "ambiguous legacy steps":
				plan.FQDN = ""
				delete(plan.Components[0].Steps[0].Params, "retirement_fqdn")
				plan.Components[0].Steps[2].TargetIdentity = "other.example.test"
			case "malformed legacy step":
				plan.Components[0].Steps[1].TargetIdentity = "Client"
			case "step alias drift":
				plan.Components[0].Steps[1].Params["inventory_alias"] = "Other"
			case "step stage drift":
				plan.Components[0].Steps[1].Params["retirement_stage"] = "prod"
			case "local identity drift":
				plan.Components[0].Steps[0].Params["retirement_fqdn"] = "other.example.test"
			case "snapshot alias drift":
				plan.Host.Name = "Other"
			case "environment drift":
				plan.Environment = "prod"
			case "missing inventory binding":
				plan.InventoryRevision = ""
			}
			// These fields are deliberately not all approval-hashed. The
			// independent binding must reject them before the strict helper.
			if name != "snapshot alias drift" && name != "environment drift" && name != "missing inventory binding" && computePlanHash(plan) != approvedHash {
				t.Fatal("control unexpectedly changed the approval hash")
			}
			executor.present = false
			queries := len(executor.gatewayTargets)
			original, err := os.ReadFile(filepath.Join(in.WorkspaceDir, "hosts.yml"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = Apply(context.Background(), ApplyInput{Plan: plan, PlanInputForFreshness: in, Now: fixedNow})
			if ClassOf(err) != ErrPlanStale || !strings.Contains(err.Error(), "cannot recover persisted FreeIPA retirement identity") || provider.cleanupTarget != "" || len(executor.gatewayTargets) != queries {
				t.Fatalf("invalid recovery reached a probe/mutation: err=%v target=%q queries=%v", err, provider.cleanupTarget, executor.gatewayTargets)
			}
			after, err := os.ReadFile(filepath.Join(in.WorkspaceDir, "hosts.yml"))
			if err != nil || string(after) != string(original) {
				t.Fatal("invalid recovery mutated the workspace")
			}
		})
	}
}

func TestHostIdentity_RecoveryNeverMasksQueryErrorOrMalformedSuccess(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(map[bool]string{false: "native query error", true: "rc0 without a host identity"}[malformed], func(t *testing.T) {
			in, plan, provider, executor := recoveryIdentityFixture(t)
			executor.present = false
			executor.queryError, executor.malformedHost = !malformed, malformed
			queries := len(executor.gatewayTargets)
			_, err := Apply(context.Background(), ApplyInput{Plan: plan, PlanInputForFreshness: in, Now: fixedNow})
			if ClassOf(err) != ErrPlanStale || provider.cleanupTarget != "" || len(executor.gatewayTargets) != queries {
				t.Fatalf("unproven absence used the identity fallback: err=%v target=%q", err, provider.cleanupTarget)
			}
		})
	}
}

func TestHostIdentity_CurrentWorkspaceBindingMustStillMatch(t *testing.T) {
	for _, name := range []string{"alias", "stage", "explicit mapping", "authority host", "provider stage", "provider explicit mapping"} {
		t.Run(name, func(t *testing.T) {
			in, plan, provider, executor := recoveryIdentityFixture(t)
			switch name {
			case "alias":
				in.HostName = "Other"
				writeWorkspaceFile(t, in.WorkspaceDir, "hosts.yml", simpleHostsYAML("Other", "10.0.0.9", []string{"freeipa-client"}, ""))
			case "stage":
				writeWorkspaceFile(t, in.WorkspaceDir, "hosts.yml", simpleHostsYAML("Client", "10.0.0.9", []string{"freeipa-client"}, "    env: prod\n"))
			case "explicit mapping":
				writeWorkspaceFile(t, in.WorkspaceDir, "hosts.yml", simpleHostsYAML("Client", "10.0.0.9", []string{"freeipa-client"}, "    ipa_client_fqdn: other.example.test\n"))
			case "authority host":
				writeWorkspaceFile(t, in.WorkspaceDir, "hosts.yml", simpleHostsYAML("Client", "10.0.0.9", []string{"freeipa-client"}, "")+"  new-authority:\n    ansible_host: 10.0.0.10\n    roles: [freeipa-server]\n")
			case "provider stage", "provider explicit mapping":
				cfg := providers.FreeIPAClientProviderConfig{Executor: executor, InventoryAlias: "Client", RetirementStage: "sandbox"}
				if name == "provider stage" {
					cfg.RetirementStage = "prod"
				} else {
					cfg.InventoryFQDN = "other.example.test"
				}
				provider.FreeIPAClientProvider = providers.NewFreeIPAClientProvider(cfg)
			}
			executor.present = false
			queries := len(executor.gatewayTargets)
			_, err := Apply(context.Background(), ApplyInput{Plan: plan, PlanInputForFreshness: in, Now: fixedNow})
			if ClassOf(err) != ErrPlanStale || provider.cleanupTarget != "" || len(executor.gatewayTargets) != queries {
				t.Fatalf("changed binding reached recovery: err=%v cleanup=%q", err, provider.cleanupTarget)
			}
		})
	}
}

func TestHostIdentity_FinalizeRecoversFromUniqueLegacyCleanupIdentity(t *testing.T) {
	in, plan, provider, executor := recoveryIdentityFixture(t)
	plan.FQDN = ""
	for i := range plan.Components[0].Steps {
		plan.Components[0].Steps[i].HostIdentitySource = ""
		plan.Components[0].Steps[i].Params = nil
	}
	executor.present = false
	verifications, err := collectVerifications(context.Background(), plan, in.Providers)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Finalize(context.Background(), FinalizeInput{Plan: plan, PlanInputForFreshness: in,
		Verifications: verifications, Now: fixedNow, StartedAt: fixedNow()})
	if err != nil || result.Status != "completed" || !result.Receipt.Verified || result.Receipt.FQDN != "client.example.test" {
		t.Fatalf("legacy Finalize = %+v, %v", result, err)
	}
	assertGatewayScopeQueriesTarget(t, executor.gatewayTargets, "client.example.test")
	assertGatewayScopeQueriesTarget(t, provider.verificationTargets, "client.example.test")
}

func TestHostIdentity_RecoveryBindingSurvivesPlanStoreJSONRoundTrip(t *testing.T) {
	for _, extra := range []string{"", "    custom_count: 7\n    custom_enabled: true\n    custom_list: [one, two]\n    custom_empty_list: []\n    custom_empty: ''\n    custom_nil: null\n"} {
		t.Run(map[bool]string{true: "empty extras", false: "YAML scalar and list extras"}[extra == ""], func(t *testing.T) {
			in, _, _, executor := recoveryIdentityFixture(t)
			writeWorkspaceFile(t, in.WorkspaceDir, "hosts.yml", simpleHostsYAML("Client", "10.0.0.9", []string{"freeipa-client"}, extra))
			plan, err := PlanHost(context.Background(), in)
			if err != nil || plan.Blocked() {
				t.Fatalf("plan with typed YAML extras = %+v, %v", plan, err)
			}
			store := NewStore(openTestStore(t))
			if err := store.SavePlan(plan); err != nil {
				t.Fatal(err)
			}
			loaded, err := store.LoadPlan(plan.ID)
			if err != nil {
				t.Fatal(err)
			}
			if jsonHash(canonicalHostSnapshot(plan.Host)) != jsonHash(canonicalHostSnapshot(loaded.Host)) {
				t.Fatal("plan JSON changed the typed host snapshot")
			}
			executor.present = false
			result, err := Apply(context.Background(), ApplyInput{Plan: loaded, PlanInputForFreshness: in,
				Now: fixedNow, StartedAt: fixedNow(), Store: store})
			if err != nil || result.Status != "completed" || !result.Receipt.Verified {
				t.Fatalf("stored plan did not bind to the fresh YAML snapshot: %+v, %v", result, err)
			}
			assertGatewayScopeQueriesTarget(t, executor.gatewayTargets, "client.example.test")
		})
	}
}
