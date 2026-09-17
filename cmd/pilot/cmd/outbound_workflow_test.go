package cmd

import (
	"reflect"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/delivery"
)

func resultOf(componentID string, outcome delivery.Outcome, failedStep string) ComponentDeliveryResult {
	return ComponentDeliveryResult{ComponentIDs: []string{componentID}, RunID: "run-" + componentID, Outcome: outcome, FailedStep: failedStep}
}

// TestOutboundWorkflow_AggregateAllSuccess is one of the pure
// aggregation-logic tests backing design spec §9's precedence table
// (full workflow-level W1-W20 coverage lands once deploy.go/reconcile.go
// are wired to call publishTerminalWorkflow).
func TestOutboundWorkflow_AggregateAllSuccess(t *testing.T) {
	results := []ComponentDeliveryResult{resultOf("docker", delivery.OutcomeSuccess, ""), resultOf("prometheus", delivery.OutcomeSuccess, "")}
	result, consistency := aggregateWorkflowResult(results)
	if result != "success" || consistency != "confirmed_for_effects" {
		t.Fatalf("got result=%s consistency=%s, want success/confirmed_for_effects", result, consistency)
	}
}

func TestOutboundWorkflow_AggregateOneFailed(t *testing.T) {
	results := []ComponentDeliveryResult{resultOf("docker", delivery.OutcomeSuccess, ""), resultOf("prometheus", delivery.OutcomeFailed, "apply")}
	result, consistency := aggregateWorkflowResult(results)
	if result != "failure" || consistency != "partial_or_unknown" {
		t.Fatalf("got result=%s consistency=%s, want failure/partial_or_unknown", result, consistency)
	}
}

func TestOutboundWorkflow_AggregateEvidenceFailed(t *testing.T) {
	results := []ComponentDeliveryResult{resultOf("docker", delivery.OutcomeEvidenceFailed, "evidence")}
	result, consistency := aggregateWorkflowResult(results)
	if result != "failure" || consistency != "unknown" {
		t.Fatalf("got result=%s consistency=%s, want failure/unknown", result, consistency)
	}
}

func TestOutboundWorkflow_AggregateCancelledBeforeMutation(t *testing.T) {
	results := []ComponentDeliveryResult{resultOf("docker", delivery.OutcomeCancelled, "preflight")}
	result, consistency := aggregateWorkflowResult(results)
	if result != "cancelled" || consistency != "unchanged" {
		t.Fatalf("got result=%s consistency=%s, want cancelled/unchanged", result, consistency)
	}
}

func TestOutboundWorkflow_AggregateCancelledDuringApply(t *testing.T) {
	results := []ComponentDeliveryResult{resultOf("docker", delivery.OutcomeCancelled, "apply")}
	result, consistency := aggregateWorkflowResult(results)
	if result != "cancelled" || consistency != "unchanged_or_partial" {
		t.Fatalf("got result=%s consistency=%s, want cancelled/unchanged_or_partial", result, consistency)
	}
}

func TestOutboundWorkflow_AggregateAuthorizationRequired(t *testing.T) {
	results := []ComponentDeliveryResult{resultOf("docker", delivery.OutcomeAuthorizationRequired, "preflight")}
	result, consistency := aggregateWorkflowResult(results)
	if result != "failure" || consistency != "unchanged" {
		t.Fatalf("got result=%s consistency=%s, want failure/unchanged", result, consistency)
	}
}

func TestOutboundWorkflow_AggregateRolledBackOnly(t *testing.T) {
	results := []ComponentDeliveryResult{resultOf("docker", delivery.OutcomeRolledBack, "apply")}
	result, consistency := aggregateWorkflowResult(results)
	if result != "failure" || consistency != "rolled_back" {
		t.Fatalf("got result=%s consistency=%s, want failure/rolled_back", result, consistency)
	}
}

func TestOutboundWorkflow_AggregateRolledBackPlusOtherCompleted(t *testing.T) {
	results := []ComponentDeliveryResult{resultOf("docker", delivery.OutcomeSuccess, ""), resultOf("prometheus", delivery.OutcomeRolledBack, "apply")}
	result, consistency := aggregateWorkflowResult(results)
	if result != "failure" || consistency != "partial_or_unknown" {
		t.Fatalf("got result=%s consistency=%s, want failure/partial_or_unknown (rolled_back is not exclusive)", result, consistency)
	}
}

func TestOutboundWorkflow_AggregateRollbackFailed(t *testing.T) {
	results := []ComponentDeliveryResult{resultOf("docker", delivery.OutcomeRollbackFailed, "rollback")}
	result, consistency := aggregateWorkflowResult(results)
	if result != "failure" || consistency != "unknown" {
		t.Fatalf("got result=%s consistency=%s, want failure/unknown", result, consistency)
	}
}

func TestOutboundWorkflow_Effects(t *testing.T) {
	autoDeploy := false
	c1 := contract.Contract{
		SchemaVersion: contract.SchemaVersion, ID: "freeipa-identity", Role: "freeipa-server",
		Effects:         []contract.Effect{contract.EffectIdentityUsers, contract.EffectAccessHBAC},
		Specs:           []contract.Spec{{Path: "docs/verification/fixture.md", Rows: contract.RowSelector{All: true}}},
		Playbooks:       contract.Playbooks{Apply: "playbooks/apply/fixture.yml"},
		HostCardinality: "one-or-more",
		StagePolicy:     contract.StagePolicy{Variable: "stage", Default: "sandbox"},
		EvidenceRequirement: contract.Evidence{
			TargetTest: "vm", Idempotency: "required",
		},
		Verification: contract.Verification{AutoDeploy: &autoDeploy},
	}
	c2 := c1
	c2.ID = "freeipa-dns"
	c2.Effects = []contract.Effect{contract.EffectDNSZones}

	catalog, err := contract.NewCatalog([]contract.Contract{c1, c2})
	if err != nil {
		t.Fatal(err)
	}
	got := outboundWorkflowEffects(catalog, []string{"freeipa-identity", "freeipa-dns", "unknown-component"})
	want := []string{"access.hbac", "dns.zones", "identity.users"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outboundWorkflowEffects = %v, want %v", got, want)
	}
}

func TestOutboundWorkflow_ComponentIDHelpers(t *testing.T) {
	results := []ComponentDeliveryResult{
		resultOf("docker", delivery.OutcomeSuccess, ""),
		resultOf("prometheus", delivery.OutcomeFailed, "apply"),
	}
	if got := componentIDsFromResults(results); !reflect.DeepEqual(got, []string{"docker", "prometheus"}) {
		t.Fatalf("componentIDsFromResults = %v", got)
	}
	if got := completedComponentIDs(results); !reflect.DeepEqual(got, []string{"docker"}) {
		t.Fatalf("completedComponentIDs = %v, want [docker]", got)
	}
	if got := failedComponentID(results); got != "prometheus" {
		t.Fatalf("failedComponentID = %q, want prometheus", got)
	}
}

func TestOutboundWorkflow_FailureInfo(t *testing.T) {
	results := []ComponentDeliveryResult{resultOf("docker", delivery.OutcomeSuccess, ""), resultOf("prometheus", delivery.OutcomeFailed, "verify")}
	info := failureInfoFrom(results, "failure")
	if info == nil || info.Class != "verify_failed" || info.Phase != "verify" || info.Component != "prometheus" {
		t.Fatalf("failureInfoFrom = %+v, want verify_failed/verify/prometheus", info)
	}
	if got := failureInfoFrom(results, "success"); got != nil {
		t.Fatalf("failureInfoFrom for a success result must be nil, got %+v", got)
	}
}

func TestOutboundWorkflow_WireDeliveryRuns(t *testing.T) {
	results := []ComponentDeliveryResult{resultOf("docker", delivery.OutcomeSuccess, "")}
	runs := wireDeliveryRunsFrom(results)
	if len(runs) != 1 || runs[0].RunID != "run-docker" || runs[0].Outcome != "success" {
		t.Fatalf("wireDeliveryRunsFrom = %+v", runs)
	}
}

func TestOutboundWorkflow_ReadinessMissingConfig(t *testing.T) {
	dir := t.TempDir()
	cfg, err := webhookReadiness(dir)
	if err != nil || cfg != nil {
		t.Fatalf("webhookReadiness with no integrations.yaml = (%v, %v), want (nil, nil)", cfg, err)
	}
}
