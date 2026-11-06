package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
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

// D15 (spec 2026-11-06 phase 2 §6.4): every delivery.Outcome constant is read
// explicitly, so a new outcome that nobody classified cannot turn into an announced
// success. The constants are read from the source of the type, not from a list kept
// here, so adding one fails this test until workflowOutcomeResult has it.
func TestEveryDeliveryOutcomeIsPublishedExplicitly(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "..", "..", "internal", "delivery", "transaction.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var declared []string
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Outcome" {
				continue
			}
			for i, name := range vs.Names {
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok {
					t.Fatalf("%s is not a string literal", name.Name)
				}
				v, _ := strconv.Unquote(lit.Value)
				declared = append(declared, v)
			}
		}
	}
	if len(declared) < 9 {
		t.Fatalf("found %d Outcome constants, want at least the 9 there were: the scan is not looking at the type", len(declared))
	}
	var listed []string
	for o := range workflowOutcomeResult {
		listed = append(listed, string(o))
	}
	slices.Sort(declared)
	slices.Sort(listed)
	if !slices.Equal(declared, listed) {
		t.Fatalf("delivery.Outcome constants %v, workflowOutcomeResult has %v: classify the new outcome", declared, listed)
	}
}

// The classification, row by row, and the default: an outcome nobody classified is
// a failure with an unknown consistency, in a mix as well as alone.
func TestAggregateWorkflowResultClassifiesEveryOutcomeAndFailsTheUnknownOne(t *testing.T) {
	for _, tc := range []struct {
		outcome delivery.Outcome
		want    string
	}{
		{delivery.OutcomeSuccess, "success"},
		{delivery.OutcomePartialSuccess, "success"},
		{delivery.OutcomeFailed, "failure"},
		{delivery.OutcomePartialFailed, "failure"},
		{delivery.OutcomeRolledBack, "failure"},
		{delivery.OutcomeRollbackFailed, "failure"},
		{delivery.OutcomeEvidenceFailed, "failure"},
		{delivery.OutcomeAuthorizationRequired, "failure"},
		{delivery.OutcomeCancelled, "cancelled"},
		{delivery.Outcome("an_outcome_added_later"), "failure"},
		{delivery.Outcome(""), "failure"},
	} {
		got, _ := aggregateWorkflowResult([]ComponentDeliveryResult{{ComponentIDs: []string{"c"}, Outcome: tc.outcome}})
		if got != tc.want {
			t.Errorf("outcome %q alone: published as %q, want %q", tc.outcome, got, tc.want)
		}
	}
	// In a mix: a failure wins over a cancellation, a cancellation over a success,
	// and an unknown outcome beside successes makes the whole a failure.
	for _, tc := range []struct {
		name     string
		outcomes []delivery.Outcome
		want     string
	}{
		{"unknown beside a success", []delivery.Outcome{delivery.OutcomeSuccess, "an_outcome_added_later"}, "failure"},
		{"failure beside a cancellation", []delivery.Outcome{delivery.OutcomeCancelled, delivery.OutcomeFailed}, "failure"},
		{"cancellation beside a success", []delivery.Outcome{delivery.OutcomeSuccess, delivery.OutcomeCancelled}, "cancelled"},
		{"partial_failed beside a success", []delivery.Outcome{delivery.OutcomeSuccess, delivery.OutcomePartialFailed}, "failure"},
	} {
		var rs []ComponentDeliveryResult
		for _, o := range tc.outcomes {
			rs = append(rs, ComponentDeliveryResult{ComponentIDs: []string{"c"}, Outcome: o})
		}
		if got, _ := aggregateWorkflowResult(rs); got != tc.want {
			t.Errorf("%s: published as %q, want %q", tc.name, got, tc.want)
		}
	}
	if _, consistency := aggregateWorkflowResult([]ComponentDeliveryResult{{ComponentIDs: []string{"c"}, Outcome: "an_outcome_added_later"}}); consistency != "unknown" {
		t.Errorf("an unknown outcome has consistency %q, want unknown", consistency)
	}
	// partial_failed is the Go writer's: a failure that is partial_or_unknown, with
	// no confirmed effects (R7).
	pub, consistency := aggregateWorkflowResult([]ComponentDeliveryResult{{ComponentIDs: []string{"freeipa-identity"}, Outcome: delivery.OutcomePartialFailed, FailedStep: "verify"}})
	if pub != "failure" || consistency != "partial_or_unknown" {
		t.Errorf("partial_failed = %s / %s, want failure / partial_or_unknown", pub, consistency)
	}
	if got := completedComponentIDs([]ComponentDeliveryResult{{ComponentIDs: []string{"freeipa-identity"}, Outcome: delivery.OutcomePartialFailed}}); len(got) != 0 {
		t.Errorf("a partial_failed component is listed as completed: %v", got)
	}
}
