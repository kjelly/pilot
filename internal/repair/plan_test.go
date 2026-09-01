package repair

import (
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/networkcheck"
)

func testPrometheusContract() contract.Contract {
	return contract.Contract{
		ID: "prometheus", Role: "prometheus",
		Playbooks: contract.Playbooks{Apply: "playbooks/apply/prometheus-apply.yml"},
		Specs:     []contract.Spec{{Path: "docs/verification/prometheus.md", Rows: contract.RowSelector{All: true}}},
		Remediation: contract.Remediation{Actions: []contract.RemediationAction{
			{ID: "restart", Risk: "R1", Executor: contract.RemediationActionExecutor{Kind: "docker_restart", Target: "pilot-prometheus"},
				MaxTargets: 1, RequiresApproval: true, Verification: contract.RemediationVerification{Spec: "docs/verification/prometheus.md"}},
		}},
	}
}

func testResolvedInventory() networkcheck.ResolvedInventory {
	return networkcheck.ResolvedInventory{
		GroupHosts: map[string][]string{"prometheus": {"web-1"}},
		HostVars:   map[string]map[string]any{"web-1": {"ansible_host": "10.0.0.5"}},
	}
}

func TestBuildPlan_Success(t *testing.T) {
	catalog := testCatalog(t, testPrometheusContract())
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	p, err := BuildPlan(catalog, testResolvedInventory(), "plan-1", "inc-1", "web-1", "prometheus", "restart", now)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if p.ExecutorKind != "docker_restart" || p.ExecutorTarget != "pilot-prometheus" {
		t.Errorf("executor = %s/%s, want docker_restart/pilot-prometheus", p.ExecutorKind, p.ExecutorTarget)
	}
	if p.VerificationSpec != "docs/verification/prometheus.md" {
		t.Errorf("VerificationSpec = %q", p.VerificationSpec)
	}
	if p.PlanHash == "" {
		t.Error("PlanHash is empty")
	}
	if !p.ExpiresAt.Equal(now.Add(PlanTTL)) {
		t.Errorf("ExpiresAt = %v, want %v", p.ExpiresAt, now.Add(PlanTTL))
	}
	if p.Expired(now) {
		t.Error("plan should not be expired at creation time")
	}
	if !p.Expired(now.Add(PlanTTL + time.Second)) {
		t.Error("plan should be expired after TTL")
	}
}

func TestBuildPlan_UnknownHostRejected(t *testing.T) {
	catalog := testCatalog(t, testPrometheusContract())
	_, err := BuildPlan(catalog, testResolvedInventory(), "plan-1", "inc-1", "nope", "prometheus", "restart", time.Now())
	if err == nil {
		t.Fatal("expected an error for an unknown host")
	}
}

func TestBuildPlan_ComponentNotAssignedToHostRejected(t *testing.T) {
	catalog := testCatalog(t, testPrometheusContract())
	resolved := testResolvedInventory()
	resolved.HostVars["web-2"] = map[string]any{}
	_, err := BuildPlan(catalog, resolved, "plan-1", "inc-1", "web-2", "prometheus", "restart", time.Now())
	if err == nil {
		t.Fatal("expected an error: web-2 is a known host but not assigned to prometheus")
	}
}

func TestBuildPlan_UnknownActionRejected(t *testing.T) {
	catalog := testCatalog(t, testPrometheusContract())
	_, err := BuildPlan(catalog, testResolvedInventory(), "plan-1", "inc-1", "web-1", "prometheus", "not-an-action", time.Now())
	if err == nil {
		t.Fatal("expected an error for an unknown action id")
	}
}

func TestBuildPlan_R2ActionRejected(t *testing.T) {
	c := testPrometheusContract()
	c.Remediation.Actions = append(c.Remediation.Actions, contract.RemediationAction{
		ID: "reapply", Risk: "R2", Executor: contract.RemediationActionExecutor{Kind: "docker_restart", Target: "pilot-prometheus"}, MaxTargets: 1,
	})
	catalog := testCatalog(t, c)
	_, err := BuildPlan(catalog, testResolvedInventory(), "plan-1", "inc-1", "web-1", "prometheus", "reapply", time.Now())
	if err == nil {
		t.Fatal("expected an error: Phase 3 must reject a declared R2 action")
	}
}

func TestVerifyPlanFresh_DetectsContractDrift(t *testing.T) {
	catalog := testCatalog(t, testPrometheusContract())
	resolved := testResolvedInventory()
	now := time.Now()
	p, err := BuildPlan(catalog, resolved, "plan-1", "inc-1", "web-1", "prometheus", "restart", now)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	fresh, err := VerifyPlanFresh(catalog, resolved, p)
	if err != nil {
		t.Fatalf("VerifyPlanFresh (unchanged) = %v, want nil", err)
	}
	if fresh.PlanHash != p.PlanHash {
		t.Errorf("fresh.PlanHash = %q, want %q (unchanged contract/inventory)", fresh.PlanHash, p.PlanHash)
	}

	// Simulate the contract's executor target changing after the plan
	// was created/approved (e.g. someone edited the contract).
	driftedContract := testPrometheusContract()
	driftedContract.Remediation.Actions[0].Executor.Target = "pilot-prometheus-renamed"
	driftedCatalog := testCatalog(t, driftedContract)
	if _, err := VerifyPlanFresh(driftedCatalog, resolved, p); err == nil {
		t.Fatal("expected VerifyPlanFresh to reject a plan whose contract action drifted")
	}
}

func TestVerifyPlanFresh_DetectsInventoryDrift(t *testing.T) {
	catalog := testCatalog(t, testPrometheusContract())
	resolved := testResolvedInventory()
	now := time.Now()
	p, err := BuildPlan(catalog, resolved, "plan-1", "inc-1", "web-1", "prometheus", "restart", now)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	drifted := testResolvedInventory()
	drifted.HostVars["web-1"] = map[string]any{"ansible_host": "10.0.0.99"}
	if _, err := VerifyPlanFresh(catalog, drifted, p); err == nil {
		t.Fatal("expected VerifyPlanFresh to reject a plan whose target host's address changed")
	}
}

// TestVerifyPlanFresh_TamperedExecutorTargetNeverReachesCaller locks in
// the exact bug found via a real MCP-handler test (2026-09-01): a caller
// who mutates p.ExecutorTarget WITHOUT recomputing p.PlanHash produces a
// Plan whose hash still matches (PlanHash never depended on the
// tampered copy in the first place — it's a fresh derivation). If a
// caller then executed against p directly, the tampered target would
// silently win. VerifyPlanFresh must return a plan whose ExecutorTarget
// is the contract-derived value, never p's own.
func TestVerifyPlanFresh_TamperedExecutorTargetNeverReachesCaller(t *testing.T) {
	catalog := testCatalog(t, testPrometheusContract())
	resolved := testResolvedInventory()
	p, err := BuildPlan(catalog, resolved, "plan-1", "inc-1", "web-1", "prometheus", "restart", time.Now())
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	tampered := p
	tampered.ExecutorTarget = "some-other-container"
	// PlanHash deliberately left untouched, exactly like a naive
	// tamperer (or a buggy client) would leave it.

	fresh, err := VerifyPlanFresh(catalog, resolved, tampered)
	if err != nil {
		t.Fatalf("VerifyPlanFresh: %v (hash matches because it was never derived from the tampered field)", err)
	}
	if fresh.ExecutorTarget != "pilot-prometheus" {
		t.Fatalf("fresh.ExecutorTarget = %q, want the contract-derived %q, not the tampered value", fresh.ExecutorTarget, "pilot-prometheus")
	}
}
