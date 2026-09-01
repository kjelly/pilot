package repair

import (
	"context"
	"testing"
	"time"
)

func TestVerifyReapplyPlanFresh_DetectsStalePlan(t *testing.T) {
	root, relPath := reapplyTestRepoRoot(t)
	catalog := testCatalog(t, reapplyTestContract(relPath))
	resolved := reapplyTestResolvedInventory()
	preview := fakePreview(true, "PLAY RECAP ***\nweb-1 : ok=1 changed=0\n", 0, nil)

	p, err := BuildReapplyPlan(context.Background(), catalog, resolved, noDeps, preview,
		root, "/tmp/inv.yml", "plan-1", "inc-1", "web-1", "prometheus", "reapply", time.Now())
	if err != nil {
		t.Fatalf("BuildReapplyPlan: %v", err)
	}

	stale := p
	stale.PlanHash = "not-the-real-hash"
	if _, err := VerifyReapplyPlanFresh(context.Background(), catalog, resolved, noDeps, preview, root, "/tmp/inv.yml", stale); err == nil {
		t.Fatal("expected an error: plan hash no longer matches current resolution")
	}
}

// TestVerifyReapplyPlanFresh_TamperedPlaybookPathNeverReachesCaller locks
// in the SAME bug class Phase 3's VerifyPlanFresh fix addressed for R1
// (design doc §6's own plan-hash rationale): a caller who mutates
// p.Resolved.PlaybookPath WITHOUT recomputing p.PlanHash produces a plan
// whose hash still matches (the hash was never derived from the
// tampered copy). VerifyReapplyPlanFresh must return a plan whose
// PlaybookPath is the contract-derived value, never p's own — so a
// caller that (correctly, per this package's own doc comments) executes
// against the RETURNED plan can never be tricked into running a
// different playbook than the one that was actually approved.
func TestVerifyReapplyPlanFresh_TamperedPlaybookPathNeverReachesCaller(t *testing.T) {
	root, relPath := reapplyTestRepoRoot(t)
	catalog := testCatalog(t, reapplyTestContract(relPath))
	resolved := reapplyTestResolvedInventory()
	preview := fakePreview(true, "PLAY RECAP ***\nweb-1 : ok=1 changed=0\n", 0, nil)

	p, err := BuildReapplyPlan(context.Background(), catalog, resolved, noDeps, preview,
		root, "/tmp/inv.yml", "plan-1", "inc-1", "web-1", "prometheus", "reapply", time.Now())
	if err != nil {
		t.Fatalf("BuildReapplyPlan: %v", err)
	}

	tampered := p
	tampered.Resolved.PlaybookPath = "playbooks/apply/some-other-dangerous-playbook.yml"
	// PlanHash deliberately left untouched, exactly like a naive
	// tamperer (or a buggy client) would leave it.

	fresh, err := VerifyReapplyPlanFresh(context.Background(), catalog, resolved, noDeps, preview, root, "/tmp/inv.yml", tampered)
	if err != nil {
		t.Fatalf("VerifyReapplyPlanFresh: %v (hash matches because it was never derived from the tampered field)", err)
	}
	if fresh.Resolved.PlaybookPath != relPath {
		t.Fatalf("fresh.Resolved.PlaybookPath = %q, want the contract-derived %q, not the tampered value", fresh.Resolved.PlaybookPath, relPath)
	}
}
