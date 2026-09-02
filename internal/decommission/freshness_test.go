package decommission

import (
	"context"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

// TestFreshness_StaleInputInvalidatesApply proves HD4/INV-3: a plan
// derived once, then re-checked after hosts.yml changed on disk, is
// detected as stale — the caller must re-plan, never execute the old
// hash's fields.
func TestFreshness_StaleInputInvalidatesApply(t *testing.T) {
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("web1", "10.0.0.5", []string{"freeipa-client"}, "    env: sandbox\n"))
	catalog := newCatalog(t, contract.Contract{ID: "freeipa-client", Role: "freeipa-client"})

	in := PlanInput{WorkspaceDir: dir, HostName: "web1", Catalog: catalog, Now: fixedNow}
	plan, err := PlanHost(context.Background(), in)
	if err != nil {
		t.Fatalf("PlanHost() error = %v", err)
	}

	// Freshness holds when nothing changed.
	if _, err := CheckFreshness(context.Background(), in, plan.PlanHash); err != nil {
		t.Fatalf("CheckFreshness() on an unmodified workspace error = %v, want nil", err)
	}

	// Mutate a plan-bound input: change the host's role set.
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("web1", "10.0.0.5", []string{"freeipa-client", "docker"}, "    env: sandbox\n"))

	fresh, err := CheckFreshness(context.Background(), in, plan.PlanHash)
	if ClassOf(err) != ErrPlanStale {
		t.Fatalf("CheckFreshness() after hosts.yml changed error = %v, want class plan_stale", err)
	}
	if fresh == nil || fresh.PlanHash == plan.PlanHash {
		t.Fatalf("CheckFreshness() returned fresh=%+v, want a freshly re-derived plan with a DIFFERENT hash from the stale one", fresh)
	}

	// Also prove a benign, non-semantic change (whitespace/key reordering
	// that resolves to the same canonical inventory) does NOT report
	// stale — freshness must compare canonical hashes, not raw bytes.
	writeWorkspaceFile(t, dir, "hosts.yml", `hosts:
  web1:
    env: sandbox
    ansible_host: "10.0.0.5"
    roles:
      - freeipa-client
`)
	if _, err := CheckFreshness(context.Background(), in, plan.PlanHash); err != nil {
		t.Fatalf("CheckFreshness() after a semantically-identical rewrite error = %v, want nil", err)
	}
}
