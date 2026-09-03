package decommission

import (
	"context"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

// TestUnreachable_TemporaryBlocksLocalCleanup proves HD16/spec.md §21: an
// unreachable host with no offline disposition supplied blocks planning
// (must supply one), and temporarily_unreachable blocks every component
// step that would require local cleanup.
func TestUnreachable_TemporaryBlocksLocalCleanup(t *testing.T) {
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("h1", "10.0.0.1", []string{"freeipa-client"}, ""))
	catalog := newCatalog(t, contract.Contract{ID: "freeipa-client", Role: "freeipa-client"})

	t.Run("no disposition supplied blocks", func(t *testing.T) {
		plan, err := PlanHost(context.Background(), PlanInput{
			WorkspaceDir: dir, HostName: "h1", Catalog: catalog, Now: fixedNow,
			Reachability: ReachabilityUnreachable,
		})
		if err != nil {
			t.Fatalf("PlanHost() error = %v", err)
		}
		if !plan.Blocked() {
			t.Fatal("plan.Blocked() = false, want true — unreachable with no disposition must block")
		}
		found := false
		for _, b := range plan.Blockers {
			if b.Code == ErrHostUnreachable {
				found = true
			}
		}
		if !found {
			t.Fatalf("plan.Blockers = %+v, want one with Code=host_unreachable", plan.Blockers)
		}
	})

	t.Run("temporarily_unreachable blocks local cleanup", func(t *testing.T) {
		plan, err := PlanHost(context.Background(), PlanInput{
			WorkspaceDir: dir, HostName: "h1", Catalog: catalog, Now: fixedNow,
			Reachability:       ReachabilityUnreachable,
			OfflineDisposition: OfflineDispositionTemporarilyUnreachable,
		})
		if err != nil {
			t.Fatalf("PlanHost() error = %v", err)
		}
		// No plan-level host_unreachable blocker anymore (a disposition
		// WAS supplied) — but the component itself must now be blocked
		// because temporarily_unreachable blocks local cleanup.
		for _, b := range plan.Blockers {
			if b.Code == ErrHostUnreachable {
				t.Fatalf("plan-level Blockers = %+v, want no host_unreachable blocker once a disposition is supplied", plan.Blockers)
			}
		}
		if len(plan.Components) != 1 {
			t.Fatalf("Components = %+v, want exactly 1", plan.Components)
		}
		found := false
		for _, b := range plan.Components[0].Blockers {
			if b.Code == ErrHostUnreachable {
				found = true
			}
		}
		if !found {
			t.Fatalf("component blockers = %+v, want one with Code=host_unreachable (local cleanup blocked)", plan.Components[0].Blockers)
		}
		if plan.Components[0].LocalCleanupStatus == LocalCleanupUnavailableAttested {
			t.Fatal("LocalCleanupStatus = local_cleanup_unavailable_attested for a TEMPORARILY unreachable host — that status is reserved for permanently_lost")
		}
	})
}

// TestUnreachable_RequiresReachableHostFalseSkipsBlock proves spec.md
// §14.1 rule 4 (Phase 5): a component whose matched contract's typed
// Lifecycle.Decommission explicitly declares requiresReachableHost: false
// is NOT blocked by temporarily_unreachable and does NOT get
// local_cleanup_unavailable_attested for permanently_lost — its cleanup
// is entirely central, so host reachability is irrelevant to it, unlike
// the fail-closed default every other component (nil Decommission) still
// gets.
func TestUnreachable_RequiresReachableHostFalseSkipsBlock(t *testing.T) {
	centralOnly := &contract.DecommissionPolicy{Class: "stateless", RequiresReachableHost: false}
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("h1", "10.0.0.1", []string{"central-only-role", "freeipa-client"}, ""))
	catalog := newCatalog(t,
		contract.Contract{ID: "central-only", Role: "central-only-role", Lifecycle: contract.Lifecycle{Decommission: centralOnly}},
		contract.Contract{ID: "freeipa-client", Role: "freeipa-client"},
	)

	t.Run("temporarily_unreachable does not block the central-only component", func(t *testing.T) {
		plan, err := PlanHost(context.Background(), PlanInput{
			WorkspaceDir: dir, HostName: "h1", Catalog: catalog, Now: fixedNow,
			Reachability:       ReachabilityUnreachable,
			OfflineDisposition: OfflineDispositionTemporarilyUnreachable,
		})
		if err != nil {
			t.Fatalf("PlanHost() error = %v", err)
		}
		var centralOnlyCP, freeipaCP *ComponentPlan
		for i := range plan.Components {
			switch plan.Components[i].ComponentID {
			case "central-only":
				centralOnlyCP = &plan.Components[i]
			case "freeipa-client":
				freeipaCP = &plan.Components[i]
			}
		}
		if centralOnlyCP == nil || freeipaCP == nil {
			t.Fatalf("expected both components in plan, got %+v", plan.Components)
		}
		for _, b := range centralOnlyCP.Blockers {
			if b.Code == ErrHostUnreachable {
				t.Fatalf("central-only component (requiresReachableHost:false) blockers = %+v, want no host_unreachable blocker", centralOnlyCP.Blockers)
			}
		}
		found := false
		for _, b := range freeipaCP.Blockers {
			if b.Code == ErrHostUnreachable {
				found = true
			}
		}
		if !found {
			t.Fatalf("freeipa-client component (fail-closed default) blockers = %+v, want a host_unreachable blocker", freeipaCP.Blockers)
		}
	})

	t.Run("permanently_lost does not mark the central-only component unavailable-attested", func(t *testing.T) {
		plan, err := PlanHost(context.Background(), PlanInput{
			WorkspaceDir: dir, HostName: "h1", Catalog: catalog, Now: fixedNow,
			Reachability:       ReachabilityUnreachable,
			OfflineDisposition: OfflineDispositionPermanentlyLost,
		})
		if err != nil {
			t.Fatalf("PlanHost() error = %v", err)
		}
		for _, c := range plan.Components {
			if c.ComponentID == "central-only" && c.LocalCleanupStatus == LocalCleanupUnavailableAttested {
				t.Fatalf("central-only component (requiresReachableHost:false) LocalCleanupStatus = %q, want unset (its cleanup never needed local host access)", c.LocalCleanupStatus)
			}
			if c.ComponentID == "freeipa-client" && c.LocalCleanupStatus != LocalCleanupUnavailableAttested {
				t.Fatalf("freeipa-client component (fail-closed default) LocalCleanupStatus = %q, want %q", c.LocalCleanupStatus, LocalCleanupUnavailableAttested)
			}
		}
	})
}

// TestUnreachable_PermanentlyLostRecordsUnattested proves HD17/spec.md
// §21.2: a permanently-lost host records local cleanup as
// local_cleanup_unavailable_attested — never a fabricated "verified"
// status, since no verification actually ran.
func TestUnreachable_PermanentlyLostRecordsUnattested(t *testing.T) {
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("h1", "10.0.0.1", []string{"freeipa-client", "docker"}, ""))
	catalog := newCatalog(t,
		contract.Contract{ID: "freeipa-client", Role: "freeipa-client"},
		contract.Contract{ID: "docker", Role: "docker"},
	)

	plan, err := PlanHost(context.Background(), PlanInput{
		WorkspaceDir: dir, HostName: "h1", Catalog: catalog, Now: fixedNow,
		Reachability:       ReachabilityUnreachable,
		OfflineDisposition: OfflineDispositionPermanentlyLost,
	})
	if err != nil {
		t.Fatalf("PlanHost() error = %v", err)
	}
	if len(plan.Components) != 2 {
		t.Fatalf("Components = %+v, want exactly 2", plan.Components)
	}
	for _, c := range plan.Components {
		if c.LocalCleanupStatus != LocalCleanupUnavailableAttested {
			t.Fatalf("component %q LocalCleanupStatus = %q, want %q", c.Role, c.LocalCleanupStatus, LocalCleanupUnavailableAttested)
		}
		// The state machine must never claim a real verification ran —
		// this is the literal never-fabricated-verified_removed
		// assertion (spec.md §21.2). There is no "verified_removed"
		// constant anywhere in this package; the only legitimate status
		// besides the zero value is exactly LocalCleanupUnavailableAttested.
		if c.LocalCleanupStatus == "verified_removed" {
			t.Fatal("a permanently-lost host must never report local cleanup as verified_removed")
		}
	}
}
