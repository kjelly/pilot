package delivery

import (
	"reflect"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestResolveExecutionScope_RequiredReachable_Included(t *testing.T) {
	scope := ResolveExecutionScope([]CandidateHost{
		{Host: "ipa-1", Policy: inventory.DeploymentAvailabilityRequired, Reachable: true},
	})
	if !reflect.DeepEqual(scope.Included, []string{"ipa-1"}) {
		t.Fatalf("Included = %v, want [ipa-1]", scope.Included)
	}
	if len(scope.Blocking) != 0 || len(scope.Deferred) != 0 {
		t.Fatalf("unexpected blocking/deferred: %+v", scope)
	}
}

func TestResolveExecutionScope_RequiredUnavailable_Blocks(t *testing.T) {
	scope := ResolveExecutionScope([]CandidateHost{
		{Host: "ipa-1", Policy: inventory.DeploymentAvailabilityRequired, Reachable: false},
	})
	if !reflect.DeepEqual(scope.Blocking, []string{"ipa-1"}) {
		t.Fatalf("Blocking = %v, want [ipa-1]", scope.Blocking)
	}
	if len(scope.Included) != 0 || len(scope.Deferred) != 0 {
		t.Fatalf("unexpected included/deferred: %+v", scope)
	}
}

func TestResolveExecutionScope_OptionalReachable_Included(t *testing.T) {
	scope := ResolveExecutionScope([]CandidateHost{
		{Host: "vm-02", Policy: inventory.DeploymentAvailabilityOptional, Reachable: true},
	})
	if !reflect.DeepEqual(scope.Included, []string{"vm-02"}) {
		t.Fatalf("Included = %v, want [vm-02]", scope.Included)
	}
}

func TestResolveExecutionScope_OptionalUnavailable_Deferred(t *testing.T) {
	scope := ResolveExecutionScope([]CandidateHost{
		{Host: "vm-01", Policy: inventory.DeploymentAvailabilityOptional, Reachable: false},
	})
	if len(scope.Deferred) != 1 || scope.Deferred[0].Host != "vm-01" || scope.Deferred[0].Reason != DeferredUnavailable {
		t.Fatalf("Deferred = %+v, want one entry for vm-01/DeferredUnavailable", scope.Deferred)
	}
	if len(scope.Included) != 0 || len(scope.Blocking) != 0 {
		t.Fatalf("unexpected included/blocking: %+v", scope)
	}
}

func TestResolveExecutionScope_MissingPolicyUnavailable_Blocks(t *testing.T) {
	scope := ResolveExecutionScope([]CandidateHost{
		{Host: "ipa-2", Policy: "", Reachable: false},
	})
	if !reflect.DeepEqual(scope.Blocking, []string{"ipa-2"}) {
		t.Fatalf("Blocking = %v, want [ipa-2] (missing policy defaults to required)", scope.Blocking)
	}
}

func TestResolveExecutionScope_InvalidPolicy_AlwaysBlocks(t *testing.T) {
	scope := ResolveExecutionScope([]CandidateHost{
		{Host: "weird-1", Policy: "sometimes", Reachable: true, Invalid: true},
	})
	if !reflect.DeepEqual(scope.Blocking, []string{"weird-1"}) {
		t.Fatalf("Blocking = %v, want [weird-1] even though Reachable=true", scope.Blocking)
	}
}

func TestResolveExecutionScope_AllOptionalUnavailable_SuccessNoOp(t *testing.T) {
	scope := ResolveExecutionScope([]CandidateHost{
		{Host: "vm-01", Policy: inventory.DeploymentAvailabilityOptional, Reachable: false},
		{Host: "vm-02", Policy: inventory.DeploymentAvailabilityOptional, Reachable: false},
	})
	if len(scope.Blocking) != 0 {
		t.Fatalf("Blocking = %v, want none", scope.Blocking)
	}
	if scope.HasManagedHosts() {
		t.Fatalf("HasManagedHosts() = true, want false (nothing to deploy)")
	}
	if len(scope.Deferred) != 2 {
		t.Fatalf("Deferred = %+v, want 2 entries", scope.Deferred)
	}
}

func TestResolveExecutionScope_UnrelatedRequiredOfflineHostNotPassedInDoesNotBlock(t *testing.T) {
	// ipa-2 is required and offline, but the caller (candidate-scope
	// resolution: role/tag/--limit) determined it is unrelated to this
	// run and never includes it as a candidate at all. The resolver must
	// not go looking for it — it only ever sees what it's given.
	scope := ResolveExecutionScope([]CandidateHost{
		{Host: "dashboard-1", Policy: inventory.DeploymentAvailabilityRequired, Reachable: true},
	})
	if len(scope.Blocking) != 0 {
		t.Fatalf("Blocking = %v, want none — ipa-2 was never a candidate", scope.Blocking)
	}
}

func TestResolveExecutionScope_NoDuplicateHostNames(t *testing.T) {
	scope := ResolveExecutionScope([]CandidateHost{
		{Host: "vm-01", Policy: inventory.DeploymentAvailabilityOptional, Reachable: true},
		{Host: "vm-01", Policy: inventory.DeploymentAvailabilityOptional, Reachable: true},
	})
	if !reflect.DeepEqual(scope.Included, []string{"vm-01"}) {
		t.Fatalf("Included = %v, want a single [vm-01]", scope.Included)
	}
	if !reflect.DeepEqual(scope.Candidates, []string{"vm-01"}) {
		t.Fatalf("Candidates = %v, want a single [vm-01]", scope.Candidates)
	}
}

func TestResolveExecutionScope_StableOrderingRegardlessOfInputOrder(t *testing.T) {
	a := ResolveExecutionScope([]CandidateHost{
		{Host: "vm-03", Policy: inventory.DeploymentAvailabilityOptional, Reachable: true},
		{Host: "vm-01", Policy: inventory.DeploymentAvailabilityOptional, Reachable: true},
		{Host: "vm-02", Policy: inventory.DeploymentAvailabilityOptional, Reachable: true},
	})
	b := ResolveExecutionScope([]CandidateHost{
		{Host: "vm-01", Policy: inventory.DeploymentAvailabilityOptional, Reachable: true},
		{Host: "vm-02", Policy: inventory.DeploymentAvailabilityOptional, Reachable: true},
		{Host: "vm-03", Policy: inventory.DeploymentAvailabilityOptional, Reachable: true},
	})
	want := []string{"vm-01", "vm-02", "vm-03"}
	if !reflect.DeepEqual(a.Included, want) || !reflect.DeepEqual(b.Included, want) {
		t.Fatalf("Included not stably ordered: a=%v b=%v want=%v", a.Included, b.Included, want)
	}
}

func TestBuildEffectiveLimit_SiteContainsLocalhost(t *testing.T) {
	got := BuildEffectiveLimit("playbooks/site.yml", []string{"dev-vm-02", "ipa-1"})
	if want := "localhost,dev-vm-02,ipa-1"; got != want {
		t.Fatalf("BuildEffectiveLimit() = %q, want %q", got, want)
	}
}

func TestBuildEffectiveLimit_SingleComponentNoLocalhost(t *testing.T) {
	got := BuildEffectiveLimit("playbooks/apply/freeipa-client-apply.yml", []string{"dev-vm-02"})
	if want := "dev-vm-02"; got != want {
		t.Fatalf("BuildEffectiveLimit() = %q, want %q", got, want)
	}
}

func TestBuildEffectiveLimit_DeduplicatesAndSorts(t *testing.T) {
	got := BuildEffectiveLimit("playbooks/site.yml", []string{"ipa-1", "localhost", "ipa-1", "dev-vm-02"})
	if want := "localhost,dev-vm-02,ipa-1"; got != want {
		t.Fatalf("BuildEffectiveLimit() = %q, want %q", got, want)
	}
}

func TestBuildEffectiveLimit_EmptyIncludedHostsForSiteIsJustLocalhost(t *testing.T) {
	got := BuildEffectiveLimit("playbooks/site.yml", nil)
	if want := "localhost"; got != want {
		t.Fatalf("BuildEffectiveLimit() = %q, want %q", got, want)
	}
}
