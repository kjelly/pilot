package accessgrants

import (
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestPlanAuthPolicyPrune_NoPriorStateYieldsNothing(t *testing.T) {
	dir := t.TempDir()
	desired := []inventory.CompiledAuthPolicyHost{{Host: "gpu01.ipa.pilot.internal", Indicators: []string{"otp"}}}
	prune, err := planAuthPolicyPrune(dir, desired)
	if err != nil {
		t.Fatalf("planAuthPolicyPrune() error = %v", err)
	}
	if len(prune) != 0 {
		t.Fatalf("prune = %+v, want none — nothing was ever recorded", prune)
	}
}

func TestPlanAuthPolicyPrune_HostDroppedFromDesiredIsPruned(t *testing.T) {
	dir := t.TempDir()
	if err := recordAuthPolicyState(dir, []inventory.CompiledAuthPolicyHost{
		{Host: "gpu01.ipa.pilot.internal", Indicators: []string{"otp", "pkinit"}},
		{Host: "gpu02.ipa.pilot.internal", Indicators: []string{"otp"}},
	}); err != nil {
		t.Fatalf("recordAuthPolicyState() error = %v", err)
	}

	// gpu01's auth_policies entry stays; gpu02's was removed from the roster.
	desired := []inventory.CompiledAuthPolicyHost{{Host: "gpu01.ipa.pilot.internal", Indicators: []string{"otp", "pkinit"}}}
	prune, err := planAuthPolicyPrune(dir, desired)
	if err != nil {
		t.Fatalf("planAuthPolicyPrune() error = %v", err)
	}
	if len(prune) != 1 || prune[0].Host != "gpu02.ipa.pilot.internal" {
		t.Fatalf("prune = %+v, want exactly gpu02.ipa.pilot.internal", prune)
	}
	if len(prune[0].Indicators) != 0 {
		t.Fatalf("prune[0].Indicators = %v, want empty (explicit clear)", prune[0].Indicators)
	}
}

func TestPlanAuthPolicyPrune_HostStillDesiredIsNotPruned(t *testing.T) {
	dir := t.TempDir()
	if err := recordAuthPolicyState(dir, []inventory.CompiledAuthPolicyHost{
		{Host: "gpu01.ipa.pilot.internal", Indicators: []string{"otp"}},
	}); err != nil {
		t.Fatalf("recordAuthPolicyState() error = %v", err)
	}
	desired := []inventory.CompiledAuthPolicyHost{{Host: "gpu01.ipa.pilot.internal", Indicators: []string{"otp"}}}
	prune, err := planAuthPolicyPrune(dir, desired)
	if err != nil {
		t.Fatalf("planAuthPolicyPrune() error = %v", err)
	}
	if len(prune) != 0 {
		t.Fatalf("prune = %+v, want none — gpu01 is still governed", prune)
	}
}

func TestRecordAuthPolicyState_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := []inventory.CompiledAuthPolicyHost{{Host: "gpu01.ipa.pilot.internal", Indicators: []string{"otp", "pkinit"}}}
	if err := recordAuthPolicyState(dir, want); err != nil {
		t.Fatalf("recordAuthPolicyState() error = %v", err)
	}
	store, err := openAuthPolicyStore(dir)
	if err != nil {
		t.Fatalf("openAuthPolicyStore() error = %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(got) != 1 || got[0].Host != "gpu01.ipa.pilot.internal" || len(got[0].Indicators) != 2 {
		t.Fatalf("got = %+v, want one record matching %+v", got, want)
	}
}
