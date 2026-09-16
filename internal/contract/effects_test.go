package contract

import (
	"strings"
	"testing"
)

// minimalValidContract returns a Contract that satisfies every
// validateLocal rule except Effects, so effects-specific tests can focus
// purely on that field. verification.autoDeploy is false so LoadFile's
// autoDeploy spec-existence check never fires.
func minimalValidContract() Contract {
	autoDeploy := false
	return Contract{
		SchemaVersion: SchemaVersion,
		ID:            "fixture-component",
		Role:          "fixture-role",
		Specs: []Spec{
			{Path: "docs/verification/fixture.md", Rows: RowSelector{All: true}},
		},
		Playbooks:       Playbooks{Apply: "playbooks/apply/fixture-apply.yml"},
		HostCardinality: "one-or-more",
		StagePolicy:     StagePolicy{Variable: "stage", Default: "sandbox"},
		EvidenceRequirement: Evidence{
			TargetTest:  "vm",
			Idempotency: "required",
		},
		Verification: Verification{AutoDeploy: &autoDeploy},
	}
}

// TestContractEffects_E1 (design spec §46.2 E1): a contract with a valid
// subset of known effects loads without error.
func TestContractEffects_E1(t *testing.T) {
	c := minimalValidContract()
	c.Effects = []Effect{EffectIdentityUsers, EffectAccessHBAC}
	if err := validateLocal(c); err != nil {
		t.Fatalf("validateLocal: %v", err)
	}
}

// TestContractEffects_E2 (design spec §46.2 E2): a duplicate effect is
// rejected.
func TestContractEffects_E2(t *testing.T) {
	c := minimalValidContract()
	c.Effects = []Effect{EffectAccessHBAC, EffectAccessHBAC}
	err := validateLocal(c)
	if err == nil {
		t.Fatal("expected error for duplicate effect, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "duplicate") {
		t.Fatalf("error = %q, want mention of duplicate", got)
	}
}

// TestContractEffects_E3 (design spec §46.2 E3): an unknown effect string
// is rejected — this is the typo-safety guarantee §6.3 requires.
func TestContractEffects_E3(t *testing.T) {
	c := minimalValidContract()
	c.Effects = []Effect{"freeipa-identity"}
	err := validateLocal(c)
	if err == nil {
		t.Fatal("expected error for unknown effect, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "unknown") {
		t.Fatalf("error = %q, want mention of unknown", got)
	}
}

// TestContractEffects_NoEffectsIsValid documents that Effects is
// additive/optional (spec §6.1) — a component that declares none is not
// an error.
func TestContractEffects_NoEffectsIsValid(t *testing.T) {
	c := minimalValidContract()
	if err := validateLocal(c); err != nil {
		t.Fatalf("validateLocal with zero effects: %v", err)
	}
}

// TestContractEffects_KnownEffectsRoundTrip locks that every value
// KnownEffects() returns is itself accepted.
func TestContractEffects_KnownEffectsRoundTrip(t *testing.T) {
	c := minimalValidContract()
	c.Effects = KnownEffects()
	if err := validateLocal(c); err != nil {
		t.Fatalf("validateLocal with every known effect: %v", err)
	}
}
