package detection

import "testing"

func TestFeatureProfile_EffectiveIdentity_DefaultsToManagedHost(t *testing.T) {
	p := FeatureProfile{ID: "linux-host-v1", Version: 1}
	id := p.EffectiveIdentity()
	if id.Label != "pilot_host" || id.Kind != SubjectKindManagedHost || id.SiteLabel != "site" {
		t.Fatalf("EffectiveIdentity() = %+v, want the spec §9.3 managed-host default", id)
	}
	if id.CohortLabel != "" {
		t.Fatalf("default CohortLabel must be empty, got %q", id.CohortLabel)
	}
}

func TestFeatureProfile_EffectiveIdentity_ExplicitProfileOverrides(t *testing.T) {
	p := FeatureProfile{
		ID: "network-device-ifmib-v1", Version: 1,
		Identity: IdentityProfile{Label: "pilot_target", Kind: "network_device", SiteLabel: "site", CohortLabel: "detection_cohort"},
	}
	id := p.EffectiveIdentity()
	if id.Label != "pilot_target" || id.Kind != "network_device" || id.CohortLabel != "detection_cohort" {
		t.Fatalf("EffectiveIdentity() = %+v, want the explicit SNMP profile values unchanged", id)
	}
}

func TestFeatureProfile_MaxSampleAge_DefaultsTo45Seconds(t *testing.T) {
	p := FeatureProfile{ID: "linux-host-v1", Version: 1}
	if got := p.MaxSampleAge(); got.Seconds() != 45 {
		t.Fatalf("MaxSampleAge() = %v, want 45s (spec §9.3 backward-compatible default)", got)
	}
	if got := p.FutureSkewTolerance(); got.Seconds() != 5 {
		t.Fatalf("FutureSkewTolerance() = %v, want 5s", got)
	}
}

func TestFeatureProfile_MaxSampleAge_ExplicitOverride(t *testing.T) {
	p := FeatureProfile{ID: "network-device-ifmib-v1", Version: 1, Sampling: SamplingProfile{MaxSampleAge: "90s", FutureSkewTolerance: "5s"}}
	if got := p.MaxSampleAge(); got.Seconds() != 90 {
		t.Fatalf("MaxSampleAge() = %v, want 90s", got)
	}
}

func TestFeatureProfile_Validate_RejectsUnparsableSamplingDuration(t *testing.T) {
	p := FeatureProfile{
		ID: "x", Version: 1, Sampling: SamplingProfile{MaxSampleAge: "not-a-duration"},
		Features: []Feature{{Name: "f", Required: true, ScaleFloor: 0.1, ValidMin: 0, ValidMax: 1, PromQL: "x"}},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected an error for an unparsable sampling.maxSampleAge")
	}
}

func TestParseFeatureProfile_SNMPIdentityRoundTrips(t *testing.T) {
	data := []byte(`
id: network-device-ifmib-v1
version: 1
identity:
  label: pilot_target
  kind: network_device
  siteLabel: site
  cohortLabel: detection_cohort
sampling:
  maxSampleAge: 90s
  futureSkewTolerance: 5s
features:
  - name: interface_error_rate
    required: true
    category: network_error
    scaleFloor: 0.01
    cohort: true
    validMin: 0
    validMax: 1000000
    promql: 'sum(ifInErrors)'
`)
	p, err := ParseFeatureProfile(data)
	if err != nil {
		t.Fatalf("ParseFeatureProfile: %v", err)
	}
	id := p.EffectiveIdentity()
	if id.Label != "pilot_target" || id.Kind != "network_device" || id.CohortLabel != "detection_cohort" {
		t.Fatalf("parsed identity = %+v, want the SNMP profile values", id)
	}
	if p.MaxSampleAge().Seconds() != 90 {
		t.Fatalf("MaxSampleAge() = %v, want 90s", p.MaxSampleAge())
	}
}
