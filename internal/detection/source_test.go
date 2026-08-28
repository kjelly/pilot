package detection

import (
	"math"
	"testing"
)

func testProfile() FeatureProfile {
	return FeatureProfile{
		ID:      "test-v1",
		Version: 1,
		Features: []Feature{
			{Name: "cpu_utilization", Required: true, Category: "cpu", ScaleFloor: 0.02, Cohort: true, ValidMin: 0, ValidMax: 1.05, PromQL: "x"},
			{Name: "memory_used_ratio", Required: true, Category: "memory", ScaleFloor: 0.02, Cohort: true, ValidMin: 0, ValidMax: 1, PromQL: "x"},
			{Name: "thermal_max_celsius", Required: false, Category: "thermal", ScaleFloor: 2.0, Cohort: true, ValidMin: -50, ValidMax: 200, PromQL: "x"},
		},
	}
}

func TestSource_MissingRequiredFeatureInvalidatesHostCycle(t *testing.T) {
	profile := testProfile()
	results := map[string]FeatureSampleResult{
		"cpu_utilization":   {Feature: "cpu_utilization", Value: 0.5, Validity: ValidityValid},
		"memory_used_ratio": {Feature: "memory_used_ratio", Validity: ValidityMissing},
	}
	if HostCycleValid(profile, results) {
		t.Fatal("a missing required feature must invalidate the whole host cycle")
	}
}

func TestSource_OptionalThermalMissingDoesNotInvalidateCore(t *testing.T) {
	profile := testProfile()
	results := map[string]FeatureSampleResult{
		"cpu_utilization":   {Feature: "cpu_utilization", Value: 0.5, Validity: ValidityValid},
		"memory_used_ratio": {Feature: "memory_used_ratio", Value: 0.5, Validity: ValidityValid},
		// thermal_max_celsius entirely absent from results.
	}
	if !HostCycleValid(profile, results) {
		t.Fatal("a missing OPTIONAL feature (thermal) must not invalidate the core cycle")
	}
}

func TestSource_DuplicateSeriesIsInvalid(t *testing.T) {
	feature := cpuFeature()
	samples := []RawSample{{Timestamp: 1000, Value: 0.5}, {Timestamp: 1000, Value: 0.6}}
	_, validity := ClassifySample(samples, 1000, feature)
	if validity != ValidityAmbiguousSeries {
		t.Fatalf("validity = %q, want ambiguous_series for >1 sample", validity)
	}
}

func TestSource_StaleAfter45Seconds(t *testing.T) {
	feature := cpuFeature()
	const evalTime = int64(1_000_000)

	// evaluation - timestamp == 45 exactly: spec uses strict ">45", so
	// this must still be valid.
	_, validity := ClassifySample([]RawSample{{Timestamp: evalTime - 45, Value: 0.5}}, evalTime, feature)
	if validity != ValidityValid {
		t.Errorf("exactly 45s old = %q, want valid (boundary is strict >45)", validity)
	}

	_, validity = ClassifySample([]RawSample{{Timestamp: evalTime - 46, Value: 0.5}}, evalTime, feature)
	if validity != ValidityStale {
		t.Errorf("46s old = %q, want stale", validity)
	}
}

func TestSource_FutureMoreThan5SecondsInvalid(t *testing.T) {
	feature := cpuFeature()
	const evalTime = int64(1_000_000)

	// timestamp == evaluation + 5 exactly: spec uses strict ">5", so this
	// must still be valid.
	_, validity := ClassifySample([]RawSample{{Timestamp: evalTime + 5, Value: 0.5}}, evalTime, feature)
	if validity != ValidityValid {
		t.Errorf("exactly 5s in the future = %q, want valid (boundary is strict >5)", validity)
	}

	_, validity = ClassifySample([]RawSample{{Timestamp: evalTime + 6, Value: 0.5}}, evalTime, feature)
	if validity != ValidityFutureSample {
		t.Errorf("6s in the future = %q, want future_sample", validity)
	}
}

func TestSource_NaNInfInvalid(t *testing.T) {
	feature := cpuFeature()
	const evalTime = int64(1_000_000)

	_, validity := ClassifySample([]RawSample{{Timestamp: evalTime, Value: math.NaN()}}, evalTime, feature)
	if validity != ValidityNonFinite {
		t.Errorf("NaN = %q, want non_finite", validity)
	}

	_, validity = ClassifySample([]RawSample{{Timestamp: evalTime, Value: math.Inf(1)}}, evalTime, feature)
	if validity != ValidityNonFinite {
		t.Errorf("+Inf = %q, want non_finite", validity)
	}
}
