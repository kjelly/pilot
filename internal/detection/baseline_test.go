package detection

import (
	"math"
	"testing"
)

func cpuFeature() Feature {
	return Feature{Name: "cpu_utilization", Category: "cpu", ScaleFloor: 0.02, Cohort: true, ValidMin: 0, ValidMax: 1.05}
}

func TestRobustBaseline_ColdStartBelow120IsInvalid(t *testing.T) {
	history := make([]float64, 119)
	for i := range history {
		history[i] = 0.5
	}
	result := ComputeRobustBaseline(cpuFeature(), history, 0.9)
	if result.Ready {
		t.Fatalf("119 buckets must be cold-start (not ready), got Ready=true: %+v", result)
	}

	history = append(history, 0.5) // now exactly 120
	result = ComputeRobustBaseline(cpuFeature(), history, 0.9)
	if !result.Ready {
		t.Fatalf("120 buckets must be ready, got Ready=false")
	}
}

func TestRobustBaseline_MedianMADFormula(t *testing.T) {
	// 60 copies of 10, 60 copies of 20 -> median=15, MAD=5 (every
	// deviation from 15 is exactly 5), sigma=1.4826*5=7.413 (both floors
	// are smaller: scaleFloor=0.02, relative floor=15*0.01=0.15).
	history := make([]float64, 0, 120)
	for i := 0; i < 60; i++ {
		history = append(history, 10.0)
	}
	for i := 0; i < 60; i++ {
		history = append(history, 20.0)
	}
	feature := cpuFeature()
	feature.ValidMax = 1000 // widen so the engineered "current" below stays in-range

	const wantSigma = 1.4826 * 5
	const wantDistance = 5.5
	current := 15.0 + wantDistance*wantSigma

	result := ComputeRobustBaseline(feature, history, current)
	if !result.Ready {
		t.Fatalf("expected Ready=true with 120 buckets")
	}
	if math.Abs(result.Median-15.0) > 1e-9 {
		t.Errorf("median = %v, want 15", result.Median)
	}
	if math.Abs(result.Sigma-wantSigma) > 1e-9 {
		t.Errorf("sigma = %v, want %v", result.Sigma, wantSigma)
	}
	if math.Abs(result.Distance-wantDistance) > 1e-9 {
		t.Errorf("distance = %v, want %v", result.Distance, wantDistance)
	}
	wantScore := (wantDistance - 3.5) / (8.0 - 3.5)
	if math.Abs(result.Score-wantScore) > 1e-9 {
		t.Errorf("score = %v, want %v", result.Score, wantScore)
	}
}

func TestRobustBaseline_ZeroMADUsesScaleFloor(t *testing.T) {
	history := make([]float64, 120)
	for i := range history {
		history[i] = 10.0 // identical -> MAD=0
	}
	feature := cpuFeature()
	feature.ScaleFloor = 2.0 // deliberately larger than the 0.1 relative floor
	feature.ValidMax = 1000

	result := ComputeRobustBaseline(feature, history, 10.0)
	if !result.Ready {
		t.Fatal("expected Ready=true")
	}
	if result.Sigma != feature.ScaleFloor {
		t.Errorf("sigma = %v, want scaleFloor %v (1.4826*MAD=0, relative floor=0.1, both smaller)", result.Sigma, feature.ScaleFloor)
	}
}

func TestRobustBaseline_RelativeFloorWinsWhenLarger(t *testing.T) {
	history := make([]float64, 120)
	for i := range history {
		history[i] = 1000.0 // identical -> MAD=0; relative floor = 1000*0.01 = 10
	}
	feature := cpuFeature()
	feature.ScaleFloor = 0.02 // much smaller than the relative floor
	feature.ValidMax = 100000

	result := ComputeRobustBaseline(feature, history, 1000.0)
	if !result.Ready {
		t.Fatal("expected Ready=true")
	}
	const wantSigma = 10.0
	if math.Abs(result.Sigma-wantSigma) > 1e-9 {
		t.Errorf("sigma = %v, want relative floor %v", result.Sigma, wantSigma)
	}
}

func TestRobustBaseline_ScoreBelow3Point5IsZero(t *testing.T) {
	for _, d := range []float64{0, 1.0, 2.0, 3.5} {
		if got := scoreFromDistance(d); got != 0 {
			t.Errorf("scoreFromDistance(%v) = %v, want 0", d, got)
		}
	}
}

func TestRobustBaseline_ScoreAt8IsOne(t *testing.T) {
	for _, d := range []float64{8.0, 8.5, 100.0} {
		if got := scoreFromDistance(d); got != 1 {
			t.Errorf("scoreFromDistance(%v) = %v, want 1", d, got)
		}
	}
}

func TestBaselineUpdate_FreezesAtCandidateThreshold(t *testing.T) {
	if ShouldUpdateBaseline(StateNormal, 0.65, true) {
		t.Error("score exactly at the candidate threshold (0.65) must freeze the baseline, not update it")
	}
	if !ShouldUpdateBaseline(StateNormal, 0.649999, true) {
		t.Error("score just below the candidate threshold must allow the baseline to update")
	}
	if ShouldUpdateBaseline(StateNormal, 0.9, true) {
		t.Error("score above threshold must freeze")
	}
	if ShouldUpdateBaseline(StateNormal, 0.1, false) {
		t.Error("an invalid/missing required feature must freeze the whole host baseline")
	}
}

func TestBaselineUpdate_FreezesWhileFiringAndRecovering(t *testing.T) {
	for _, state := range []LifecycleState{StateCandidate, StateFiring, StateRecovering} {
		if ShouldUpdateBaseline(state, 0.1, true) {
			t.Errorf("state=%s with a low score must still freeze (only normal updates the baseline)", state)
		}
	}
}

func TestBaselineWindow_KeepsLatestSamplePerUTCMinute(t *testing.T) {
	store := NewHostBaselineStore()
	const t0 = int64(1_700_000_000) // arbitrary minute-aligned-ish base
	minuteStart := (t0 / 60) * 60

	store.Observe("web-1", "cpu_utilization", minuteStart+5, 0.10)
	store.Observe("web-1", "cpu_utilization", minuteStart+35, 0.20) // same minute, later evaluation_time

	history := store.History("web-1", "cpu_utilization")
	if len(history) != 1 {
		t.Fatalf("expected exactly one bucket for one UTC minute, got %d: %v", len(history), history)
	}
	if history[0] != 0.20 {
		t.Errorf("expected the LATER sample (0.20) to win, got %v", history[0])
	}
}

func TestBaselineWindow_EvictsOlderThan24Hours(t *testing.T) {
	store := NewHostBaselineStore()
	base := (int64(1_700_000_000) / 60) * 60 // minute-aligned, so bucketOf(base) == base

	store.Observe("web-1", "cpu_utilization", base, 0.5)

	// Exactly 24h later: bucket_time == evaluationTime-24h, spec's rule is
	// strictly "<", so this must NOT evict yet.
	store.Evict("web-1", "cpu_utilization", base+baselineWindowSeconds)
	if len(store.History("web-1", "cpu_utilization")) != 1 {
		t.Fatal("a bucket exactly 24h old must not be evicted yet (spec uses strict <)")
	}

	// One second past 24h: must evict.
	store.Evict("web-1", "cpu_utilization", base+baselineWindowSeconds+1)
	if len(store.History("web-1", "cpu_utilization")) != 0 {
		t.Fatal("a bucket older than 24h must be evicted")
	}
}
