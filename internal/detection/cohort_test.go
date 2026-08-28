package detection

import (
	"math"
	"testing"
)

func gpuWorkerFeature() Feature {
	return Feature{Name: "cpu_utilization", Category: "cpu", ScaleFloor: 0.02, Cohort: true, ValidMin: 0, ValidMax: 1.05}
}

func TestCohort_ExcludesSubjectItself(t *testing.T) {
	subject := HostCycleSnapshot{Host: "gpu-1", Cohort: "gpu-workers-a", Current: map[string]float64{"cpu_utilization": 0.5}}
	allHosts := []HostCycleSnapshot{
		subject, // must never appear as its own peer, even though it's in the snapshot list
		{Host: "gpu-2", Cohort: "gpu-workers-a", Current: map[string]float64{"cpu_utilization": 0.4}},
		{Host: "gpu-3", Cohort: "gpu-workers-a", Current: map[string]float64{"cpu_utilization": 0.4}},
		{Host: "gpu-4", Cohort: "gpu-workers-a", Current: map[string]float64{"cpu_utilization": 0.4}},
	}
	peers := CohortPeerValues(subject, allHosts, "cpu_utilization")
	if len(peers) != 3 {
		t.Fatalf("peers = %v, want exactly the 3 OTHER hosts (subject excluded)", peers)
	}
	for _, v := range peers {
		if v == 0.5 {
			t.Fatalf("subject's own value leaked into its peer set: %v", peers)
		}
	}
}

func TestCohort_RequiresThreePeers(t *testing.T) {
	feature := gpuWorkerFeature()
	if r := ComputeCohortDistance(feature, []float64{0.1, 0.1}, 0.9); r.Ready {
		t.Error("2 peers must not be enough (min is 3)")
	}
	if r := ComputeCohortDistance(feature, []float64{0.1, 0.1, 0.1}, 0.9); !r.Ready {
		t.Error("3 peers must be enough")
	}
}

func TestCohort_UsesSameScoreMapping(t *testing.T) {
	feature := gpuWorkerFeature()
	feature.ValidMax = 1000
	// 3 peers at 10, 3 at 20 -> median=15, MAD=5, sigma=1.4826*5=7.413,
	// same math as TestRobustBaseline_MedianMADFormula, applied to a peer
	// set instead of history.
	peers := []float64{10, 10, 10, 20, 20, 20}
	const wantSigma = 1.4826 * 5
	const wantDistance = 5.5
	current := 15.0 + wantDistance*wantSigma

	result := ComputeCohortDistance(feature, peers, current)
	if !result.Ready {
		t.Fatal("expected Ready=true with 6 peers")
	}
	wantScore := (wantDistance - 3.5) / (8.0 - 3.5)
	if math.Abs(result.Score-wantScore) > 1e-9 {
		t.Errorf("score = %v, want %v (same 3.5/8.0 mapping as robust-baseline-v1)", result.Score, wantScore)
	}
}

func TestCohort_MissingPeerFeatureDoesNotBecomeZero(t *testing.T) {
	subject := HostCycleSnapshot{Host: "gpu-1", Cohort: "gpu-workers-a", Current: map[string]float64{"cpu_utilization": 0.9}}
	allHosts := []HostCycleSnapshot{
		subject,
		{Host: "gpu-2", Cohort: "gpu-workers-a", Current: map[string]float64{"cpu_utilization": 0.4}},
		{Host: "gpu-3", Cohort: "gpu-workers-a", Current: map[string]float64{"cpu_utilization": 0.4}},
		// gpu-4 has no cpu_utilization reading at all this cycle (invalid/missing).
		{Host: "gpu-4", Cohort: "gpu-workers-a", Current: map[string]float64{}},
	}
	peers := CohortPeerValues(subject, allHosts, "cpu_utilization")
	if len(peers) != 2 {
		t.Fatalf("peers = %v, want exactly 2 (missing peer must be omitted, not zero-filled)", peers)
	}
	for _, v := range peers {
		if v == 0 {
			t.Fatalf("a missing peer reading must never appear as a 0 value: %v", peers)
		}
	}
	// Only 2 real peers -> below minCohortPeers, so the feature must be
	// not-applicable, not scored against a phantom 0 for gpu-4.
	if r := ComputeCohortDistance(gpuWorkerFeature(), peers, 0.9); r.Ready {
		t.Error("2 real peers (one missing, correctly omitted) must not meet the 3-peer minimum")
	}
}
