package detection

// minCohortPeers is the minimum number of same-cohort peers (excluding the
// subject itself) a feature needs before cohort-outlier-v1 can score it
// (spec §17).
const minCohortPeers = 3

// ComputeCohortDistance implements cohort-outlier-v1 (spec §17): the same
// median/MAD/sigma/distance/score math as robust-baseline-v1, applied to a
// peer set instead of the subject's own history.
func ComputeCohortDistance(feature Feature, peerValues []float64, current float64) RobustBaselineResult {
	if len(peerValues) < minCohortPeers {
		return RobustBaselineResult{Ready: false}
	}
	return computeDistanceScore(feature, peerValues, current)
}

// HostCycleSnapshot is one host's cohort membership and this cycle's valid
// feature readings — the shape CohortPeerValues and the engine's cycle
// loop need to select peers.
type HostCycleSnapshot struct {
	Host    string
	Cohort  string
	Current map[string]float64 // only features valid this cycle are present
}

// CohortPeerValues selects the same-cohort, self-excluded peer values for
// one feature (spec §17). A peer missing a valid reading for the feature
// is simply omitted — never treated as a 0 reading (spec: "missing peer
// feature does not become zero").
func CohortPeerValues(subject HostCycleSnapshot, allHosts []HostCycleSnapshot, feature string) []float64 {
	if subject.Cohort == "" {
		return nil
	}
	var out []float64
	for _, peer := range allHosts {
		if peer.Host == subject.Host || peer.Cohort != subject.Cohort {
			continue
		}
		if v, ok := peer.Current[feature]; ok {
			out = append(out, v)
		}
	}
	return out
}

// ComputeCohortHostScore evaluates cohort-outlier-v1 across every
// cohort-eligible feature the subject has a valid reading for this cycle
// (spec §17). If the subject has no cohort, or no feature meets
// minCohortPeers, the result is Valid=false ("not applicable" — never a
// bare score of 0).
func ComputeCohortHostScore(profile FeatureProfile, subject HostCycleSnapshot, allHosts []HostCycleSnapshot) HostFeatureScoreResult {
	var scored []Contributor
	for name, value := range subject.Current {
		feature, ok := profile.Feature(name)
		if !ok || !feature.Cohort {
			continue
		}
		peers := CohortPeerValues(subject, allHosts, name)
		result := ComputeCohortDistance(feature, peers, value)
		if !result.Ready {
			continue
		}
		scored = append(scored, Contributor{Feature: name, Category: feature.Category, Score: result.Score})
	}
	return aggregateFeatureScores(scored)
}
