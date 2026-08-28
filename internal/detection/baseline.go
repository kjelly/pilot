package detection

import (
	"math"
	"sort"
)

// Distance thresholds shared by robust-baseline-v1 (spec §15) and
// cohort-outlier-v1 (spec §17) — both use the exact same 3.5/8.0 mapping.
const (
	scoreZeroDistance = 3.5
	scoreOneDistance  = 8.0
)

// minReadyBuckets is the minimum number of one-minute history buckets a
// feature needs before its baseline detector is anything but "learning"
// (spec §14.1).
const minReadyBuckets = 120

// maxHistoryBuckets bounds bootstrap ingestion to the last 24h of one-minute
// buckets (spec §14.1).
const maxHistoryBuckets = 1440

// baselineWindow is the eviction horizon for runtime history buckets
// (spec §14.2).
const baselineWindowSeconds = 24 * 60 * 60

// HostBaselineStore holds the rolling one-minute-bucketed history each
// feature of each host needs for robust-baseline-v1 (spec §14).
type HostBaselineStore struct {
	hosts map[string]map[string]map[int64]float64 // host -> feature -> bucket_ts -> value
}

// NewHostBaselineStore returns an empty store.
func NewHostBaselineStore() *HostBaselineStore {
	return &HostBaselineStore{hosts: map[string]map[string]map[int64]float64{}}
}

// BucketOf rounds evaluationTime down to its containing one-minute bucket
// — exported so callers persisting samples (Store.SaveBaselineSamples) use
// the exact same bucketing Observe does.
func BucketOf(evaluationTime int64) int64 {
	return (evaluationTime / 60) * 60
}

func (s *HostBaselineStore) featureBuckets(host, feature string) map[int64]float64 {
	f, ok := s.hosts[host]
	if !ok {
		f = map[string]map[int64]float64{}
		s.hosts[host] = f
	}
	b, ok := f[feature]
	if !ok {
		b = map[int64]float64{}
		f[feature] = b
	}
	return b
}

// Bootstrap seeds a feature's history from a Prometheus range-query result
// (spec §14.1: 24h lookback, 60s step, at most 1440 buckets). Samples are
// bucketed the same way runtime Observe calls are, so a bootstrap sample
// and a subsequent Observe in the same minute compose correctly.
func (s *HostBaselineStore) Bootstrap(host, feature string, samples []RawSample) {
	buckets := s.featureBuckets(host, feature)
	for _, sm := range samples {
		buckets[BucketOf(sm.Timestamp)] = sm.Value
	}
	// Bound to the newest maxHistoryBuckets entries in case the caller
	// handed us more than 24h of samples.
	if len(buckets) > maxHistoryBuckets {
		keys := make([]int64, 0, len(buckets))
		for k := range buckets {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] > keys[j] })
		for _, k := range keys[maxHistoryBuckets:] {
			delete(buckets, k)
		}
	}
}

// Observe records one runtime-valid sample for (host, feature) at
// evaluationTime, downsampled to at most one value per UTC minute. Because
// the engine's scheduler calls Observe with monotonically increasing
// evaluationTime values, a later call within the same minute naturally
// overwrites an earlier one — satisfying spec §14.2's "keep the sample
// with the largest evaluation timestamp" rule without tracking timestamps
// separately. Callers must gate this behind the contamination-protection
// check in ShouldUpdateBaseline (spec §16) themselves.
func (s *HostBaselineStore) Observe(host, feature string, evaluationTime int64, value float64) {
	s.featureBuckets(host, feature)[BucketOf(evaluationTime)] = value
}

// Evict drops buckets older than 24h relative to evaluationTime (spec §14.2).
func (s *HostBaselineStore) Evict(host, feature string, evaluationTime int64) {
	buckets := s.featureBuckets(host, feature)
	cutoff := evaluationTime - baselineWindowSeconds
	for ts := range buckets {
		if ts < cutoff {
			delete(buckets, ts)
		}
	}
}

// LoadSample directly sets one bucket's value — the warm-start path
// (Store.LoadBaselineHistory) that repopulates a fresh HostBaselineStore
// from persisted baseline_samples rows after a process restart, so
// robust-baseline-v1 doesn't cold-start its 120-bucket requirement (spec
// §14.1) every time the daemon restarts.
func (s *HostBaselineStore) LoadSample(host, feature string, bucketTS int64, value float64) {
	s.featureBuckets(host, feature)[bucketTS] = value
}

// History returns the current history values for (host, feature) in no
// particular order — robust-baseline-v1 only needs the multiset of values.
func (s *HostBaselineStore) History(host, feature string) []float64 {
	buckets := s.featureBuckets(host, feature)
	out := make([]float64, 0, len(buckets))
	for _, v := range buckets {
		out = append(out, v)
	}
	return out
}

// median is the standard statistical median: the middle value for an odd
// count, the average of the two middle values for an even count.
func median(xs []float64) float64 {
	n := len(xs)
	if n == 0 {
		return 0
	}
	sorted := append([]float64(nil), xs...)
	sort.Float64s(sorted)
	mid := n / 2
	if n%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

func medianAbsoluteDeviation(xs []float64, m float64) float64 {
	dev := make([]float64, len(xs))
	for i, x := range xs {
		dev[i] = math.Abs(x - m)
	}
	return median(dev)
}

// scoreFromDistance is the shared 3.5/8.0 linear mapping used by both
// robust-baseline-v1 (spec §15) and cohort-outlier-v1 (spec §17).
func scoreFromDistance(d float64) float64 {
	switch {
	case d <= scoreZeroDistance:
		return 0
	case d >= scoreOneDistance:
		return 1
	default:
		return (d - scoreZeroDistance) / (scoreOneDistance - scoreZeroDistance)
	}
}

// RobustBaselineResult is one feature's robust-baseline-v1 evaluation
// (spec §15).
type RobustBaselineResult struct {
	// Ready is false when history has fewer than 120 valid buckets — the
	// feature's baseline detector is "learning" and invalid for scoring
	// (spec §14.1). All other fields are zero in that case.
	Ready    bool
	Median   float64
	Sigma    float64
	Distance float64
	Score    float64
}

// computeDistanceScore is the median/MAD/sigma/distance/score math shared
// by robust-baseline-v1 (spec §15, applied to a host's own history) and
// cohort-outlier-v1 (spec §17, applied to a peer set) — identical formula,
// different minimum-sample-count gate applied by each caller.
func computeDistanceScore(feature Feature, values []float64, current float64) RobustBaselineResult {
	m := median(values)
	mad := medianAbsoluteDeviation(values, m)
	sigma := math.Max(1.4826*mad, math.Max(feature.ScaleFloor, math.Abs(m)*0.01))
	d := math.Abs(current-m) / sigma
	return RobustBaselineResult{
		Ready:    true,
		Median:   m,
		Sigma:    sigma,
		Distance: d,
		Score:    scoreFromDistance(d),
	}
}

// ComputeRobustBaseline implements spec §15 exactly: median/MAD scale with
// a scale_floor and relative floor, distance, and the 3.5/8.0 score mapping.
func ComputeRobustBaseline(feature Feature, history []float64, current float64) RobustBaselineResult {
	if len(history) < minReadyBuckets {
		return RobustBaselineResult{Ready: false}
	}
	return computeDistanceScore(feature, history, current)
}

// Contributor is one feature's contribution to a host's aggregate score
// (baseline or cohort), used to pick the top-5 reported contributors and
// the category hint (spec §15/§17).
type Contributor struct {
	Feature  string
	Category string
	Score    float64
}

// HostFeatureScoreResult is a host's aggregate detector score across all of
// its scoreable features, plus the reporting metadata derived from it.
type HostFeatureScoreResult struct {
	// Valid is false when no feature had enough ready history/peers to
	// contribute at all — the whole detector is invalid for this host this
	// cycle, not merely scored 0 (spec §15/§17).
	Valid        bool
	Score        float64
	Contributors []Contributor
	Category     string
}

// aggregateFeatureScores implements the shared "max score, top-5
// contributors DESC score / ASC feature name, category from the highest
// contributor with ties broken by feature name ASC, unknown if none" rule
// used identically by robust-baseline-v1 (spec §15) and cohort-outlier-v1
// (spec §17).
func aggregateFeatureScores(scored []Contributor) HostFeatureScoreResult {
	if len(scored) == 0 {
		return HostFeatureScoreResult{Valid: false}
	}
	maxScore := 0.0
	for _, c := range scored {
		if c.Score > maxScore {
			maxScore = c.Score
		}
	}

	positive := make([]Contributor, 0, len(scored))
	for _, c := range scored {
		if c.Score > 0 {
			positive = append(positive, c)
		}
	}
	sort.Slice(positive, func(i, j int) bool {
		if positive[i].Score != positive[j].Score {
			return positive[i].Score > positive[j].Score
		}
		return positive[i].Feature < positive[j].Feature
	})
	if len(positive) > 5 {
		positive = positive[:5]
	}

	category := "unknown"
	if len(positive) > 0 {
		category = positive[0].Category
	}

	return HostFeatureScoreResult{
		Valid:        true,
		Score:        maxScore,
		Contributors: positive,
		Category:     category,
	}
}

// ComputeBaselineHostScore evaluates robust-baseline-v1 across every
// feature the host currently has a valid reading for (spec §15). history
// maps feature name to that feature's historical values from
// HostBaselineStore.History; current maps feature name to this cycle's
// valid reading — features absent from current are not scored (spec §13:
// invalid/missing features never become part of a score).
func ComputeBaselineHostScore(profile FeatureProfile, history map[string][]float64, current map[string]float64) HostFeatureScoreResult {
	var scored []Contributor
	for name, value := range current {
		feature, ok := profile.Feature(name)
		if !ok {
			continue
		}
		result := ComputeRobustBaseline(feature, history[name], value)
		if !result.Ready {
			continue
		}
		scored = append(scored, Contributor{Feature: name, Category: feature.Category, Score: result.Score})
	}
	return aggregateFeatureScores(scored)
}

// ShouldUpdateBaseline implements the contamination-protection rule (spec
// §16): a baseline sample may only be written for a host's current minute
// when the host is lifecycle-normal, its fused local score is below the
// candidate threshold, and every required feature was valid this cycle.
// Any false input freezes the WHOLE host's baseline for that minute — the
// caller must skip Observe for every feature, not just an invalid one.
func ShouldUpdateBaseline(state LifecycleState, localScore float64, allRequiredFeaturesValid bool) bool {
	return state == StateNormal && localScore < ModelTriggerThreshold && allRequiredFeaturesValid
}
