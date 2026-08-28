package detection

// LocalScoreResult is a host's fused local (non-model) score for one cycle
// (spec §18, extended by spec1.md §66 to a third, equally-weighted log
// detector): the higher of its valid baseline/cohort/log scores.
type LocalScoreResult struct {
	// Valid is false when baseline, cohort, AND log were all invalid (not
	// just scored 0) — the whole host cycle is invalid (spec §18).
	Valid        bool
	Score        float64
	Contributors []Contributor
	Category     string
	// Source names which detector's contributors/category won: "baseline",
	// "cohort", or "log". A tie goes to baseline, then cohort (spec §18).
	Source string
}

// localScoreCandidate pairs one detector's result with its Source label,
// in ComputeLocalScore's fixed tie-break precedence order.
type localScoreCandidate struct {
	result HostFeatureScoreResult
	source string
}

// ComputeLocalScore implements spec §18 (extended by spec1.md §66):
// local_score = max(baseline_score, cohort_score, log_score) across
// whichever of the three are valid; a tie goes to baseline, then cohort.
// log detectors always feed the SAME max()-based aggregation as
// baseline/cohort — including the known-critical-pattern hard trigger
// (spec1.md §37 Option B), which is nothing more than a log score of 1.0
// naturally dominating this max().
func ComputeLocalScore(baseline, cohort, log HostFeatureScoreResult) LocalScoreResult {
	candidates := []localScoreCandidate{
		{baseline, "baseline"},
		{cohort, "cohort"},
		{log, "log"},
	}

	best := -1
	for i, c := range candidates {
		if !c.result.Valid {
			continue
		}
		if best == -1 || c.result.Score > candidates[best].result.Score {
			best = i
		}
	}
	if best == -1 {
		return LocalScoreResult{Valid: false}
	}
	winner := candidates[best]
	return LocalScoreResult{
		Valid:        true,
		Score:        winner.result.Score,
		Contributors: winner.result.Contributors,
		Category:     winner.result.Category,
		Source:       winner.source,
	}
}

// IsCandidate implements spec §18's MODEL_TRIGGER gate: local_score >= 0.65.
func IsCandidate(localScore float64) bool {
	return localScore >= CandidateThreshold
}
