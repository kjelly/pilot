package detection

// LocalScoreResult is a host's fused local (non-model) score for one cycle
// (spec §18): the higher of its valid baseline/cohort scores.
type LocalScoreResult struct {
	// Valid is false when BOTH baseline and cohort were invalid (not just
	// scored 0) — the whole host cycle is invalid (spec §18).
	Valid        bool
	Score        float64
	Contributors []Contributor
	Category     string
	// Source names which detector's contributors/category won: "baseline"
	// or "cohort". A tie is won by baseline (spec §18).
	Source string
}

// ComputeLocalScore implements spec §18: local_score = max(baseline_score
// if valid, cohort_score if valid); a tie goes to baseline.
func ComputeLocalScore(baseline, cohort HostFeatureScoreResult) LocalScoreResult {
	switch {
	case !baseline.Valid && !cohort.Valid:
		return LocalScoreResult{Valid: false}
	case baseline.Valid && (!cohort.Valid || baseline.Score >= cohort.Score):
		return LocalScoreResult{
			Valid:        true,
			Score:        baseline.Score,
			Contributors: baseline.Contributors,
			Category:     baseline.Category,
			Source:       "baseline",
		}
	default:
		return LocalScoreResult{
			Valid:        true,
			Score:        cohort.Score,
			Contributors: cohort.Contributors,
			Category:     cohort.Category,
			Source:       "cohort",
		}
	}
}

// IsCandidate implements spec §18's MODEL_TRIGGER gate: local_score >= 0.65.
func IsCandidate(localScore float64) bool {
	return localScore >= CandidateThreshold
}
