package detection

import "sort"

// Candidate is one subject selected for model-assisted scoring this cycle
// (spec §35, generalized to a generic SubjectKey by spec §9.11/Phase 6):
// local_score >= CandidateThreshold, carrying whatever this cycle's valid
// current feature values were.
type Candidate struct {
	Subject    SubjectKey
	LocalScore LocalScoreResult
	Current    map[string]float64
}

// MaxCandidatesPerCycle, ModelBatchSize, and MaxBatchesPerCycle implement
// spec §35's cost bound: at most 16 candidates/cycle (4 requests * 4
// candidates/request), at most 4 concurrent requests.
const (
	MaxCandidatesPerCycle  = 16
	ModelBatchSize         = 4
	MaxBatchesPerCycle     = 4
	MaxProviderConcurrency = 4
)

// SelectCandidates implements spec §35's candidate selection: every valid
// host with local_score >= CandidateThreshold, sorted local_score DESC
// then pilot_host ASC, capped at MaxCandidatesPerCycle. dropped (below the
// cap, deterministically the lowest-scoring tail after the sort) falls
// back to local-only scoring for this cycle — the caller increments
// pilot_detection_model_candidates_dropped_total{reason=cap} for len(dropped).
func SelectCandidates(all []Candidate) (kept, dropped []Candidate) {
	sorted := make([]Candidate, len(all))
	copy(sorted, all)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].LocalScore.Score != sorted[j].LocalScore.Score {
			return sorted[i].LocalScore.Score > sorted[j].LocalScore.Score
		}
		return sorted[i].Subject.ID < sorted[j].Subject.ID
	})
	if len(sorted) <= MaxCandidatesPerCycle {
		return sorted, nil
	}
	return sorted[:MaxCandidatesPerCycle], sorted[MaxCandidatesPerCycle:]
}

// ChunkBatches groups candidates into ModelBatchSize-sized batches, in the
// same order SelectCandidates returned them (already local_score DESC /
// host ASC) — at most MaxBatchesPerCycle batches given the
// MaxCandidatesPerCycle cap upstream.
func ChunkBatches(candidates []Candidate) [][]Candidate {
	var batches [][]Candidate
	for i := 0; i < len(candidates); i += ModelBatchSize {
		end := i + ModelBatchSize
		if end > len(candidates) {
			end = len(candidates)
		}
		batches = append(batches, candidates[i:end])
	}
	return batches
}
