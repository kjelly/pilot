// Package docs provides RAG over Ansible documentation and user playbooks.
package docs

import (
	"math"
	"sort"
)

// Cosine computes the cosine similarity between two vectors.
// Returns 0 if either vector is zero-length.
func Cosine(a, b []float32) float64 {
	if len(a) == 0 || len(b) == 0 || len(a) != len(b) {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

// CosineBatch computes similarity to every vector in batch. Returns
// parallel slices of indices and scores sorted by score descending.
func CosineBatch(query []float32, batch [][]float32) ([]int, []float64) {
	idx := make([]int, len(batch))
	scores := make([]float64, len(batch))
	for i, v := range batch {
		idx[i] = i
		scores[i] = Cosine(query, v)
	}
	// Sort idx and scores together by score descending. We sort a
	// parallel slice of indices and use it to permute both arrays
	// in lock-step, so scores[i] always corresponds to idx[i].
	perm := make([]int, len(idx))
	for i := range perm {
		perm[i] = i
	}
	sort.Slice(perm, func(i, j int) bool {
		return scores[perm[i]] > scores[perm[j]]
	})
	sortedIdx := make([]int, len(idx))
	sortedScores := make([]float64, len(scores))
	for i, p := range perm {
		sortedIdx[i] = idx[p]
		sortedScores[i] = scores[p]
	}
	return sortedIdx, sortedScores
}

// TopK returns the top-k (index, score) pairs from a batch similarity.
func TopK(query []float32, batch [][]float32, k int) []Match {
	if k > len(batch) {
		k = len(batch)
	}
	idx, scores := CosineBatch(query, batch)
	out := make([]Match, k)
	for i := 0; i < k; i++ {
		out[i] = Match{Index: idx[i], Score: scores[i]}
	}
	return out
}

// Match is a search hit.
type Match struct {
	Index int
	Score float64
}
