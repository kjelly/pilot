package docs

import (
	"strings"
	"testing"
)

func TestCosineBatchSortedDescending(t *testing.T) {
	// Build a batch where we know the expected order.
	q := []float32{1, 0, 0}
	batch := [][]float32{
		{0.5, 0.5, 0}, // score 0.707
		{1, 0, 0},     // score 1.000
		{0.3, 0.4, 0}, // score 0.6
		{0, 1, 0},     // score 0
	}
	idx, scores := CosineBatch(q, batch)
	if len(idx) != 4 {
		t.Fatalf("got %d entries, want 4", len(idx))
	}
	for i := 1; i < len(scores); i++ {
		if scores[i] > scores[i-1] {
			t.Errorf("not sorted descending: scores[%d]=%v > scores[%d]=%v",
				i, scores[i], i-1, scores[i-1])
		}
	}
	// Highest-scoring vector was batch[1] (idx 1), it must come first.
	if idx[0] != 1 {
		t.Errorf("idx[0] = %d, want 1", idx[0])
	}
}

func TestCacheKeyDifferentiatesSource(t *testing.T) {
	// Same query and k, different source → different cache keys.
	// This is the regression test for cross-source pollution.
	k1 := cacheKey("disable ssh", 5, SourceModule)
	k2 := cacheKey("disable ssh", 5, SourcePlaybook)
	if k1 == k2 {
		t.Errorf("cache keys collide: %q vs %q", k1, k2)
	}
	// And same-source must be deterministic.
	k1b := cacheKey("disable ssh", 5, SourceModule)
	if k1 != k1b {
		t.Errorf("cache key not deterministic: %q vs %q", k1, k1b)
	}
	// Different k → different keys.
	k3 := cacheKey("disable ssh", 10, SourceModule)
	if k1 == k3 {
		t.Errorf("k not in key: %q vs %q", k1, k3)
	}
}

func TestCacheKeyHasNoFmtSprintf(t *testing.T) {
	// Sanity-check the implementation: a numeric k="0" should NOT
	// produce a key containing "%!".
	for _, k := range []int{0, 1, 10, 1000000} {
		key := cacheKey("q", k, SourceModule)
		if strings.Contains(key, "%!") {
			t.Errorf("cache key has format error: %q", key)
		}
	}
}

func TestTopK(t *testing.T) {
	q := []float32{1, 0}
	// batch[0] and batch[1] both have cosine=1.0 (cosine treats 1-d
	// vectors as identical to themselves); batch[2] has cosine≈0.707.
	// Top-2 must therefore be (0, 1) with batch[2] excluded.
	batch := [][]float32{{0.1, 0}, {1, 0}, {0.5, 0.5}}
	matches := TopK(q, batch, 2)
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(matches))
	}
	if matches[0].Index != 0 || matches[1].Index != 1 {
		t.Errorf("top-2 ordering wrong: got indices %d, %d",
			matches[0].Index, matches[1].Index)
	}
}
