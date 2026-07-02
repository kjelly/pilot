package ollama

import (
	"context"
	"math"
	"testing"

	"github.com/anomalyco/pilot/internal/docs"
)

func TestEmbeddingsDimension(t *testing.T) {
	c := NewClient("http://localhost:11434", "qwen2.5:3b")
	if err := c.Ping(context.Background()); err != nil {
		t.Skipf("ollama not reachable: %v", err)
	}
	// qwen3-embedding:4b is 2560-dim per the /api/tags output (test fixture only — production default is now nomic-embed-text, 768-dim)
	c.SetEmbeddingModel("qwen3-embedding:4b")
	vec, err := c.Embeddings(context.Background(), "hello world")
	if err != nil {
		t.Fatal(err)
	}
	if len(vec) == 0 {
		t.Fatal("empty embedding")
	}
	t.Logf("got embedding of dimension %d", len(vec))
}

func TestBatchEmbeddingsPreservesOrder(t *testing.T) {
	c := NewClient("http://localhost:11434", "qwen2.5:3b")
	if err := c.Ping(context.Background()); err != nil {
		t.Skipf("ollama not reachable: %v", err)
	}
	c.SetEmbeddingModel("qwen3-embedding:4b")
	vecs, err := c.BatchEmbeddings(context.Background(), []string{"alpha", "beta", "gamma"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vecs) != 3 {
		t.Fatalf("got %d, want 3", len(vecs))
	}
	if len(vecs[0]) == 0 {
		t.Fatal("first embedding empty")
	}
}

func TestEmbeddingCosineSimilarity(t *testing.T) {
	identical := []float32{1, 0, 0}
	other := []float32{1, 0, 0}
	orth := []float32{0, 1, 0}
	opp := []float32{-1, 0, 0}

	if !floatNear(docs.Cosine(identical, other), 1.0, 1e-5) {
		t.Errorf("identical: %f", docs.Cosine(identical, other))
	}
	if !floatNear(docs.Cosine(identical, orth), 0.0, 1e-5) {
		t.Errorf("orth: %f", docs.Cosine(identical, orth))
	}
	if !floatNear(docs.Cosine(identical, opp), -1.0, 1e-5) {
		t.Errorf("opp: %f", docs.Cosine(identical, opp))
	}
}

func TestTopK(t *testing.T) {
	query := []float32{1, 0, 0}
	batch := [][]float32{
		{1, 0, 0},     // 1.0
		{0.9, 0.1, 0}, // ~0.99
		{0, 1, 0},     // 0
		{-1, 0, 0},    // -1
	}
	matches := docs.TopK(query, batch, 2)
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(matches))
	}
	if matches[0].Index != 0 {
		t.Errorf("top match: got idx %d, want 0", matches[0].Index)
	}
	if matches[1].Index != 1 {
		t.Errorf("second match: got idx %d, want 1", matches[1].Index)
	}
}

func floatNear(a, b, eps float64) bool { return math.Abs(a-b) < eps }
