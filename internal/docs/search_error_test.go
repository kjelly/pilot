package docs

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// failingEmbedder always returns an error from Embeddings.
type failingEmbedder struct{ err error }

func (f *failingEmbedder) Embeddings(_ context.Context, _ string) ([]float32, error) {
	return nil, f.err
}
func (f *failingEmbedder) BatchEmbeddings(_ context.Context, _ []string) ([][]float32, error) {
	return nil, f.err
}
func (f *failingEmbedder) EmbeddingModel() string { return "failing" }

func TestSearchReturnsErrorOnEmbedFailure(t *testing.T) {
	idx := NewIndex()
	// Empty index → Search should return (nil, nil), not an error.
	if _, err := idx.Search(context.Background(), &failingEmbedder{err: nil}, "q", 5, ""); err != nil {
		t.Fatalf("empty index should not error, got: %v", err)
	}

	// Add a single chunk so the embed path is actually exercised.
	idx.chunks = []Chunk{{ID: "x", Source: "modules", Text: "t"}}
	idx.vectors = [][]float32{{0.1, 0.2, 0.3}}

	boom := errors.New("ollama down")
	matches, err := idx.Search(context.Background(), &failingEmbedder{err: boom}, "q", 5, "")
	if err == nil {
		t.Fatal("expected error from Search when Embeddings fails")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error should wrap the embed error, got: %v", err)
	}
	if matches != nil {
		t.Errorf("matches should be nil on error, got: %v", matches)
	}
	if !strings.Contains(err.Error(), "embed query") {
		t.Errorf("error message should describe the operation, got: %v", err)
	}
}
