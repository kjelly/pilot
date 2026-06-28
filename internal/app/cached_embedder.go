package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/anomalyco/pilot/internal/docs"
	"github.com/anomalyco/pilot/internal/store"
)

type CachedEmbedder struct {
	inner docs.Embedder
	store *store.Store
}

func NewCachedEmbedder(inner docs.Embedder, store *store.Store) *CachedEmbedder {
	return &CachedEmbedder{inner: inner, store: store}
}

func (ce *CachedEmbedder) EmbeddingModel() string {
	return ce.inner.EmbeddingModel()
}

func (ce *CachedEmbedder) Embeddings(ctx context.Context, text string) ([]float32, error) {
	if ce.store == nil {
		return ce.inner.Embeddings(ctx, text)
	}
	model := ce.EmbeddingModel()
	hash := hashText(text)
	if cached, err := ce.store.GetEmbedding(hash, model); err == nil && len(cached) > 0 {
		return cached, nil
	}
	vec, err := ce.inner.Embeddings(ctx, text)
	if err != nil {
		return nil, err
	}
	_ = ce.store.SaveEmbedding(hash, model, vec)
	return vec, nil
}

func (ce *CachedEmbedder) BatchEmbeddings(ctx context.Context, texts []string) ([][]float32, error) {
	if ce.store == nil || len(texts) == 0 {
		return ce.inner.BatchEmbeddings(ctx, texts)
	}
	model := ce.EmbeddingModel()
	results := make([][]float32, len(texts))
	var missingTexts []string
	var missingIndices []int

	for i, t := range texts {
		hash := hashText(t)
		if cached, err := ce.store.GetEmbedding(hash, model); err == nil && len(cached) > 0 {
			results[i] = cached
		} else {
			missingTexts = append(missingTexts, t)
			missingIndices = append(missingIndices, i)
		}
	}

	if len(missingTexts) > 0 {
		vecs, err := ce.inner.BatchEmbeddings(ctx, missingTexts)
		if err != nil {
			return nil, err
		}
		for i, vec := range vecs {
			originalIndex := missingIndices[i]
			results[originalIndex] = vec
			_ = ce.store.SaveEmbedding(hashText(missingTexts[i]), model, vec)
		}
	}
	return results, nil
}

func hashText(text string) string {
	h := sha256.Sum256([]byte(text))
	return hex.EncodeToString(h[:])
}
