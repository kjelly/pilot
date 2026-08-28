package detection

import "context"

// FakeModelProvider is an in-process ModelProvider test double (Stage B-1's
// "fake provider" for Go-level unit tests — no network, fully
// deterministic). ScoreFunc is called directly; a nil ScoreFunc is a
// configuration error, surfaced as a KindNetwork ProviderError so a
// misconfigured test fails loudly rather than silently fusing local-only.
type FakeModelProvider struct {
	ScoreFunc func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error)
}

func (f *FakeModelProvider) Score(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
	if f.ScoreFunc == nil {
		return ModelBatchResponse{}, newProviderError(KindNetwork, "FakeModelProvider: no ScoreFunc set")
	}
	return f.ScoreFunc(ctx, req)
}
