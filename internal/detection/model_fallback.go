package detection

import (
	"context"
	"time"
)

// FallbackProvider composes two already-managed providers (each with its
// own retry/circuit-breaker/timeout, since a primary and fallback
// backend's failure modes are independent): Score() always tries Primary
// first; on ANY error — network, timeout, circuit-open, invalid
// structured response — it tries Fallback instead of failing the cycle.
// This is spec1.md §35's "Level 2: alternate backend", generalized to any
// protocol pair rather than hardcoded to FLM-specific alternates: an
// operator configures which protocol is primary (e.g. flm, to prefer
// local NPU inference) and which is the fallback (e.g. ollama-chat or
// openai-responses, for when the NPU backend is unavailable or its
// response repeatedly fails validation).
type FallbackProvider struct {
	Primary  *ManagedProvider
	Fallback *ManagedProvider
}

func (f *FallbackProvider) Score(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
	resp, err := f.Primary.Score(ctx, req)
	if err == nil {
		return resp, nil
	}
	return f.Fallback.Score(ctx, req)
}

// CircuitState reports "open" only when BOTH the primary and fallback
// circuits are open — the pair is only actually unavailable then; status
// consumers should not report "the model provider is down" while either
// path is still usable.
func (f *FallbackProvider) CircuitState(now time.Time) string {
	if f.Primary.CircuitState(now) == "open" && f.Fallback.CircuitState(now) == "open" {
		return "open"
	}
	return "closed"
}

// circuitReporter is satisfied by both *ManagedProvider and
// *FallbackProvider — main.go's serve loop type-asserts Engine.Provider
// against it to populate status.json/metrics without caring which one is
// actually configured.
type circuitReporter interface {
	CircuitState(now time.Time) string
}
