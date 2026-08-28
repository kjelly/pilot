package detection

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFallbackProvider_UsesPrimaryWhenHealthy(t *testing.T) {
	fallbackCalled := false
	primary := NewManagedProvider(&FakeModelProvider{ScoreFunc: func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
		return ModelBatchResponse{SchemaVersion: 1, RequestID: req.RequestID, Status: "ok"}, nil
	}}, "flm", time.Second)
	fallback := NewManagedProvider(&FakeModelProvider{ScoreFunc: func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
		fallbackCalled = true
		return ModelBatchResponse{}, nil
	}}, "ollama-chat", time.Second)

	fp := &FallbackProvider{Primary: primary, Fallback: fallback}
	resp, err := fp.Score(context.Background(), ModelBatchRequest{RequestID: "r"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.RequestID != "r" {
		t.Errorf("unexpected response: %+v", resp)
	}
	if fallbackCalled {
		t.Error("fallback must not be called when the primary succeeds")
	}
}

func TestFallbackProvider_FallsBackOnPrimaryError(t *testing.T) {
	primaryCalls, fallbackCalls := 0, 0
	primary := NewManagedProvider(&FakeModelProvider{ScoreFunc: func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
		primaryCalls++
		return ModelBatchResponse{}, newProviderError(KindNetwork, "primary unreachable")
	}}, "flm", time.Second)
	fallback := NewManagedProvider(&FakeModelProvider{ScoreFunc: func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
		fallbackCalls++
		return ModelBatchResponse{SchemaVersion: 1, RequestID: req.RequestID, Status: "ok"}, nil
	}}, "ollama-chat", time.Second)
	primary.Sleep = func(time.Duration) {}

	fp := &FallbackProvider{Primary: primary, Fallback: fallback}
	resp, err := fp.Score(context.Background(), ModelBatchRequest{RequestID: "r"})
	if err != nil {
		t.Fatalf("expected the fallback to recover, got %v", err)
	}
	if resp.RequestID != "r" {
		t.Errorf("unexpected response: %+v", resp)
	}
	if fallbackCalls != 1 {
		t.Errorf("expected exactly 1 fallback call, got %d", fallbackCalls)
	}
	if primaryCalls == 0 {
		t.Error("primary should have been tried first")
	}
}

func TestFallbackProvider_ReturnsFallbackErrorWhenBothFail(t *testing.T) {
	primary := NewManagedProvider(&FakeModelProvider{ScoreFunc: func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
		return ModelBatchResponse{}, newProviderError(KindClientError, "primary broken")
	}}, "flm", time.Second)
	fallback := NewManagedProvider(&FakeModelProvider{ScoreFunc: func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
		return ModelBatchResponse{}, newProviderError(KindClientError, "fallback also broken")
	}}, "ollama-chat", time.Second)

	fp := &FallbackProvider{Primary: primary, Fallback: fallback}
	_, err := fp.Score(context.Background(), ModelBatchRequest{RequestID: "r"})
	if err == nil {
		t.Fatal("expected an error when both primary and fallback fail")
	}
	var perr *ProviderError
	if !errors.As(err, &perr) || perr.Err.Error() != "fallback also broken" {
		t.Errorf("expected the fallback's own error to surface, got %v", err)
	}
}

func TestFallbackProvider_CircuitStateOpenOnlyWhenBothOpen(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	failing := func(kind ProviderErrorKind) *ManagedProvider {
		mp := NewManagedProvider(&FakeModelProvider{ScoreFunc: func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
			return ModelBatchResponse{}, newProviderError(kind, "boom")
		}}, "flm", time.Second)
		mp.Sleep = func(time.Duration) {}
		mp.Now = func() time.Time { return now }
		return mp
	}
	openCircuit := func(mp *ManagedProvider) {
		for i := 0; i < 3; i++ {
			_, _ = mp.Score(context.Background(), ModelBatchRequest{})
		}
	}

	primary := failing(KindServerError)
	fallback := failing(KindServerError)
	fp := &FallbackProvider{Primary: primary, Fallback: fallback}

	if fp.CircuitState(now) != "closed" {
		t.Fatalf("expected closed before any failures, got %q", fp.CircuitState(now))
	}

	openCircuit(primary)
	if fp.CircuitState(now) != "closed" {
		t.Errorf("expected closed while only the primary's circuit is open, got %q", fp.CircuitState(now))
	}

	openCircuit(fallback)
	if fp.CircuitState(now) != "open" {
		t.Errorf("expected open once BOTH circuits are open, got %q", fp.CircuitState(now))
	}
}
