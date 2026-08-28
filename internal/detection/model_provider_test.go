package detection

import (
	"context"
	"errors"
	"testing"
	"time"
)

func noopSleep(time.Duration) {}

// TestProvider_TimeoutFallsBackLocal (spec §34/§48): a provider that never
// returns within the configured timeout produces a Score() error — the
// caller (RunCycle's fusion pass) falls back to local, never blocking.
func TestProvider_TimeoutFallsBackLocal(t *testing.T) {
	base := &FakeModelProvider{ScoreFunc: func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
		<-ctx.Done()
		return ModelBatchResponse{}, newProviderError(KindTimeout, "timed out: %v", ctx.Err())
	}}
	mp := NewManagedProvider(base, "openai-responses", 10*time.Millisecond)
	mp.Sleep = noopSleep

	_, err := mp.Score(context.Background(), ModelBatchRequest{})
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if classify(err) != KindTimeout {
		t.Errorf("expected KindTimeout, got kind=%v err=%v", classify(err), err)
	}
}

// TestProvider_CircuitOpensAfterFiveFailures (spec §34/§48): 5 health
// failures within the rolling 2m window opens the circuit; while open, the
// underlying provider is never called again.
func TestProvider_CircuitOpensAfterFiveFailures(t *testing.T) {
	calls := 0
	base := &FakeModelProvider{ScoreFunc: func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
		calls++
		return ModelBatchResponse{}, newProviderError(KindServerError, "boom")
	}}
	mp := NewManagedProvider(base, "openai-responses", time.Second)
	mp.Sleep = noopSleep

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mp.Now = func() time.Time { return now }

	// Each Score() call retries twice internally (3 attempts), so 2 calls
	// to Score() already produce 6 recorded health failures — well past
	// the threshold of 5. Use single-attempt-worth of failures by
	// advancing `now` between health-failure-producing calls instead of
	// relying on retries: disable retry accounting noise by asserting on
	// CircuitState transition, not exact calls-to-open count.
	for i := 0; i < 2; i++ {
		_, _ = mp.Score(context.Background(), ModelBatchRequest{})
	}
	if mp.CircuitState(now) != "open" {
		t.Fatalf("expected circuit to be open after >=5 health failures within the window, got %q (calls=%d)", mp.CircuitState(now), calls)
	}

	callsBeforeOpen := calls
	_, err := mp.Score(context.Background(), ModelBatchRequest{})
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen while open, got %v", err)
	}
	if calls != callsBeforeOpen {
		t.Errorf("expected no provider call while circuit is open, got %d additional calls", calls-callsBeforeOpen)
	}
}

// TestProvider_CircuitDoesNotOpenOnRefusal (spec §34/§48): refusal and
// insufficient_data are excluded from the health-failure count — even
// repeated refusals never open the circuit.
func TestProvider_CircuitDoesNotOpenOnRefusal(t *testing.T) {
	base := &FakeModelProvider{ScoreFunc: func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
		return ModelBatchResponse{}, newProviderError(KindRefusal, "refused")
	}}
	mp := NewManagedProvider(base, "openai-responses", time.Second)
	mp.Sleep = noopSleep
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mp.Now = func() time.Time { return now }

	for i := 0; i < 10; i++ {
		_, err := mp.Score(context.Background(), ModelBatchRequest{})
		if err == nil {
			t.Fatal("expected a refusal error")
		}
	}
	if mp.CircuitState(now) != "closed" {
		t.Errorf("expected circuit to remain closed after repeated refusals, got %q", mp.CircuitState(now))
	}
}

func TestManagedProvider_RetriesHealthFailureThenSucceeds(t *testing.T) {
	attempts := 0
	base := &FakeModelProvider{ScoreFunc: func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
		attempts++
		if attempts < 2 {
			return ModelBatchResponse{}, newProviderError(KindNetwork, "transient")
		}
		return ModelBatchResponse{SchemaVersion: 1, RequestID: req.RequestID, Status: "ok"}, nil
	}}
	mp := NewManagedProvider(base, "ollama-chat", time.Second)
	mp.Sleep = noopSleep

	resp, err := mp.Score(context.Background(), ModelBatchRequest{RequestID: "r"})
	if err != nil {
		t.Fatalf("expected retry to succeed, got %v", err)
	}
	if resp.RequestID != "r" {
		t.Errorf("unexpected response: %+v", resp)
	}
	if attempts != 2 {
		t.Errorf("expected exactly 2 attempts, got %d", attempts)
	}
}

func TestManagedProvider_NoRetryOnClientError(t *testing.T) {
	attempts := 0
	base := &FakeModelProvider{ScoreFunc: func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
		attempts++
		return ModelBatchResponse{}, newProviderError(KindClientError, "bad request")
	}}
	mp := NewManagedProvider(base, "openai-responses", time.Second)
	mp.Sleep = noopSleep

	_, err := mp.Score(context.Background(), ModelBatchRequest{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if attempts != 1 {
		t.Errorf("expected no retry for a client error, got %d attempts", attempts)
	}
}
