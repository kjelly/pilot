package detection

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func openAIEnvelope(t *testing.T, status string, content []openAIContentItem) string {
	t.Helper()
	env := openAIResponseEnvelope{
		Status: status,
		Output: []openAIOutputItem{
			{Type: "message", Role: "assistant", Status: "completed", Content: content},
		},
	}
	b := mustMarshal(t, env)
	return string(b)
}

func openAIServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *OpenAIProvider) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	return srv, &OpenAIProvider{BaseURL: srv.URL, Model: "test-model", HTTPClient: srv.Client()}
}

// TestProvider_OpenAICompletedSingleOutputText (spec §31/§31.1/§48): the
// happy path — status=completed, exactly one assistant message, exactly
// one output_text carrying a schema/semantically valid batch response.
func TestProvider_OpenAICompletedSingleOutputText(t *testing.T) {
	req := validRequest()
	respJSON := string(mustMarshal(t, ModelBatchResponse{
		SchemaVersion: 1, RequestID: req.RequestID, Status: "ok",
		Candidates: []ModelCandidateResponse{
			{CandidateID: "host-a", Score: 0.7, Confidence: 0.8, CategoryHint: "cpu-hot", Contributors: []ModelContributor{{Feature: "cpu", Score: 0.7}}},
			{CandidateID: "host-b", Score: 0.1, Confidence: 0.9, CategoryHint: "", Contributors: []ModelContributor{}},
		},
	}))

	_, provider := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, openAIEnvelope(t, "completed", []openAIContentItem{{Type: "output_text", Text: respJSON}}))
	})

	resp, err := provider.Score(context.Background(), req)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if resp.RequestID != req.RequestID || resp.Status != "ok" || len(resp.Candidates) != 2 {
		t.Errorf("unexpected response: %+v", resp)
	}
}

// TestProvider_OpenAIIncompleteRejected (spec §31.1/§48): status=incomplete
// falls back (KindProviderRejected), and is explicitly NOT a circuit
// health failure.
func TestProvider_OpenAIIncompleteRejected(t *testing.T) {
	_, provider := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, openAIEnvelope(t, "incomplete", nil))
	})
	_, err := provider.Score(context.Background(), validRequest())
	if err == nil {
		t.Fatal("expected an error for status=incomplete")
	}
	if kind := classify(err); kind != KindProviderRejected {
		t.Errorf("kind = %v, want KindProviderRejected", kind)
	}
	if classify(err).healthFailure() {
		t.Error("status=incomplete must not count as a circuit health failure")
	}
}

// TestProvider_OpenAIRefusalFallsBackWithoutCircuitFailure (spec
// §31.1/§34/§48).
func TestProvider_OpenAIRefusalFallsBackWithoutCircuitFailure(t *testing.T) {
	_, provider := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, openAIEnvelope(t, "completed", []openAIContentItem{{Type: "refusal", Refusal: "cannot comply"}}))
	})
	_, err := provider.Score(context.Background(), validRequest())
	if err == nil {
		t.Fatal("expected a refusal error")
	}
	kind := classify(err)
	if kind != KindRefusal {
		t.Errorf("kind = %v, want KindRefusal", kind)
	}
	if kind.healthFailure() {
		t.Error("refusal must not count as a circuit health failure (spec §34)")
	}
	if kind.retryable() {
		t.Error("refusal must not be retried (spec §34)")
	}
}

// TestProvider_OpenAIMultipleOutputTextRejected (spec §31.1/§48): more than
// one output_text in the completed assistant message is an invalid
// structured response — health-failure eligible, unlike refusal/incomplete.
func TestProvider_OpenAIMultipleOutputTextRejected(t *testing.T) {
	_, provider := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, openAIEnvelope(t, "completed", []openAIContentItem{
			{Type: "output_text", Text: "{}"},
			{Type: "output_text", Text: "{}"},
		}))
	})
	_, err := provider.Score(context.Background(), validRequest())
	if err == nil {
		t.Fatal("expected an error for multiple output_text items")
	}
	kind := classify(err)
	if kind != KindInvalidStructured {
		t.Errorf("kind = %v, want KindInvalidStructured", kind)
	}
	if !kind.healthFailure() {
		t.Error("multiple output_text (invalid structured response) must count as a circuit health failure")
	}
}

func TestProvider_OpenAI_HTTP429IsRateLimited(t *testing.T) {
	_, provider := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":"rate limited"}`)
	})
	_, err := provider.Score(context.Background(), validRequest())
	if err == nil {
		t.Fatal("expected an error")
	}
	if kind := classify(err); kind != KindRateLimited || !kind.retryable() || !kind.healthFailure() {
		t.Errorf("kind = %v, want retryable+health-failure KindRateLimited", kind)
	}
}

func TestProvider_OpenAI_HTTP401IsClientErrorNotRetried(t *testing.T) {
	_, provider := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, err := provider.Score(context.Background(), validRequest())
	if err == nil {
		t.Fatal("expected an error")
	}
	kind := classify(err)
	if kind != KindClientError || kind.retryable() || kind.healthFailure() {
		t.Errorf("kind = %v, want non-retryable non-health-failure KindClientError", kind)
	}
}

func TestProvider_OpenAI_SchemaSemanticMismatchIsInvalidStructured(t *testing.T) {
	req := validRequest()
	badJSON := string(mustMarshal(t, ModelBatchResponse{
		SchemaVersion: 1, RequestID: "wrong-id", Status: "ok",
		Candidates: []ModelCandidateResponse{{CandidateID: "host-a", Score: 0.1, Confidence: 0.1, CategoryHint: "", Contributors: []ModelContributor{}}},
	}))
	_, provider := openAIServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, openAIEnvelope(t, "completed", []openAIContentItem{{Type: "output_text", Text: badJSON}}))
	})
	_, err := provider.Score(context.Background(), req)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrSchemaSemanticMismatch) {
		t.Errorf("expected ErrSchemaSemanticMismatch in the chain, got %v", err)
	}
	if classify(err) != KindInvalidStructured {
		t.Errorf("kind = %v, want KindInvalidStructured", classify(err))
	}
}
