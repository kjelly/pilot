package detection

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func ollamaServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *OllamaProvider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	return &OllamaProvider{BaseURL: srv.URL, Model: "test-model", HTTPClient: srv.Client()}
}

func TestProvider_OllamaChatHappyPath(t *testing.T) {
	req := validRequest()
	content := string(mustMarshal(t, ModelBatchResponse{
		SchemaVersion: 1, RequestID: req.RequestID, Status: "ok",
		Candidates: []ModelCandidateResponse{
			{CandidateID: "host-a", Score: 0.6, Confidence: 0.7, CategoryHint: "mem", Contributors: []ModelContributor{{Feature: "cpu", Score: 0.6}}},
			{CandidateID: "host-b", Score: 0.1, Confidence: 0.5, CategoryHint: "", Contributors: []ModelContributor{}},
		},
	}))
	provider := ollamaServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("path = %q, want /api/chat", r.URL.Path)
		}
		fmt.Fprint(w, string(mustMarshal(t, ollamaChatResponse{Message: &ollamaChatMessage{Role: "assistant", Content: content}})))
	})

	resp, err := provider.Score(context.Background(), req)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if resp.Status != "ok" || len(resp.Candidates) != 2 {
		t.Errorf("unexpected response: %+v", resp)
	}
}

// TestProvider_OllamaChatSchemaValidatedClientSide (spec §32/§48): Ollama's
// own `format` field is only a best-effort hint — the adapter must reject
// a malformed/invalid message.content itself rather than trust the server.
func TestProvider_OllamaChatSchemaValidatedClientSide(t *testing.T) {
	req := validRequest()

	cases := []struct {
		name    string
		content string
	}{
		{"not JSON at all", "this is not json"},
		{"valid JSON, wrong shape (missing required fields)", `{"foo":"bar"}`},
		{"schema-valid but semantically wrong request_id", string(mustMarshal(t, ModelBatchResponse{
			SchemaVersion: 1, RequestID: "not-the-request-id", Status: "ok",
			Candidates: []ModelCandidateResponse{{CandidateID: "host-a", Score: 0.1, Confidence: 0.1, CategoryHint: "", Contributors: []ModelContributor{}}},
		}))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			provider := ollamaServer(t, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, string(mustMarshal(t, ollamaChatResponse{Message: &ollamaChatMessage{Role: "assistant", Content: c.content}})))
			})
			_, err := provider.Score(context.Background(), req)
			if err == nil {
				t.Fatal("expected client-side validation to reject this response")
			}
			if !errors.Is(err, ErrSchemaSemanticMismatch) {
				t.Errorf("expected ErrSchemaSemanticMismatch in the chain, got %v", err)
			}
			if classify(err) != KindInvalidStructured {
				t.Errorf("kind = %v, want KindInvalidStructured", classify(err))
			}
		})
	}
}

func TestProvider_Ollama_HTTP500IsServerError(t *testing.T) {
	provider := ollamaServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := provider.Score(context.Background(), validRequest())
	if err == nil {
		t.Fatal("expected an error")
	}
	kind := classify(err)
	if kind != KindServerError || !kind.retryable() || !kind.healthFailure() {
		t.Errorf("kind = %v, want retryable+health-failure KindServerError", kind)
	}
}
