package detection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// OllamaTimeout is spec §34's default Ollama request timeout.
const OllamaTimeout = 30 * time.Second

// OllamaProvider implements ModelProvider for spec §32's native
// ollama-chat protocol (POST <base_url>/api/chat). v1.3 deliberately does
// not use Ollama's /v1/responses OpenAI-compatibility endpoint.
type OllamaProvider struct {
	BaseURL    string
	Model      string
	HTTPClient *http.Client
}

type ollamaChatRequest struct {
	Model    string              `json:"model"`
	Messages []ollamaChatMessage `json:"messages"`
	Format   json.RawMessage     `json:"format"`
	Stream   bool                `json:"stream"`
	Options  ollamaChatOptions   `json:"options"`
}

type ollamaChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChatOptions struct {
	Temperature float64 `json:"temperature"`
}

type ollamaChatResponse struct {
	Message *ollamaChatMessage `json:"message"`
	Error   string             `json:"error"`
}

func (p *OllamaProvider) client() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}

// Score sends one batch request via POST <base_url>/api/chat (spec §32).
// Client-side JSON Schema + semantic validation is always mandatory —
// Ollama's own `format` field is a best-effort hint, never trusted alone.
func (p *OllamaProvider) Score(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return ModelBatchResponse{}, newProviderError(KindClientError, "marshal request: %v", err)
	}

	payload := ollamaChatRequest{
		Model: p.Model,
		Messages: []ollamaChatMessage{
			{Role: "system", Content: HostAnomalyPrompt()},
			{Role: "user", Content: string(reqJSON)},
		},
		Format:  modelBatchResponseSchemaJSON,
		Stream:  false,
		Options: ollamaChatOptions{Temperature: 0},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ModelBatchResponse{}, newProviderError(KindClientError, "marshal payload: %v", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.BaseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return ModelBatchResponse{}, newProviderError(KindClientError, "build request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client().Do(httpReq)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ModelBatchResponse{}, newProviderError(KindTimeout, "ollama request timed out: %v", err)
		}
		return ModelBatchResponse{}, newProviderError(KindNetwork, "ollama request failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ModelBatchResponse{}, newProviderError(classifyHTTPStatus(resp.StatusCode), "ollama http %d: %s", resp.StatusCode, truncateForError(respBody))
	}

	var env ollamaChatResponse
	if err := json.Unmarshal(respBody, &env); err != nil {
		return ModelBatchResponse{}, newProviderError(KindInvalidStructured, "ollama response envelope: %v", err)
	}
	if env.Error != "" {
		return ModelBatchResponse{}, newProviderError(KindProviderRejected, "ollama error: %s", env.Error)
	}
	if env.Message == nil || env.Message.Content == "" {
		return ModelBatchResponse{}, newProviderError(KindInvalidStructured, "ollama response has no message.content")
	}

	batchResp, verr := ValidateBatchResponse([]byte(env.Message.Content), req)
	if verr != nil {
		return ModelBatchResponse{}, newProviderError(KindInvalidStructured, "ollama message.content: %w", verr)
	}
	return batchResp, nil
}
