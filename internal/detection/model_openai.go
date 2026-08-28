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

// OpenAITimeout is spec §34's default OpenAI request timeout.
const OpenAITimeout = 15 * time.Second

// OpenAIProvider implements ModelProvider for spec §31's openai-responses
// protocol. It is a pure HTTP client: no SDK convenience helpers, no
// conversation/previous_response_id/background/web-search/tool use.
type OpenAIProvider struct {
	BaseURL    string
	Model      string
	APIKey     string // empty = no Authorization header (auth=none)
	HTTPClient *http.Client
}

type openAIRequestPayload struct {
	Model           string           `json:"model"`
	Instructions    string           `json:"instructions"`
	Input           []openAIInputMsg `json:"input"`
	Text            openAITextField  `json:"text"`
	Tools           []any            `json:"tools"`
	ToolChoice      string           `json:"tool_choice"`
	Store           bool             `json:"store"`
	Stream          bool             `json:"stream"`
	MaxOutputTokens int              `json:"max_output_tokens"`
}

type openAIInputMsg struct {
	Role    string               `json:"role"`
	Content []openAIInputContent `json:"content"`
}

type openAIInputContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type openAITextField struct {
	Format openAITextFormat `json:"format"`
}

type openAITextFormat struct {
	Type   string          `json:"type"`
	Name   string          `json:"name"`
	Strict bool            `json:"strict"`
	Schema json.RawMessage `json:"schema"`
}

type openAIResponseEnvelope struct {
	Status string             `json:"status"`
	Error  *openAIError       `json:"error"`
	Output []openAIOutputItem `json:"output"`
}

type openAIError struct {
	Message string `json:"message"`
}

type openAIOutputItem struct {
	Type    string              `json:"type"`
	Role    string              `json:"role"`
	Status  string              `json:"status"`
	Content []openAIContentItem `json:"content"`
}

type openAIContentItem struct {
	Type    string `json:"type"`
	Text    string `json:"text"`
	Refusal string `json:"refusal"`
}

func (p *OpenAIProvider) client() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}

// Score sends one batch request via POST <base_url>/responses (spec §31).
func (p *OpenAIProvider) Score(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return ModelBatchResponse{}, newProviderError(KindClientError, "marshal request: %v", err)
	}

	payload := openAIRequestPayload{
		Model:        p.Model,
		Instructions: HostAnomalyPrompt(),
		Input: []openAIInputMsg{{
			Role:    "user",
			Content: []openAIInputContent{{Type: "input_text", Text: string(reqJSON)}},
		}},
		Text: openAITextField{Format: openAITextFormat{
			Type:   "json_schema",
			Name:   "pilot_detection_batch_response_v1",
			Strict: true,
			Schema: modelBatchResponseSchemaJSON,
		}},
		Tools:           []any{},
		ToolChoice:      "none",
		Store:           false,
		Stream:          false,
		MaxOutputTokens: 2048,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ModelBatchResponse{}, newProviderError(KindClientError, "marshal payload: %v", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.BaseURL+"/responses", bytes.NewReader(body))
	if err != nil {
		return ModelBatchResponse{}, newProviderError(KindClientError, "build request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.APIKey)
	}

	resp, err := p.client().Do(httpReq)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ModelBatchResponse{}, newProviderError(KindTimeout, "openai request timed out: %v", err)
		}
		return ModelBatchResponse{}, newProviderError(KindNetwork, "openai request failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ModelBatchResponse{}, newProviderError(classifyHTTPStatus(resp.StatusCode), "openai http %d: %s", resp.StatusCode, truncateForError(respBody))
	}

	var env openAIResponseEnvelope
	if err := json.Unmarshal(respBody, &env); err != nil {
		return ModelBatchResponse{}, newProviderError(KindInvalidStructured, "openai response envelope: %v", err)
	}
	if env.Error != nil {
		return ModelBatchResponse{}, newProviderError(KindProviderRejected, "openai error: %s", env.Error.Message)
	}
	switch env.Status {
	case "completed":
		// continue
	case "incomplete":
		return ModelBatchResponse{}, newProviderError(KindProviderRejected, "openai response status=incomplete")
	case "failed", "cancelled":
		return ModelBatchResponse{}, newProviderError(KindProviderRejected, "openai response status=%s", env.Status)
	case "queued", "in_progress":
		return ModelBatchResponse{}, newProviderError(KindProviderRejected, "openai response status=%s is invalid in a synchronous call", env.Status)
	default:
		return ModelBatchResponse{}, newProviderError(KindProviderRejected, "openai response unexpected status=%q", env.Status)
	}

	var assistantMsgs []openAIOutputItem
	for _, item := range env.Output {
		if item.Type == "message" && item.Role == "assistant" && item.Status == "completed" {
			assistantMsgs = append(assistantMsgs, item)
		}
	}
	if len(assistantMsgs) != 1 {
		return ModelBatchResponse{}, newProviderError(KindInvalidStructured, "openai response has %d completed assistant messages, want exactly 1", len(assistantMsgs))
	}

	for _, c := range assistantMsgs[0].Content {
		if c.Type == "refusal" {
			return ModelBatchResponse{}, newProviderError(KindRefusal, "openai refused: %s", c.Refusal)
		}
	}

	var outputTexts []string
	for _, c := range assistantMsgs[0].Content {
		if c.Type == "output_text" {
			outputTexts = append(outputTexts, c.Text)
		}
	}
	if len(outputTexts) != 1 {
		return ModelBatchResponse{}, newProviderError(KindInvalidStructured, "openai response has %d output_text items, want exactly 1", len(outputTexts))
	}

	batchResp, verr := ValidateBatchResponse([]byte(outputTexts[0]), req)
	if verr != nil {
		return ModelBatchResponse{}, newProviderError(KindInvalidStructured, "openai output_text: %w", verr)
	}
	return batchResp, nil
}

// classifyHTTPStatus maps an HTTP status code onto spec §34's retry/circuit
// classification: 429 retryable+health-failure, 5xx retryable+health-
// failure, everything else 4xx neither (400/401/403/404 explicitly, and
// any other 4xx by the same reasoning: a client/config problem, not
// provider unhealth).
func classifyHTTPStatus(code int) ProviderErrorKind {
	switch {
	case code == http.StatusTooManyRequests:
		return KindRateLimited
	case code >= 500:
		return KindServerError
	default:
		return KindClientError
	}
}

func truncateForError(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "...(truncated)"
	}
	return string(b)
}
