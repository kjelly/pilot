package ollama

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	model   string
	http    *http.Client
}

// defaultHTTPTimeout caps any single Ollama HTTP call when the
// caller passes a context without a deadline (i.e. context.Background()
// or the agent loop's root context). Per-call contexts with their own
// deadlines still take precedence — http.Client's built-in Timeout
// is only used when the context has no deadline. 2 minutes is well
// above the slowest real call we've seen (a streaming chat with the
// cloud model cold-starts in ~5s and finishes inside 30s for the
// playbooks used in CI).
const defaultHTTPTimeout = 2 * time.Minute

func NewClient(baseURL, model string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		http:    &http.Client{Timeout: defaultHTTPTimeout},
	}
}

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type ToolCall struct {
	Function ToolCallFunction `json:"function"`
}

type ToolCallFunction struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type ChatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Tools    []Tool    `json:"tools,omitempty"`
	Stream   bool      `json:"stream"`
	Think    bool      `json:"think,omitempty"`
}

type ChatResponse struct {
	Model      string  `json:"model"`
	Message    Message `json:"message"`
	DoneReason string  `json:"done_reason,omitempty"`
	Error      string  `json:"error,omitempty"`
}

type StreamChunk struct {
	Model   string `json:"model"`
	Message struct {
		Role      string     `json:"role"`
		Content   string     `json:"content"`
		Thinking  string     `json:"thinking,omitempty"`
		ToolCalls []ToolCall `json:"tool_calls,omitempty"`
		Done      bool       `json:"done"`
	} `json:"message"`
	Done bool `json:"done"`
}

// Chat sends a non-streaming chat request
func (c *Client) Chat(ctx context.Context, messages []Message, tools []Tool) (*ChatResponse, error) {
	req := ChatRequest{
		Model:    c.model,
		Messages: messages,
		Tools:    tools,
		Stream:   false,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama returned %d: %s", resp.StatusCode, string(errBody))
	}

	var result ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if result.Error != "" {
		return nil, fmt.Errorf("ollama error: %s", result.Error)
	}
	return &result, nil
}

// ChatStream sends a streaming chat request, calling onChunk for each event.
// Returns the final assembled message.
func (c *Client) ChatStream(ctx context.Context, messages []Message, tools []Tool, onChunk func(content, thinking string)) (*ChatResponse, error) {
	req := ChatRequest{
		Model:    c.model,
		Messages: messages,
		Tools:    tools,
		Stream:   true,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama returned %d: %s", resp.StatusCode, string(errBody))
	}

	final := &ChatResponse{Model: c.model}
	final.Message.Role = "assistant"
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		// Honour context cancellation between chunks. The scanner
		// blocks on the next chunk read, so we have to poll ctx
		// at the top of each iteration rather than mid-read.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var chunk StreamChunk
		if err := json.Unmarshal(line, &chunk); err != nil {
			continue
		}
		if len(chunk.Message.ToolCalls) > 0 {
			final.Message.ToolCalls = append(final.Message.ToolCalls, chunk.Message.ToolCalls...)
		}
		if chunk.Message.Content != "" {
			final.Message.Content += chunk.Message.Content
			if onChunk != nil {
				onChunk(chunk.Message.Content, "")
			}
		}
		if chunk.Message.Thinking != "" {
			if onChunk != nil {
				onChunk("", chunk.Message.Thinking)
			}
		}
		if chunk.Done {
			return final, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return final, nil
}

// ListModels lists available Ollama models
func (c *Client) ListModels(ctx context.Context) ([]string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/tags", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(result.Models))
	for _, m := range result.Models {
		names = append(names, m.Name)
	}
	return names, nil
}

// Ping checks if the Ollama server is reachable
func (c *Client) Ping(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama returned %d", resp.StatusCode)
	}
	return nil
}
