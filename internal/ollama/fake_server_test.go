package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOllama is a minimal /api/chat + /api/embeddings + /api/tags stub
// for use in tests. It records every request and dispatches scripted
// responses based on the most recent user message.
type fakeOllama struct {
	mu              sync.Mutex
	requests        []recordedRequest
	chatScript      []ChatResponse // returned one per call to /api/chat
	embedDim        int            // dimension of returned embeddings
	embedErr        error          // if set, /api/embeddings returns 500
	streamNDJSON    bool           // emit streaming NDJSON instead of single response
	blockAfterChunk bool           // when true, block after first chunk to test cancellation
}

type recordedRequest struct {
	Method string
	Path   string
	Body   string
}

func newFakeOllama() *fakeOllama {
	return &fakeOllama{embedDim: 4}
}

func (f *fakeOllama) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		fmt.Fprint(w, `{"models":[{"name":"qwen2.5:3b"},{"name":"qwen3-embedding:4b"}]}`)
	})
	mux.HandleFunc("/api/embeddings", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if f.embedErr != nil {
			http.Error(w, f.embedErr.Error(), http.StatusInternalServerError)
			return
		}
		vec := make([]float32, f.embedDim)
		for i := range vec {
			vec[i] = float32(i+1) * 0.1
		}
		resp := struct {
			Embedding []float32 `json:"embedding"`
		}{Embedding: vec}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/chat", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		f.mu.Lock()
		if len(f.chatScript) == 0 {
			f.mu.Unlock()
			http.Error(w, "no scripted response", http.StatusInternalServerError)
			return
		}
		resp := f.chatScript[0]
		f.chatScript = f.chatScript[1:]
		f.mu.Unlock()

		if f.streamNDJSON {
			w.Header().Set("Content-Type", "application/x-ndjson")
			flusher, _ := w.(http.Flusher)
			// Emit one chunk.
			fmt.Fprintf(w, `{"message":{"role":"assistant","content":%q},"done":false}`+"\n", resp.Message.Content)
			if flusher != nil {
				flusher.Flush()
			}
			if f.blockAfterChunk {
				// Hold the connection open so the client must cancel.
				<-r.Context().Done()
				return
			}
			fmt.Fprintf(w, `{"done":true}`+"\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}

func (f *fakeOllama) record(r *http.Request) {
	body := ""
	if r.Body != nil {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		body = string(buf[:n])
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, recordedRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Body:   body,
	})
}

func (f *fakeOllama) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// TestFakeOllamaChatReturnsScriptedResponse exercises the non-streaming
// /api/chat code path: the Client returns the scripted ChatResponse
// verbatim.
func TestFakeOllamaChatReturnsScriptedResponse(t *testing.T) {
	fo := newFakeOllama()
	fo.chatScript = []ChatResponse{
		{Message: Message{Role: "assistant", Content: "hello"}},
	}
	srv := httptest.NewServer(fo.handler())
	defer srv.Close()

	c := NewClient(srv.URL, "qwen2.5:3b")
	got, err := c.Chat(context.Background(),
		[]Message{{Role: "user", Content: "ping"}},
		nil,
	)
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if got.Message.Content != "hello" {
		t.Errorf("got %q, want %q", got.Message.Content, "hello")
	}
	if fo.requestCount() < 1 {
		t.Errorf("expected at least one request recorded")
	}
}

// TestFakeOllamaStreamReassembles exercises the streaming /api/chat
// path: the Client emits NDJSON chunks via onChunk and returns the
// concatenated final message.
func TestFakeOllamaStreamReassembles(t *testing.T) {
	fo := newFakeOllama()
	fo.streamNDJSON = true
	// ChatStream emits NDJSON then re-fetches as non-streaming when no
	// tool calls are returned. Provide two scripted responses so both
	// calls succeed.
	fo.chatScript = []ChatResponse{
		{Message: Message{Role: "assistant", Content: "world"}},
		{Message: Message{Role: "assistant", Content: "world"}},
	}
	srv := httptest.NewServer(fo.handler())
	defer srv.Close()

	c := NewClient(srv.URL, "qwen2.5:3b")
	chunks := []string{}
	_, err := c.ChatStream(context.Background(),
		[]Message{{Role: "user", Content: "ping"}},
		nil,
		func(content, _ string) {
			if content != "" {
				chunks = append(chunks, content)
			}
		},
	)
	if err != nil {
		t.Fatalf("ChatStream: %v", err)
	}
	joined := strings.Join(chunks, "")
	if joined != "world" {
		t.Errorf("streamed content = %q, want %q", joined, "world")
	}
}

// TestFakeOllamaEmbeddingsReturnsVector exercises the /api/embeddings
// path: the Client decodes the embedding into the right dimension.
func TestFakeOllamaEmbeddingsReturnsVector(t *testing.T) {
	fo := newFakeOllama()
	srv := httptest.NewServer(fo.handler())
	defer srv.Close()

	c := NewClient(srv.URL, "qwen2.5:3b")
	c.SetEmbeddingModel("qwen3-embedding:4b")
	vec, err := c.Embeddings(context.Background(), "query")
	if err != nil {
		t.Fatalf("Embeddings: %v", err)
	}
	if len(vec) != 4 {
		t.Errorf("got dim %d, want 4", len(vec))
	}
}

// TestFakeOllamaEmbeddingsPropagatesError verifies that a 500 from
// /api/embeddings surfaces as a Go error, not silent zeros.
func TestFakeOllamaEmbeddingsPropagatesError(t *testing.T) {
	fo := newFakeOllama()
	fo.embedErr = fmt.Errorf("upstream on fire")
	srv := httptest.NewServer(fo.handler())
	defer srv.Close()

	c := NewClient(srv.URL, "qwen2.5:3b")
	_, err := c.Embeddings(context.Background(), "query")
	if err == nil {
		t.Fatal("expected error when /api/embeddings returns 500")
	}
	if !strings.Contains(err.Error(), "upstream on fire") {
		t.Errorf("error should wrap the upstream message, got: %v", err)
	}
}

// TestFakeOllamaPingSucceeds covers the simple Ping path so the
// fixture is usable from other tests.
func TestFakeOllamaPingSucceeds(t *testing.T) {
	fo := newFakeOllama()
	srv := httptest.NewServer(fo.handler())
	defer srv.Close()

	c := NewClient(srv.URL, "qwen2.5:3b")
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

// Compile-time check that httptest is reachable.
var _ = httptest.NewServer
var _ = time.Second


// TestFakeOllamaStreamHonoursContextCancellation verifies that
// ChatStream returns ctx.Err() when the caller cancels the context
// mid-stream.
func TestFakeOllamaStreamHonoursContextCancellation(t *testing.T) {
	fo := newFakeOllama()
	fo.streamNDJSON = true
	// Emit ONE chunk then block forever on the next read.
	fo.blockAfterChunk = true
	fo.chatScript = []ChatResponse{
		{Message: Message{Role: "assistant", Content: "first"}},
		{Message: Message{Role: "assistant", Content: "second"}},
	}
	srv := httptest.NewServer(fo.handler())
	defer srv.Close()

	c := NewClient(srv.URL, "qwen2.5:3b")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err := c.ChatStream(ctx, []Message{{Role: "user", Content: "x"}}, nil, func(string, string) {})
	if err == nil {
		t.Fatal("expected ctx cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
