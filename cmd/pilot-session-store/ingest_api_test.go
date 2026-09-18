package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/sessionstore"
)

func newTestStoreForIngestAPI(t *testing.T) *sessionstore.Store {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	enc, err := sessionstore.NewEncryptor("test-key", key)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	store, err := sessionstore.Open(filepath.Join(t.TempDir(), "index.db"), enc)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestIngestAPIFullLifecycle drives the real HTTP handlers (real
// httptest.Server, real *sessionstore.Store backed by a real temp
// SQLite file) through start -> events -> finish, proving the wire
// protocol end-to-end — the same protocol
// internal/sessionrecording.HTTPSink speaks against a real server in its
// own tests.
func TestIngestAPIFullLifecycle(t *testing.T) {
	store := newTestStoreForIngestAPI(t)
	srv := httptest.NewServer(newIngestServer(store, "correct-token").routes())
	defer srv.Close()

	post := func(path string, body any) *http.Response {
		payload, _ := json.Marshal(body)
		req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer correct-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		return resp
	}

	startResp := post("/v1/sessions/start", sessionStartRequest{
		SessionID: "sess-wire-1", User: "alice", Target: "target01", RecordingMode: "terminal_output",
	})
	defer func() { _ = startResp.Body.Close() }()
	if startResp.StatusCode != http.StatusOK {
		t.Fatalf("start status = %d, want 200", startResp.StatusCode)
	}

	eventsResp := post("/v1/sessions/sess-wire-1/events", eventsRequest{Events: []wireEvent{
		{Seq: 1, Stream: "tty_output", DataBase64: base64.StdEncoding.EncodeToString([]byte("hi"))},
	}})
	defer func() { _ = eventsResp.Body.Close() }()
	if eventsResp.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d, want 200", eventsResp.StatusCode)
	}

	finishResp := post("/v1/sessions/sess-wire-1/finish", sessionFinishRequest{Complete: true})
	defer func() { _ = finishResp.Body.Close() }()
	if finishResp.StatusCode != http.StatusOK {
		t.Fatalf("finish status = %d, want 200", finishResp.StatusCode)
	}

	summary, err := store.GetSession(t.Context(), "sess-wire-1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !summary.Complete || summary.EventCount != 1 {
		t.Fatalf("summary = %+v, want Complete=true EventCount=1", summary)
	}
}

// TestIngestAPIRejectsMissingOrWrongToken proves the bearer-token gate
// actually rejects requests, both with no Authorization header and with
// the wrong token.
func TestIngestAPIRejectsMissingOrWrongToken(t *testing.T) {
	store := newTestStoreForIngestAPI(t)
	srv := httptest.NewServer(newIngestServer(store, "correct-token").routes())
	defer srv.Close()

	body, _ := json.Marshal(sessionStartRequest{SessionID: "sess-x", User: "alice"})

	noAuthReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/sessions/start", bytes.NewReader(body))
	noAuthResp, err := http.DefaultClient.Do(noAuthReq)
	if err != nil {
		t.Fatalf("POST (no auth): %v", err)
	}
	defer func() { _ = noAuthResp.Body.Close() }()
	if noAuthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-Authorization-header status = %d, want 401", noAuthResp.StatusCode)
	}

	wrongAuthReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/sessions/start", bytes.NewReader(body))
	wrongAuthReq.Header.Set("Authorization", "Bearer wrong-token")
	wrongAuthResp, err := http.DefaultClient.Do(wrongAuthReq)
	if err != nil {
		t.Fatalf("POST (wrong token): %v", err)
	}
	defer func() { _ = wrongAuthResp.Body.Close() }()
	if wrongAuthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-token status = %d, want 401", wrongAuthResp.StatusCode)
	}
}

// TestIngestAPIEventConflictReturns409 proves a diverging retry (spec.md
// §28.1) surfaces as HTTP 409 through the real handler, not just at the
// internal/sessionstore.Store layer already covered by store_test.go.
func TestIngestAPIEventConflictReturns409(t *testing.T) {
	store := newTestStoreForIngestAPI(t)
	srv := httptest.NewServer(newIngestServer(store, "t").routes())
	defer srv.Close()

	post := func(path string, body any) *http.Response {
		payload, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer t")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		return resp
	}

	_ = post("/v1/sessions/start", sessionStartRequest{SessionID: "sess-conflict", User: "alice"}).Body.Close()
	first := post("/v1/sessions/sess-conflict/events", eventsRequest{Events: []wireEvent{{Seq: 1, Stream: "tty_output", DataBase64: base64.StdEncoding.EncodeToString([]byte("a"))}}})
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first ingest status = %d, want 200", first.StatusCode)
	}

	second := post("/v1/sessions/sess-conflict/events", eventsRequest{Events: []wireEvent{{Seq: 1, Stream: "tty_output", DataBase64: base64.StdEncoding.EncodeToString([]byte("different"))}}})
	defer func() { _ = second.Body.Close() }()
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("conflicting retry status = %d, want 409", second.StatusCode)
	}
}
