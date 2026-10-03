package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

// testSessionStoreServer starts a minimal fake pilot-session-store read
// API over a real Unix socket, serving handler-supplied JSON — this
// tests sessionStoreClient's wire decoding against the real HTTP-over-
// Unix-socket transport, not a mocked RoundTripper. The wire SHAPE
// itself (field names/nesting) is proven correct end-to-end by
// cmd/pilot-session-store's own read_api_test.go; this test only proves
// this package's client decodes that shape correctly.
func testSessionStoreServer(t *testing.T, handler http.HandlerFunc) (*sessionStoreClient, func()) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "session-store.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	cleanup := func() { _ = srv.Close(); _ = ln.Close() }
	return newSessionStoreClient(sockPath), cleanup
}

func TestSessionStoreClientListSessions(t *testing.T) {
	client, cleanup := testSessionStoreServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sessions" {
			t.Errorf("path = %s, want /v1/sessions", r.URL.Path)
		}
		if r.URL.Query().Get("user") != "alice" {
			t.Errorf("user query = %q, want alice", r.URL.Query().Get("user"))
		}
		_ = json.NewEncoder(w).Encode(listSessionsResponse{Sessions: []sessionSummary{
			{SessionID: "sess-1", User: "alice", Target: "target01", Complete: true, EventCount: 3},
		}})
	})
	defer cleanup()

	resp, err := client.ListSessions(context.Background(), "alice")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(resp.Sessions) != 1 || resp.Sessions[0].SessionID != "sess-1" {
		t.Fatalf("ListSessions = %+v, want one session sess-1", resp.Sessions)
	}
}

func TestSessionStoreClientGetSessionNotFound(t *testing.T) {
	client, cleanup := testSessionStoreServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	})
	defer cleanup()

	_, err := client.GetSession(context.Background(), "missing")
	if err == nil {
		t.Fatalf("GetSession succeeded against a 404, want an error")
	}
}

func TestSessionStoreClientReplayDecodesGapsAndEvents(t *testing.T) {
	client, cleanup := testSessionStoreServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(replayResult{
			SessionID: "sess-gap", Complete: false,
			Gaps:   []replayGap{{FromSeq: 3, ToSeq: 4}},
			Events: []replayEvent{{Seq: 1, Stream: "tty_output", DataBase64: "aGVsbG8="}},
		})
	})
	defer cleanup()

	result, err := client.Replay(context.Background(), "sess-gap", "replay")
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if result.Complete {
		t.Fatalf("Complete = true, want false (gap present)")
	}
	if len(result.Gaps) != 1 || result.Gaps[0] != (replayGap{FromSeq: 3, ToSeq: 4}) {
		t.Fatalf("Gaps = %+v", result.Gaps)
	}
	if len(result.Events) != 1 || result.Events[0].DataBase64 != "aGVsbG8=" {
		t.Fatalf("Events = %+v", result.Events)
	}
}

func TestPrintSessionListFormatsRows(t *testing.T) {
	var buf bytes.Buffer
	err := printSessionList(&buf, []sessionSummary{
		{SessionID: "sess-1", User: "alice", Target: "target01", Scope: "gpu", RecordingMode: "terminal_output", StartedAt: "2026-09-18T00:00:00Z", Complete: true, EventCount: 5},
	})
	if err != nil {
		t.Fatalf("printSessionList: %v", err)
	}
	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("sess-1")) || !bytes.Contains([]byte(out), []byte("alice")) {
		t.Fatalf("printSessionList output missing expected fields: %s", out)
	}
}
