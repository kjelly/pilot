package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// exportStore serves one session to the export command and records the
// order and purpose of the calls it received.
type exportStore struct {
	mu    sync.Mutex
	calls []string
}

func (s *exportStore) handler(started time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		call := r.URL.Path
		if p := r.URL.Query().Get("purpose"); p != "" {
			call += "?purpose=" + p
		}
		s.calls = append(s.calls, call)
		s.mu.Unlock()
		switch r.URL.Path {
		case "/v1/sessions/sess-exp":
			_ = json.NewEncoder(w).Encode(sessionSummary{SessionID: "sess-exp", StartedAt: started.Format(time.RFC3339Nano), Complete: true})
		case "/v1/sessions/sess-exp/replay":
			_ = json.NewEncoder(w).Encode(replayResult{SessionID: "sess-exp", Complete: true, Events: []replayEvent{
				{Seq: 1, Stream: "resize", Rows: 30, Cols: 100},
				{Seq: 2, Stream: "tty_output", OffsetNanos: 5e8, DataBase64: "aGk="},
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(sessionStoreErrorResponse{Error: "not found"})
		}
	}
}

func (s *exportStore) callLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func startExportStore(t *testing.T) (*sessionStoreClient, *exportStore, time.Time) {
	t.Helper()
	started := time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)
	st := &exportStore{}
	client, cleanup := testSessionStoreServer(t, st.handler(started))
	t.Cleanup(cleanup)
	return client, st, started
}

// TestSessionExport_WritesPrivateFileAfterShow: export reads the summary
// first (for started_at), then replays with purpose=export, and writes a
// 0600 asciicast file.
func TestSessionExport_WritesPrivateFileAfterShow(t *testing.T) {
	client, st, started := startExportStore(t)
	out := filepath.Join(t.TempDir(), "session.cast")
	if err := runSessionExport(context.Background(), client, "sess-exp", "asciicast-v2", out, false, nil); err != nil {
		t.Fatalf("runSessionExport: %v", err)
	}
	if calls := st.callLog(); strings.Join(calls, " ") != "/v1/sessions/sess-exp /v1/sessions/sess-exp/replay?purpose=export" {
		t.Fatalf("store calls = %v, want show then replay?purpose=export", calls)
	}
	info, err := os.Stat(out)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	b, _ := os.ReadFile(out)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var header map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatal(err)
	}
	if header["timestamp"] != float64(started.Unix()) || header["width"] != float64(100) || header["height"] != float64(30) {
		t.Fatalf("header = %v", header)
	}
	if lines[len(lines)-1] != `[0.5,"o","hi"]` {
		t.Fatalf("last event = %s", lines[len(lines)-1])
	}
}

// TestSessionExport_ForceOverwrites: an existing file is refused without
// --force (before any store call) and replaced with 0600 with it.
func TestSessionExport_ForceOverwrites(t *testing.T) {
	client, st, _ := startExportStore(t)
	out := filepath.Join(t.TempDir(), "session.cast")
	if err := os.WriteFile(out, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runSessionExport(context.Background(), client, "sess-exp", "asciicast-v2", out, false, nil)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("export over an existing file = %v, want a --force refusal", err)
	}
	if b, _ := os.ReadFile(out); string(b) != "keep" || len(st.callLog()) != 0 {
		t.Fatalf("refused export touched the file or the store: %q, calls %v", b, st.callLog())
	}
	if err := runSessionExport(context.Background(), client, "sess-exp", "asciicast-v2", out, true, nil); err != nil {
		t.Fatalf("export --force: %v", err)
	}
	info, _ := os.Stat(out)
	b, _ := os.ReadFile(out)
	if info.Mode().Perm() != 0o600 || !strings.HasPrefix(string(b), `{"height":30`) {
		t.Fatalf("forced export mode %o content %q", info.Mode().Perm(), b)
	}
}

func TestSessionExport_Stdout(t *testing.T) {
	client, _, _ := startExportStore(t)
	var buf bytes.Buffer
	if err := runSessionExport(context.Background(), client, "sess-exp", "asciicast-v2", "-", false, &buf); err != nil {
		t.Fatalf("runSessionExport: %v", err)
	}
	if !strings.Contains(buf.String(), `"title":"pilot session sess-exp"`) {
		t.Fatalf("stdout = %q", buf.String())
	}
}

func TestSessionExport_RejectsBadArguments(t *testing.T) {
	client, st, _ := startExportStore(t)
	if err := runSessionExport(context.Background(), client, "sess-exp", "json", "-", false, &bytes.Buffer{}); err == nil {
		t.Fatal("an unsupported format was accepted")
	}
	if err := runSessionExport(context.Background(), client, "sess-exp", "asciicast-v2", "", false, nil); err == nil {
		t.Fatal("a missing --output was accepted")
	}
	if err := runSessionExport(context.Background(), client, "missing", "asciicast-v2", "-", false, &bytes.Buffer{}); err == nil {
		t.Fatal("an unknown session was exported")
	}
	if calls := st.callLog(); len(calls) != 1 {
		t.Fatalf("store calls = %v, want only the failed show", calls)
	}
}
