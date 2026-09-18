package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/sessionstore"
)

func currentUsername(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current unavailable: %v", err)
	}
	return u.Username
}

func newTestStoreForReadAPI(t *testing.T) *sessionstore.Store {
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

// testReadServer starts a real readServer over a real Unix socket
// (exercising genuine SO_PEERCRED, exactly like
// internal/directoryapi/server_test.go's testServer) and returns an
// http.Client dialing it.
func testReadServer(t *testing.T, store *sessionstore.Store, auditorGroup string) *http.Client {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "read.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := newReadServer(store, auditorGroup, slog.New(slog.NewTextHandler(testWriter{t}, nil)))
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestReadAPIListGetReplay(t *testing.T) {
	store := newTestStoreForReadAPI(t)
	ctx := context.Background()
	if err := store.StartSession(ctx, sessionstore.SessionStart{
		SessionID: "sess-1", User: "alice", DirectoryID: "dir01", GatewayID: "gw01",
		Scope: "gpu", Target: "target01.example.test", RecordingMode: "terminal_output",
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	if _, err := store.IngestEvents(ctx, "sess-1", []sessionstore.IngestEvent{
		{Seq: 1, Stream: "tty_output", Data: []byte("hello over http")},
	}); err != nil {
		t.Fatalf("IngestEvents: %v", err)
	}
	if err := store.FinishSession(ctx, "sess-1", time.Now().UTC(), true); err != nil {
		t.Fatalf("FinishSession: %v", err)
	}

	client := testReadServer(t, store, "")

	resp, err := client.Get("http://unix/v1/sessions")
	if err != nil {
		t.Fatalf("GET /v1/sessions: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var listBody struct {
		Sessions []sessionSummaryJSON `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listBody); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(listBody.Sessions) != 1 || listBody.Sessions[0].SessionID != "sess-1" {
		t.Fatalf("list = %+v, want one session sess-1", listBody.Sessions)
	}

	getResp, err := client.Get("http://unix/v1/sessions/sess-1")
	if err != nil {
		t.Fatalf("GET /v1/sessions/sess-1: %v", err)
	}
	defer func() { _ = getResp.Body.Close() }()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", getResp.StatusCode)
	}

	replayResp, err := client.Get("http://unix/v1/sessions/sess-1/replay")
	if err != nil {
		t.Fatalf("GET /v1/sessions/sess-1/replay: %v", err)
	}
	defer func() { _ = replayResp.Body.Close() }()
	if replayResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", replayResp.StatusCode)
	}
	var replay replayResponse
	if err := json.NewDecoder(replayResp.Body).Decode(&replay); err != nil {
		t.Fatalf("decode replay: %v", err)
	}
	if !replay.Complete {
		t.Fatalf("replay.Complete = false, want true")
	}
	if len(replay.Events) != 1 || replay.Events[0].DataBase64 == "" {
		t.Fatalf("replay.Events = %+v, want one event with data", replay.Events)
	}
	decoded, err := base64.StdEncoding.DecodeString(replay.Events[0].DataBase64)
	if err != nil {
		t.Fatalf("decode event data: %v", err)
	}
	if string(decoded) != "hello over http" {
		t.Fatalf("replayed data = %q, want %q", decoded, "hello over http")
	}
}

func TestReadAPIGetUnknownSessionReturns404(t *testing.T) {
	store := newTestStoreForReadAPI(t)
	client := testReadServer(t, store, "")
	resp, err := client.Get("http://unix/v1/sessions/does-not-exist")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// TestReadAPIUnknownAuditorGroupFailsClosed mirrors
// internal/directoryapi's TestHandleIdentity_PortalUserGroupUnknownGroupDenies:
// a configured auditor group that does not even resolve on this host
// must deny, not silently allow.
func TestReadAPIUnknownAuditorGroupFailsClosed(t *testing.T) {
	store := newTestStoreForReadAPI(t)
	client := testReadServer(t, store, "this-group-does-not-exist-13579")
	resp, err := client.Get("http://unix/v1/sessions")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 when the configured auditor group doesn't resolve", resp.StatusCode)
	}
}

// TestReadAPINoAuditorGroupAllowsAnyPeer confirms the default (no
// auditor_group configured) behavior: any SO_PEERCRED-resolved caller is
// served — mirrors directoryapi's PortalUserGroup-unset test.
func TestReadAPINoAuditorGroupAllowsAnyPeer(t *testing.T) {
	_ = currentUsername(t) // proves user.Current works in this environment
	store := newTestStoreForReadAPI(t)
	client := testReadServer(t, store, "")
	resp, err := client.Get("http://unix/v1/sessions")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 when auditor_group is unset", resp.StatusCode)
	}
}
