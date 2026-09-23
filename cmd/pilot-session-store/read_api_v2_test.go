package main

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/sessionstore"
)

func TestReadAPISummaryIncludesPolicySourceAndLastSeq(t *testing.T) {
	store := newTestStoreForIngestAPI(t)
	ctx := context.Background()
	jti := strings.Repeat("c", 32)
	if err := store.StartSession(ctx, sessionstore.SessionStart{
		SessionID: "sess-v2", User: "alice", GatewayID: "gw01", Scope: "gpu", Target: "t.example.test",
		RecordingMode: "terminal_output", RecordingPolicySource: "host", IngestJTI: jti,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.IngestEvents(ctx, "sess-v2", []sessionstore.IngestEvent{{Seq: 1, Stream: "tty_output", Data: []byte("x")}}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishSession(ctx, "sess-v2", time.Now().UTC(), true, 3); err != nil {
		t.Fatal(err)
	}

	client := testReadServer(t, store, "")
	resp, err := client.Get("http://unix/v1/sessions/sess-v2")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var got sessionSummaryJSON
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	if got.RecordingPolicySource != "host" || got.LastSeq != 3 || got.Complete {
		t.Fatalf("summary = %+v, want source host, last_seq 3, incomplete (trailing gap)", got)
	}
	if strings.Contains(string(raw), jti) || strings.Contains(string(raw), "ingest_jti") {
		t.Fatalf("read API exposes the ingest jti: %s", raw)
	}

	replayResp, err := client.Get("http://unix/v1/sessions/sess-v2/replay")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replayResp.Body.Close() }()
	var replay replayResponse
	if err := json.NewDecoder(replayResp.Body).Decode(&replay); err != nil {
		t.Fatal(err)
	}
	if replay.Complete || len(replay.Gaps) != 1 {
		t.Fatalf("replay complete=%v gaps=%+v, want the trailing gap [2,3]", replay.Complete, replay.Gaps)
	}
}
