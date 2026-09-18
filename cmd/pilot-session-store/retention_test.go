package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/sessionstore"
)

// TestRunRetentionSweepPurgesOnlyOldSessions proves the sweep wrapper
// purges sessions older than the retention period and leaves recent
// ones untouched — internal/sessionstore's own tests cover
// DeleteSessionPayload/SessionsOlderThan in isolation; this proves
// runRetentionSweep wires them together correctly end to end.
func TestRunRetentionSweepPurgesOnlyOldSessions(t *testing.T) {
	store := newTestStoreForIngestAPI(t)
	ctx := context.Background()

	if err := store.StartSession(ctx, sessionstore.SessionStart{
		SessionID: "sess-old", User: "alice", Target: "t", StartedAt: time.Now().Add(-100 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("StartSession(old): %v", err)
	}
	if _, err := store.IngestEvents(ctx, "sess-old", []sessionstore.IngestEvent{{Seq: 1, Data: []byte("x")}}); err != nil {
		t.Fatalf("IngestEvents(old): %v", err)
	}
	if err := store.StartSession(ctx, sessionstore.SessionStart{
		SessionID: "sess-recent", User: "alice", Target: "t", StartedAt: time.Now().Add(-1 * time.Hour),
	}); err != nil {
		t.Fatalf("StartSession(recent): %v", err)
	}
	if _, err := store.IngestEvents(ctx, "sess-recent", []sessionstore.IngestEvent{{Seq: 1, Data: []byte("y")}}); err != nil {
		t.Fatalf("IngestEvents(recent): %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	purged, err := runRetentionSweep(ctx, store, 90*24*time.Hour, logger)
	if err != nil {
		t.Fatalf("runRetentionSweep: %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged = %d, want 1", purged)
	}

	oldSummary, err := store.GetSession(ctx, "sess-old")
	if err != nil {
		t.Fatalf("GetSession(sess-old): %v", err)
	}
	if oldSummary.EventCount != 0 || oldSummary.Bytes != 0 {
		t.Fatalf("sess-old after sweep = %+v, want purged (EventCount=0 Bytes=0)", oldSummary)
	}

	recentSummary, err := store.GetSession(ctx, "sess-recent")
	if err != nil {
		t.Fatalf("GetSession(sess-recent): %v", err)
	}
	if recentSummary.EventCount != 1 {
		t.Fatalf("sess-recent after sweep = %+v, want untouched (EventCount=1)", recentSummary)
	}

	// A second sweep must be a no-op (already-purged sessions must not
	// be selected again).
	purgedAgain, err := runRetentionSweep(ctx, store, 90*24*time.Hour, logger)
	if err != nil {
		t.Fatalf("second runRetentionSweep: %v", err)
	}
	if purgedAgain != 0 {
		t.Fatalf("second sweep purged = %d, want 0 (idempotent)", purgedAgain)
	}
}
