package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kjelly/pilot/internal/sessionstore"
)

// runRetentionSweep purges payload for every session whose started_at is
// older than retentionPeriod (docs/tmp/now/spec.md §28.5). Each purge
// uses Store.DeleteSessionPayload's own transaction (index updated,
// payload deleted, audit record written, in that order) — a failure on
// one session is logged and skipped rather than aborting the whole
// sweep, so one bad row cannot block every other session's retention
// from converging.
func runRetentionSweep(ctx context.Context, store *sessionstore.Store, retentionPeriod time.Duration, logger *slog.Logger) (int, error) {
	cutoff := time.Now().Add(-retentionPeriod)
	ids, err := store.SessionsOlderThan(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("list sessions older than retention cutoff: %w", err)
	}
	reason := fmt.Sprintf("retention_days cutoff: started_at < %s", cutoff.UTC().Format(time.RFC3339))
	purged := 0
	for _, id := range ids {
		if err := store.DeleteSessionPayload(ctx, id, reason); err != nil {
			logger.Error("retention sweep: purge failed", "session_id", id, "error", err)
			continue
		}
		purged++
		logger.Info("retention sweep: purged session payload", "session_id", id)
	}
	return purged, nil
}
