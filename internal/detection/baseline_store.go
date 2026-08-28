package detection

import (
	"fmt"
	"time"
)

// BaselineSampleRecord is one persisted robust-baseline-v1 history bucket
// (spec §14) — the durable mirror of HostBaselineStore's in-memory map, so
// a process restart doesn't cold-start the 120-minute warm-up (spec
// §14.1) every time the daemon restarts.
type BaselineSampleRecord struct {
	PilotHost string
	Feature   string
	BucketTS  int64
	Value     float64
}

// SaveBaselineSamples upserts a batch of observed samples and, for every
// distinct (host, feature) pair the batch touches, prunes any bucket older
// than baselineWindowSeconds relative to evaluationTime — the same 24h
// eviction horizon HostBaselineStore.Evict already enforces in memory
// (spec §14.2), kept in sync here so the table never grows unbounded. All
// in one transaction.
func (s *Store) SaveBaselineSamples(records []BaselineSampleRecord, evaluationTime int64) (err error) {
	if len(records) == 0 {
		return nil
	}
	tx, txErr := s.db.Begin()
	if txErr != nil {
		return fmt.Errorf("begin save baseline samples: %w", txErr)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	upsert, prepErr := tx.Prepare(`
		INSERT INTO baseline_samples (pilot_host, feature, bucket_ts, value)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (pilot_host, feature, bucket_ts) DO UPDATE SET value=excluded.value
	`)
	if prepErr != nil {
		err = fmt.Errorf("prepare upsert baseline_samples: %w", prepErr)
		return err
	}
	defer upsert.Close()

	cutoff := evaluationTime - baselineWindowSeconds
	pruned := map[[2]string]bool{}
	for _, r := range records {
		if _, execErr := upsert.Exec(r.PilotHost, r.Feature, r.BucketTS, r.Value); execErr != nil {
			err = fmt.Errorf("upsert baseline sample %s/%s: %w", r.PilotHost, r.Feature, execErr)
			return err
		}
		key := [2]string{r.PilotHost, r.Feature}
		if pruned[key] {
			continue
		}
		pruned[key] = true
		if _, execErr := tx.Exec(`DELETE FROM baseline_samples WHERE pilot_host=? AND feature=? AND bucket_ts<?`,
			r.PilotHost, r.Feature, cutoff); execErr != nil {
			err = fmt.Errorf("prune baseline samples %s/%s: %w", r.PilotHost, r.Feature, execErr)
			return err
		}
	}
	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit save baseline samples: %w", commitErr)
		return err
	}
	return nil
}

// LoadBaselineHistory reads every baseline sample newer than
// now-baselineWindowSeconds (24h) into a fresh HostBaselineStore — the
// startup warm-start path (spec §14.1/§14.2). Without it, robust-
// baseline-v1's 120-bucket history requirement cold-starts on every
// process restart regardless of how long this host has actually been
// observed; an empty/absent table (fresh install) simply yields an empty
// store, identical to NewHostBaselineStore().
func (s *Store) LoadBaselineHistory(now time.Time) (*HostBaselineStore, error) {
	cutoff := now.Unix() - baselineWindowSeconds
	rows, err := s.db.Query(`SELECT pilot_host, feature, bucket_ts, value FROM baseline_samples WHERE bucket_ts >= ?`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query baseline_samples: %w", err)
	}
	defer rows.Close()

	store := NewHostBaselineStore()
	for rows.Next() {
		var host, feature string
		var bucketTS int64
		var value float64
		if scanErr := rows.Scan(&host, &feature, &bucketTS, &value); scanErr != nil {
			return nil, fmt.Errorf("scan baseline_samples row: %w", scanErr)
		}
		store.LoadSample(host, feature, bucketTS, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate baseline_samples: %w", err)
	}
	return store, nil
}
