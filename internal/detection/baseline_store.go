package detection

import (
	"fmt"
	"time"
)

// BaselineSampleRecord is one persisted robust-baseline-v1 history bucket
// (spec §14) — the durable mirror of HostBaselineStore's in-memory map, so
// a process restart doesn't cold-start the 120-minute warm-up (spec
// §14.1) every time the daemon restarts. SubjectID/SubjectKind/Site were
// added in Phase 4 (spec §9.7): the persisted uniqueness key is now
// (subject_id, subject_kind, feature, bucket_ts) — two different-kind
// subjects that happened to share an ID string (e.g. a managed host and
// an SNMP device both named "core-sw-01") must never collide in this
// table. PilotHost stays the CLI/MCP compatibility mirror column (spec
// §9.7 point 4): equal to SubjectID for a managed_host subject,
// empty-string for any other kind (see the Phase 4 runbook for why this
// package uses "" rather than a literal NULL column here).
type BaselineSampleRecord struct {
	SubjectID   string
	SubjectKind string
	Site        string
	PilotHost   string
	Feature     string
	BucketTS    int64
	Value       float64
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
			_ = tx.Rollback()
		}
	}()

	upsert, prepErr := tx.Prepare(`
		INSERT INTO baseline_samples (subject_id, subject_kind, site, pilot_host, feature, bucket_ts, value)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (subject_id, subject_kind, feature, bucket_ts) DO UPDATE SET value=excluded.value
	`)
	if prepErr != nil {
		err = fmt.Errorf("prepare upsert baseline_samples: %w", prepErr)
		return err
	}
	defer upsert.Close() //nolint:errcheck

	cutoff := evaluationTime - baselineWindowSeconds
	pruned := map[[3]string]bool{}
	for _, r := range records {
		if _, execErr := upsert.Exec(r.SubjectID, r.SubjectKind, r.Site, nullString(r.PilotHost), r.Feature, r.BucketTS, r.Value); execErr != nil {
			err = fmt.Errorf("upsert baseline sample %s/%s/%s: %w", r.SubjectID, r.SubjectKind, r.Feature, execErr)
			return err
		}
		key := [3]string{r.SubjectID, r.SubjectKind, r.Feature}
		if pruned[key] {
			continue
		}
		pruned[key] = true
		if _, execErr := tx.Exec(`DELETE FROM baseline_samples WHERE subject_id=? AND subject_kind=? AND feature=? AND bucket_ts<?`,
			r.SubjectID, r.SubjectKind, r.Feature, cutoff); execErr != nil {
			err = fmt.Errorf("prune baseline samples %s/%s/%s: %w", r.SubjectID, r.SubjectKind, r.Feature, execErr)
			return err
		}
	}
	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit save baseline samples: %w", commitErr)
		return err
	}
	return nil
}

// LoadBaselineHistory restores recent normal history and the frozen normal
// reference windows of firing/recovering subjects of the given subjectKind
// into a fresh HostBaselineStore (spec §14.1/§14.2).
// Without it, robust-baseline-v1's 120-bucket history requirement
// cold-starts on every process restart regardless of how long this
// subject has actually been observed; an empty/absent table (fresh
// install) simply yields an empty store, identical to
// NewHostBaselineStore(). subjectKind scopes the query to one Engine's own
// profile kind (spec §9.7 point 5's uniqueness key includes subject_kind)
// — without it, a managed host and an SNMP device that happened to share
// an ID and feature name could load each other's history.
func (s *Store) LoadBaselineHistory(now time.Time, subjectKind string) (*HostBaselineStore, error) {
	cutoff := now.Unix() - baselineWindowSeconds
	// Active episodes cannot learn replacement samples (§16), so applying
	// the wall-clock cutoff to their reference makes a long-running episode
	// permanently unscoreable after restart. Restore its bounded window
	// relative to the last accepted normal bucket instead. Resolved episodes
	// never extend the cutoff, and another subject kind cannot claim it.
	rows, err := s.db.Query(`
		WITH active_subjects AS (
			SELECT DISTINCT subject_id FROM signal_episodes
			WHERE subject_kind = ? AND state IN ('firing', 'recovering')
		), active_baselines AS (
			SELECT b.subject_id, b.feature, MAX(b.bucket_ts) - ? AS cutoff
			FROM active_subjects a
			JOIN baseline_samples b ON b.subject_id = a.subject_id
			WHERE b.subject_kind = ? AND b.bucket_ts <= ?
			GROUP BY b.subject_id, b.feature
		)
		SELECT b.subject_id, b.feature, b.bucket_ts, b.value
		FROM baseline_samples b
		LEFT JOIN active_baselines a ON a.subject_id = b.subject_id AND a.feature = b.feature
		WHERE b.subject_kind = ? AND b.bucket_ts <= ?
		AND b.bucket_ts >= COALESCE(a.cutoff, ?)
	`, subjectKind, baselineWindowSeconds, subjectKind, now.Unix(), subjectKind, now.Unix(), cutoff)
	if err != nil {
		return nil, fmt.Errorf("query baseline_samples: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	store := NewHostBaselineStore()
	for rows.Next() {
		var subjectID, feature string
		var bucketTS int64
		var value float64
		if scanErr := rows.Scan(&subjectID, &feature, &bucketTS, &value); scanErr != nil {
			return nil, fmt.Errorf("scan baseline_samples row: %w", scanErr)
		}
		store.LoadSample(subjectID, feature, bucketTS, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate baseline_samples: %w", err)
	}
	return store, nil
}
