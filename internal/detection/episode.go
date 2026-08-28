package detection

import (
	"database/sql"
	"fmt"
	"time"
)

// EpisodeRecord mirrors the signal_episodes row shape (spec §24).
type EpisodeRecord struct {
	SignalID             string
	Fingerprint          string
	PilotHost            string
	Site                 string
	ProfileID            string
	ProfileVersion       int
	State                string
	Severity             string // "" persists as SQL NULL
	CategoryHint         string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	Revision             int
	LastScore            *float64
	LastConfidence       *float64
	WarningBits          int
	WarningCount         int
	CriticalStreak       int
	RecoveryStreak       int
	CandidateClearStreak int
}

// HistoryRecord mirrors one signal_history row (spec §24).
type HistoryRecord struct {
	SignalID    string
	Revision    int
	EventType   string
	PayloadJSON string
	CreatedAt   time.Time
}

// OutboxRecord mirrors one outbox row queued at transition time (spec §24,
// §25). ID must be caller-supplied and unique (a ULID is a natural fit).
type OutboxRecord struct {
	ID            string
	SignalID      string
	Revision      int
	Sequence      int
	Kind          string
	PayloadJSON   string
	NextAttemptAt time.Time
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// ApplyTransition persists one lifecycle transition atomically (spec §25):
// upsert signal_episodes, insert signal_history, and insert every required
// outbox row in a SINGLE SQLite transaction. No HTTP delivery may happen
// before this commits, and a failed commit must leave no partial state —
// both are satisfied structurally here since outbox rows are written in
// the same transaction as the episode/history rows, never queued
// in-memory for a later separate write.
func (s *Store) ApplyTransition(episode EpisodeRecord, history HistoryRecord, outbox []OutboxRecord) (err error) {
	tx, txErr := s.db.Begin()
	if txErr != nil {
		return fmt.Errorf("begin transition: %w", txErr)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	_, execErr := tx.Exec(`
		INSERT INTO signal_episodes (
			signal_id, fingerprint, pilot_host, site, profile_id, profile_version,
			state, severity, category_hint, created_at, updated_at, revision,
			last_score, last_confidence, warning_bits, warning_count,
			critical_streak, recovery_streak, candidate_clear_streak
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(signal_id) DO UPDATE SET
			state=excluded.state,
			severity=excluded.severity,
			category_hint=excluded.category_hint,
			updated_at=excluded.updated_at,
			revision=excluded.revision,
			last_score=excluded.last_score,
			last_confidence=excluded.last_confidence,
			warning_bits=excluded.warning_bits,
			warning_count=excluded.warning_count,
			critical_streak=excluded.critical_streak,
			recovery_streak=excluded.recovery_streak,
			candidate_clear_streak=excluded.candidate_clear_streak
	`,
		episode.SignalID, episode.Fingerprint, episode.PilotHost, episode.Site,
		episode.ProfileID, episode.ProfileVersion, episode.State, nullString(episode.Severity),
		episode.CategoryHint, rfc3339(episode.CreatedAt), rfc3339(episode.UpdatedAt), episode.Revision,
		episode.LastScore, episode.LastConfidence, episode.WarningBits, episode.WarningCount,
		episode.CriticalStreak, episode.RecoveryStreak, episode.CandidateClearStreak,
	)
	if execErr != nil {
		err = fmt.Errorf("upsert signal_episodes: %w", execErr)
		return err
	}

	_, execErr = tx.Exec(`
		INSERT INTO signal_history (signal_id, revision, event_type, payload_json, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, history.SignalID, history.Revision, history.EventType, history.PayloadJSON, rfc3339(history.CreatedAt))
	if execErr != nil {
		err = fmt.Errorf("insert signal_history: %w", execErr)
		return err
	}

	for _, o := range outbox {
		_, execErr = tx.Exec(`
			INSERT INTO outbox (
				id, signal_id, revision, sequence, kind, payload_json,
				status, attempts, next_attempt_at, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)
		`, o.ID, o.SignalID, o.Revision, o.Sequence, o.Kind, o.PayloadJSON,
			rfc3339(o.NextAttemptAt), rfc3339(time.Now()), rfc3339(time.Now()))
		if execErr != nil {
			err = fmt.Errorf("insert outbox row (signal=%s seq=%d): %w", o.SignalID, o.Sequence, execErr)
			return err
		}
	}

	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit transition: %w", commitErr)
		return err
	}
	return nil
}

// GetEpisodeByFingerprint returns the active (state <> 'resolved') episode
// for a fingerprint, if any (spec §21: dedup — an active episode with the
// same fingerprint is updated in place rather than duplicated).
func (s *Store) GetEpisodeByFingerprint(fingerprint string) (*EpisodeRecord, error) {
	row := s.db.QueryRow(`
		SELECT signal_id, fingerprint, pilot_host, site, profile_id, profile_version,
			state, severity, category_hint, created_at, updated_at, revision,
			last_score, last_confidence, warning_bits, warning_count,
			critical_streak, recovery_streak, candidate_clear_streak
		FROM signal_episodes
		WHERE fingerprint = ? AND state <> 'resolved'
	`, fingerprint)
	var e EpisodeRecord
	var severity sql.NullString
	var createdAt, updatedAt string
	if err := row.Scan(
		&e.SignalID, &e.Fingerprint, &e.PilotHost, &e.Site, &e.ProfileID, &e.ProfileVersion,
		&e.State, &severity, &e.CategoryHint, &createdAt, &updatedAt, &e.Revision,
		&e.LastScore, &e.LastConfidence, &e.WarningBits, &e.WarningCount,
		&e.CriticalStreak, &e.RecoveryStreak, &e.CandidateClearStreak,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get episode by fingerprint: %w", err)
	}
	e.Severity = severity.String
	e.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	e.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &e, nil
}

// GetEpisode returns one episode by signal_id, or nil if it does not exist.
func (s *Store) GetEpisode(signalID string) (*EpisodeRecord, error) {
	row := s.db.QueryRow(`
		SELECT signal_id, fingerprint, pilot_host, site, profile_id, profile_version,
			state, severity, category_hint, created_at, updated_at, revision,
			last_score, last_confidence, warning_bits, warning_count,
			critical_streak, recovery_streak, candidate_clear_streak
		FROM signal_episodes
		WHERE signal_id = ?
	`, signalID)
	var e EpisodeRecord
	var severity sql.NullString
	var createdAt, updatedAt string
	if err := row.Scan(
		&e.SignalID, &e.Fingerprint, &e.PilotHost, &e.Site, &e.ProfileID, &e.ProfileVersion,
		&e.State, &severity, &e.CategoryHint, &createdAt, &updatedAt, &e.Revision,
		&e.LastScore, &e.LastConfidence, &e.WarningBits, &e.WarningCount,
		&e.CriticalStreak, &e.RecoveryStreak, &e.CandidateClearStreak,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get episode: %w", err)
	}
	e.Severity = severity.String
	e.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	e.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &e, nil
}

// ListActiveEpisodes returns every non-resolved episode, ordered by
// signal_id for deterministic output (spec §7's `signals list`).
func (s *Store) ListActiveEpisodes() ([]EpisodeRecord, error) {
	rows, err := s.db.Query(`
		SELECT signal_id, fingerprint, pilot_host, site, profile_id, profile_version,
			state, severity, category_hint, created_at, updated_at, revision,
			last_score, last_confidence, warning_bits, warning_count,
			critical_streak, recovery_streak, candidate_clear_streak
		FROM signal_episodes
		WHERE state <> 'resolved'
		ORDER BY signal_id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list active episodes: %w", err)
	}
	defer rows.Close()

	var out []EpisodeRecord
	for rows.Next() {
		var e EpisodeRecord
		var severity sql.NullString
		var createdAt, updatedAt string
		if err := rows.Scan(
			&e.SignalID, &e.Fingerprint, &e.PilotHost, &e.Site, &e.ProfileID, &e.ProfileVersion,
			&e.State, &severity, &e.CategoryHint, &createdAt, &updatedAt, &e.Revision,
			&e.LastScore, &e.LastConfidence, &e.WarningBits, &e.WarningCount,
			&e.CriticalStreak, &e.RecoveryStreak, &e.CandidateClearStreak,
		); err != nil {
			return nil, fmt.Errorf("scan episode: %w", err)
		}
		e.Severity = severity.String
		e.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		e.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		out = append(out, e)
	}
	return out, rows.Err()
}
