package agentcontroller

import (
	"database/sql"
	"fmt"
	"time"
)

// Circuit breaker states (design doc §8). "A tripped breaker does not
// silently self-clear in MVP. Operator reset must be audited."
const (
	BreakerClosed = "CLOSED"
	BreakerOpen   = "OPEN"
)

// Breaker scope naming convention — three explicit prefixes so a single
// TEXT PRIMARY KEY column can hold all three scopes design doc §8
// requires (global/component/host) without a separate "kind" column.
const (
	BreakerScopeGlobal = "global"
)

func BreakerScopeComponent(component string) string { return "component:" + component }
func BreakerScopeHost(host string) string           { return "host:" + host }

// BreakerRecord is one circuit_breakers row.
type BreakerRecord struct {
	Scope      string
	State      string
	Reason     string
	TrippedAt  *time.Time
	ResetAt    *time.Time
	ResetActor string
}

// BreakerState returns scope's current record — CLOSED with no history
// when no row exists yet (a breaker that has never tripped).
func (s *Store) BreakerState(scope string) (BreakerRecord, error) {
	row := s.db.QueryRow(`SELECT scope, state, COALESCE(reason, ''), tripped_at, reset_at, COALESCE(reset_actor, '')
		FROM circuit_breakers WHERE scope = ?`, scope)
	var r BreakerRecord
	var trippedAt, resetAt sql.NullString
	if err := row.Scan(&r.Scope, &r.State, &r.Reason, &trippedAt, &resetAt, &r.ResetActor); err != nil {
		if err == sql.ErrNoRows {
			return BreakerRecord{Scope: scope, State: BreakerClosed}, nil
		}
		return BreakerRecord{}, fmt.Errorf("read breaker %s: %w", scope, err)
	}
	if trippedAt.Valid {
		if t, perr := time.Parse(time.RFC3339, trippedAt.String); perr == nil {
			r.TrippedAt = &t
		}
	}
	if resetAt.Valid {
		if t, perr := time.Parse(time.RFC3339, resetAt.String); perr == nil {
			r.ResetAt = &t
		}
	}
	return r, nil
}

// TripBreaker opens scope's breaker — upsert so tripping an already-open
// breaker just refreshes the reason/time rather than erroring (multiple
// independent triggers for the same scope are expected, not a bug).
func (s *Store) TripBreaker(scope, reason string, now time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO circuit_breakers (scope, state, reason, tripped_at, reset_at, reset_actor)
		VALUES (?, ?, ?, ?, NULL, NULL)
		ON CONFLICT(scope) DO UPDATE SET state = excluded.state, reason = excluded.reason,
			tripped_at = excluded.tripped_at, reset_at = NULL, reset_actor = NULL
	`, scope, BreakerOpen, reason, rfc3339(now))
	if err != nil {
		return fmt.Errorf("trip breaker %s: %w", scope, err)
	}
	return nil
}

// ResetBreaker closes an OPEN breaker. actor is required — an operator
// reset must be audited (design doc §8), never automatic.
func (s *Store) ResetBreaker(scope, actor, reason string, now time.Time) error {
	if actor == "" {
		return fmt.Errorf("actor is required — breaker reset must come from trusted operator context")
	}
	cur, err := s.BreakerState(scope)
	if err != nil {
		return err
	}
	if cur.State != BreakerOpen {
		return fmt.Errorf("breaker %s is %s, not OPEN — nothing to reset", scope, cur.State)
	}
	res, err := s.db.Exec(`UPDATE circuit_breakers SET state = ?, reset_at = ?, reset_actor = ?, reason = ?
		WHERE scope = ? AND state = ?`,
		BreakerClosed, rfc3339(now), actor, reason, scope, BreakerOpen)
	if err != nil {
		return fmt.Errorf("reset breaker %s: %w", scope, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("breaker %s state changed concurrently — refusing to reset", scope)
	}
	return nil
}

// ListBreakers returns every breaker that has ever tripped, for
// `autonomy status`.
func (s *Store) ListBreakers() ([]BreakerRecord, error) {
	rows, err := s.db.Query(`SELECT scope, state, COALESCE(reason, ''), tripped_at, reset_at, COALESCE(reset_actor, '')
		FROM circuit_breakers ORDER BY scope ASC`)
	if err != nil {
		return nil, fmt.Errorf("list breakers: %w", err)
	}
	defer rows.Close()
	var out []BreakerRecord
	for rows.Next() {
		var r BreakerRecord
		var trippedAt, resetAt sql.NullString
		if err := rows.Scan(&r.Scope, &r.State, &r.Reason, &trippedAt, &resetAt, &r.ResetActor); err != nil {
			return nil, fmt.Errorf("scan breaker: %w", err)
		}
		if trippedAt.Valid {
			if t, perr := time.Parse(time.RFC3339, trippedAt.String); perr == nil {
				r.TrippedAt = &t
			}
		}
		if resetAt.Valid {
			if t, perr := time.Parse(time.RFC3339, resetAt.String); perr == nil {
				r.ResetAt = &t
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
