package sessionstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Store is one pilot-session-store instance's encrypted index + payload
// database. All methods are safe for concurrent use (database/sql pools
// its own connections; SQLite's WAL mode + busy_timeout, set in
// openDB, serialize writers rather than erroring under light
// concurrency).
type Store struct {
	db  *sql.DB
	enc *Encryptor
}

// Open opens (or creates) the index database at path, using enc to seal
// and open event payloads. enc must not be nil — a Store with no
// encryptor could not honor spec.md §28.4's "recording payload 必須
// encrypted at rest" even for its very first write.
func Open(path string, enc *Encryptor) (*Store, error) {
	if enc == nil {
		return nil, fmt.Errorf("sessionstore: encryptor is required")
	}
	db, err := openDB(path)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, enc: enc}, nil
}

func (s *Store) Close() error { return s.db.Close() }

var (
	// ErrUnknownSession is returned by any operation on a session_id that
	// was never started (or was purged by retention).
	ErrUnknownSession = errors.New("sessionstore: unknown session")
	// ErrSessionConflict is returned when POST /v1/sessions/start is
	// retried with metadata that differs from the already-recorded start
	// (spec.md §28.1's retry-idempotency rule, applied to session start
	// the same way it applies to events).
	ErrSessionConflict = errors.New("sessionstore: session already started with different metadata")
	// ErrEventConflict is returned when the same (session_id, seq) is
	// ingested twice with a different payload (spec.md §28.1: "重送同
	// sequence: different payload → conflict / audit error").
	ErrEventConflict = errors.New("sessionstore: event payload conflict for existing sequence")
	// ErrSessionFinished rejects any write to a session that has already
	// been finished (per-host recording spec §21.2): events after finish, a
	// start that would reopen it, or a finish with a different outcome.
	ErrSessionFinished = errors.New("sessionstore: session already finished")
	// ErrLastSeqTooLow rejects a finish whose last_seq is below an already
	// stored event's seq.
	ErrLastSeqTooLow = errors.New("sessionstore: finish last_seq below a stored event seq")
)

// SessionStart is the metadata POST /v1/sessions/start carries — one row
// in spec.md §28.3's index.
type SessionStart struct {
	SessionID     string
	User          string
	DirectoryID   string
	GatewayID     string
	Scope         string
	Target        string
	RecordingMode string
	StartedAt     time.Time
	// RecordingPolicySource is where the gateway resolved the recording
	// mode from (host | gateway_default), taken from the signed token.
	RecordingPolicySource string
	// IngestJTI is the signed token's jti; every later events/finish call
	// must present a token with the same jti.
	IngestJTI string
}

// StartSession records a new session, or — if session_id was already
// started with identical core metadata — succeeds as a no-op (retry
// idempotency). Metadata that differs from the existing row is a
// conflict: a session_id must identify exactly one logical session for
// its whole lifetime.
func (s *Store) StartSession(ctx context.Context, in SessionStart) error {
	if in.SessionID == "" {
		return fmt.Errorf("sessionstore: session_id is required")
	}
	if in.StartedAt.IsZero() {
		in.StartedAt = time.Now().UTC()
	}
	existing, err := s.GetSession(ctx, in.SessionID)
	switch {
	case err == nil:
		if existing.EndedAt != nil {
			return ErrSessionFinished
		}
		if existing.User == in.User && existing.Target == in.Target && existing.Scope == in.Scope &&
			existing.GatewayID == in.GatewayID && existing.DirectoryID == in.DirectoryID &&
			existing.RecordingMode == in.RecordingMode && existing.RecordingPolicySource == in.RecordingPolicySource &&
			existing.IngestJTI == in.IngestJTI {
			return nil
		}
		return ErrSessionConflict
	case errors.Is(err, ErrUnknownSession):
		// fall through to insert
	default:
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (session_id, user, directory_id, gateway_id, scope, target, recording_mode, started_at, key_id, recording_policy_source, ingest_jti)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		in.SessionID, in.User, in.DirectoryID, in.GatewayID, in.Scope, in.Target, in.RecordingMode,
		in.StartedAt.UTC().Format(time.RFC3339Nano), s.enc.KeyID(), in.RecordingPolicySource, in.IngestJTI)
	return err
}

// IngestEvent is one TerminalEvent's already-decoded (from base64)
// payload, decoupled from internal/sessionrecording.TerminalEvent's JSON
// wire shape on purpose — this package must not import a CLI-facing
// package, and the HTTP layer (cmd/pilot-session-store) is what owns
// translating the wire format.
type IngestEvent struct {
	Seq           uint64
	Stream        string
	OffsetNanos   int64
	Data          []byte
	Rows          int
	Cols          int
	RedactedBytes int
}

// IngestOutcome reports how many events in one IngestEvents call were
// newly written vs. recognized as an identical retry.
type IngestOutcome struct {
	Accepted  int
	Duplicate int
}

// IngestEvents appends events to sessionID's stream inside one
// transaction. Idempotency (spec.md §28.1) is per-event: a (session_id,
// seq) already on disk with the SAME payload is silently skipped
// (Duplicate++); with a DIFFERENT payload it fails the whole batch with
// ErrEventConflict — a diverging retry is exactly the kind of ambiguity
// this store must never resolve by picking one side silently.
func (s *Store) IngestEvents(ctx context.Context, sessionID string, events []IngestEvent) (IngestOutcome, error) {
	var out IngestOutcome
	summary, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return out, err
	}
	if summary.EndedAt != nil {
		return out, ErrSessionFinished
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()

	var addedBytes int64
	var addedCount int
	for _, ev := range events {
		hash := payloadHash(ev)

		var existingHash string
		err := tx.QueryRowContext(ctx,
			`SELECT payload_sha256 FROM session_events WHERE session_id=? AND seq=?`,
			sessionID, ev.Seq).Scan(&existingHash)
		switch {
		case err == nil:
			if existingHash == hash {
				out.Duplicate++
				continue
			}
			return out, fmt.Errorf("%w: session=%s seq=%d", ErrEventConflict, sessionID, ev.Seq)
		case errors.Is(err, sql.ErrNoRows):
			// not seen before; fall through to insert
		default:
			return out, err
		}

		nonce, ciphertext, err := s.enc.seal(sessionID, ev.Seq, ev.Stream, ev.Data)
		if err != nil {
			return out, err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO session_events (session_id, seq, stream, offset_nanos, rows, cols, redacted_bytes, nonce, ciphertext, payload_sha256, created_at)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			sessionID, ev.Seq, ev.Stream, ev.OffsetNanos, ev.Rows, ev.Cols, ev.RedactedBytes,
			nonce, ciphertext, hash, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return out, err
		}
		out.Accepted++
		addedCount++
		addedBytes += int64(len(ev.Data))
	}

	if addedCount > 0 {
		if _, err := tx.ExecContext(ctx,
			`UPDATE sessions SET bytes = bytes + ?, event_count = event_count + ? WHERE session_id=?`,
			addedBytes, addedCount, sessionID); err != nil {
			return out, err
		}
	}
	if err := tx.Commit(); err != nil {
		return out, err
	}
	return out, nil
}

func payloadHash(ev IngestEvent) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d|%d|%d|%x", ev.Stream, ev.OffsetNanos, ev.Rows, ev.Cols, ev.RedactedBytes, ev.Data)))
	return hex.EncodeToString(sum[:])
}

// FinishSession records the end of a session (per-host recording spec
// §21.4). lastSeq is the recorder's last assigned seq, including events it
// dropped; the stored completeness is the client's own claim AND no gap in
// [1, lastSeq] AND the highest stored seq equal to lastSeq, so events lost
// at the tail are detected too. Repeating an identical finish (same
// endedAt instant and lastSeq) is a no-op; any other finish of an already
// finished session is ErrSessionFinished.
func (s *Store) FinishSession(ctx context.Context, sessionID string, endedAt time.Time, complete bool, lastSeq uint64) error {
	if endedAt.IsZero() {
		return fmt.Errorf("sessionstore: ended_at is required")
	}
	summary, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}
	if summary.EndedAt != nil {
		if summary.EndedAt.Equal(endedAt) && summary.LastSeq == lastSeq {
			return nil
		}
		return ErrSessionFinished
	}
	seqs, err := s.eventSeqs(ctx, sessionID)
	if err != nil {
		return err
	}
	var maxSeq uint64
	for _, seq := range seqs {
		maxSeq = max(maxSeq, seq)
	}
	if lastSeq < maxSeq {
		return fmt.Errorf("%w: last_seq=%d, stored max seq=%d", ErrLastSeqTooLow, lastSeq, maxSeq)
	}
	complete = complete && maxSeq == lastSeq && len(gapsUpTo(seqs, lastSeq)) == 0
	_, err = s.db.ExecContext(ctx,
		`UPDATE sessions SET ended_at=?, complete=?, last_seq=? WHERE session_id=?`,
		endedAt.UTC().Format(time.RFC3339Nano), boolToInt(complete), lastSeq, sessionID)
	return err
}

func (s *Store) eventSeqs(ctx context.Context, sessionID string) ([]uint64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq FROM session_events WHERE session_id=?`, sessionID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var seqs []uint64
	for rows.Next() {
		var seq uint64
		if err := rows.Scan(&seq); err != nil {
			return nil, err
		}
		seqs = append(seqs, seq)
	}
	return seqs, rows.Err()
}

// SessionSummary is one spec.md §28.3 index row.
type SessionSummary struct {
	SessionID     string
	User          string
	DirectoryID   string
	GatewayID     string
	Scope         string
	Target        string
	RecordingMode string
	StartedAt     time.Time
	EndedAt       *time.Time
	Complete      bool
	Bytes         int64
	EventCount    int
	KeyID         string
	// RecordingPolicySource and LastSeq are exposed by the read API;
	// IngestJTI is internal to ingest authorization and never exposed.
	RecordingPolicySource string
	LastSeq               uint64
	IngestJTI             string
}

const summaryColumns = `session_id,user,directory_id,gateway_id,scope,target,recording_mode,started_at,ended_at,complete,bytes,event_count,key_id,recording_policy_source,last_seq,ingest_jti`

// GetSession returns one session's index row.
func (s *Store) GetSession(ctx context.Context, sessionID string) (SessionSummary, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+summaryColumns+` FROM sessions WHERE session_id=?`, sessionID)
	var out SessionSummary
	var startedAt, endedAt string
	var completeInt int
	err := row.Scan(&out.SessionID, &out.User, &out.DirectoryID, &out.GatewayID, &out.Scope, &out.Target,
		&out.RecordingMode, &startedAt, &endedAt, &completeInt, &out.Bytes, &out.EventCount, &out.KeyID,
		&out.RecordingPolicySource, &out.LastSeq, &out.IngestJTI)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionSummary{}, ErrUnknownSession
	}
	if err != nil {
		return SessionSummary{}, err
	}
	out.StartedAt, _ = time.Parse(time.RFC3339Nano, startedAt)
	out.Complete = completeInt != 0
	if endedAt != "" {
		t, _ := time.Parse(time.RFC3339Nano, endedAt)
		out.EndedAt = &t
	}
	return out, nil
}

// ListFilter narrows ListSessions. A zero value lists every session,
// newest first.
type ListFilter struct {
	User  string
	Limit int
}

// ListSessions returns index rows for `pilot session list`, newest
// started_at first.
func (s *Store) ListSessions(ctx context.Context, filter ListFilter) ([]SessionSummary, error) {
	query := `SELECT ` + summaryColumns + ` FROM sessions`
	var args []any
	if filter.User != "" {
		query += ` WHERE user = ?`
		args = append(args, filter.User)
	}
	query += ` ORDER BY started_at DESC`
	if filter.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, filter.Limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []SessionSummary
	for rows.Next() {
		var summary SessionSummary
		var startedAt, endedAt string
		var completeInt int
		if err := rows.Scan(&summary.SessionID, &summary.User, &summary.DirectoryID, &summary.GatewayID,
			&summary.Scope, &summary.Target, &summary.RecordingMode, &startedAt, &endedAt, &completeInt,
			&summary.Bytes, &summary.EventCount, &summary.KeyID,
			&summary.RecordingPolicySource, &summary.LastSeq, &summary.IngestJTI); err != nil {
			return nil, err
		}
		summary.StartedAt, _ = time.Parse(time.RFC3339Nano, startedAt)
		summary.Complete = completeInt != 0
		if endedAt != "" {
			t, _ := time.Parse(time.RFC3339Nano, endedAt)
			summary.EndedAt = &t
		}
		out = append(out, summary)
	}
	return out, rows.Err()
}

// ReplayEvent is one decrypted event in playback order.
type ReplayEvent struct {
	Seq           uint64
	Stream        string
	OffsetNanos   int64
	Data          []byte
	Rows          int
	Cols          int
	RedactedBytes int
}

// GapRange is an inclusive range of missing sequence numbers.
type GapRange struct {
	FromSeq uint64
	ToSeq   uint64
}

// ReplayResult is spec.md §29's replay output: decrypted events in
// sequence, any detected gaps, and whether the session is both marked
// complete AND has no gap — `pilot session replay` must show "RECORDING
// INCOMPLETE" prominently whenever Complete is false.
type ReplayResult struct {
	Events   []ReplayEvent
	Gaps     []GapRange
	Complete bool
}

// Replay decrypts every event for sessionID in sequence order and
// verifies sequence continuity (spec.md §29). It never re-executes any
// input — decryption and gap detection only.
func (s *Store) Replay(ctx context.Context, sessionID string) (ReplayResult, error) {
	summary, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return ReplayResult{}, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT seq,stream,offset_nanos,rows,cols,redacted_bytes,nonce,ciphertext FROM session_events WHERE session_id=? ORDER BY seq ASC`,
		sessionID)
	if err != nil {
		return ReplayResult{}, err
	}
	defer func() { _ = rows.Close() }()

	var events []ReplayEvent
	var seqs []uint64
	for rows.Next() {
		var seq uint64
		var stream string
		var offsetNanos int64
		var rowsN, cols, redacted int
		var nonce, ciphertext []byte
		if err := rows.Scan(&seq, &stream, &offsetNanos, &rowsN, &cols, &redacted, &nonce, &ciphertext); err != nil {
			return ReplayResult{}, err
		}
		plaintext, err := s.enc.open(sessionID, seq, stream, nonce, ciphertext)
		if err != nil {
			return ReplayResult{}, fmt.Errorf("replay session %s: %w", sessionID, err)
		}
		events = append(events, ReplayEvent{Seq: seq, Stream: stream, OffsetNanos: offsetNanos, Data: plaintext, Rows: rowsN, Cols: cols, RedactedBytes: redacted})
		seqs = append(seqs, seq)
	}
	if err := rows.Err(); err != nil {
		return ReplayResult{}, err
	}

	gaps := gapsUpTo(seqs, summary.LastSeq)
	return ReplayResult{Events: events, Gaps: gaps, Complete: summary.Complete && len(gaps) == 0}, nil
}

// detectGaps assumes sequence numbers start at 1 and increment by 1 per
// event (internal/sessionrecording.Recorder's own discipline —
// r.seq.Add(1) on a zero-valued atomic.Uint64). Any missing number in
// [1, max(seqs)] is a gap.
// gapsUpTo is detectGaps plus the trailing range (max stored seq, lastSeq]
// that a finish with a known lastSeq reveals; lastSeq 0 (not yet finished,
// or no events) adds nothing.
func gapsUpTo(seqs []uint64, lastSeq uint64) []GapRange {
	gaps := detectGaps(seqs)
	var maxSeq uint64
	for _, seq := range seqs {
		maxSeq = max(maxSeq, seq)
	}
	if lastSeq > maxSeq {
		gaps = append(gaps, GapRange{FromSeq: maxSeq + 1, ToSeq: lastSeq})
	}
	return gaps
}

func detectGaps(seqs []uint64) []GapRange {
	if len(seqs) == 0 {
		return nil
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	var gaps []GapRange
	expected := uint64(1)
	for _, seq := range seqs {
		if seq > expected {
			gaps = append(gaps, GapRange{FromSeq: expected, ToSeq: seq - 1})
		}
		if seq >= expected {
			expected = seq + 1
		}
	}
	return gaps
}

// DeleteSessionPayload removes one session's event ciphertext and
// records a retention audit row, in the order spec.md §28.5 requires:
// index updated first (bytes/event_count zeroed — the index no longer
// claims payload exists), then the payload rows are deleted, then the
// audit record is written. All three happen in one transaction so a
// crash mid-sweep never leaves the index claiming payload that is
// already gone, or vice versa.
func (s *Store) DeleteSessionPayload(ctx context.Context, sessionID, reason string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `UPDATE sessions SET bytes=0, event_count=0 WHERE session_id=?`, sessionID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrUnknownSession
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM session_events WHERE session_id=?`, sessionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO retention_events (session_id, action, detail, created_at) VALUES (?,?,?,?)`,
		sessionID, "retention_delete", reason, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

// SessionsOlderThan returns session_ids whose started_at is before
// cutoff and whose payload has not already been purged (event_count > 0
// OR bytes > 0 — a session with zero events but never purged is still
// eligible, so retention converges even for empty/aborted sessions).
func (s *Store) SessionsOlderThan(ctx context.Context, cutoff time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT session_id FROM sessions WHERE started_at < ? AND session_id NOT IN (SELECT session_id FROM retention_events WHERE action='retention_delete')`,
		cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
