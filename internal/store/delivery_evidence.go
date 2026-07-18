package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrRunFinished      = errors.New("delivery run is already finished")
	ErrEvidenceConflict = errors.New("delivery evidence conflicts with an existing operation")
)

const (
	EventRunStarted   = "run_started"
	EventHeartbeat    = "run_heartbeat"
	EventStepFinished = "step_finished"
	EventRunFinished  = "run_finished"
	maxEvidenceBytes  = 64 * 1024
)

// RunStarted defines immutable facts known before a delivery or standalone
// verification begins. Hosts is the resolved verification scope and is used
// to reject evidence for an unrelated host.
type RunStarted struct {
	RunID       string
	OperationID string
	Stage       string
	Component   string
	Playbook    string
	Inventory   string
	Hosts       []string
	StartedAt   time.Time
}

type Event struct {
	OperationID string
	Type        string
	Step        string
	Payload     any
	ExitCode    *int
	CreatedAt   time.Time
}

type RunFinished struct {
	OperationID string
	Outcome     string
	ExitCode    int
	FinishedAt  time.Time
}

// VerifyEvidence is one immutable host × row observation. Callers evaluate
// Expected before appending; this type records facts and the resulting
// verdict, it does not rerun a matcher.
type VerifyEvidence struct {
	SpecPath    string
	RowID       string
	Host        string
	Attempt     int
	OperationID string
	Command     string
	Expected    string
	Stdout      string
	Stderr      string
	ExitCode    int
	ProbeStatus string
	Verdict     string
	Redacted    bool
	StartedAt   time.Time
	FinishedAt  time.Time
}

// RunWriter serializes a run's append-only events. The mutex establishes a
// same-process happens-before relationship; BEGIN IMMEDIATE protects callers
// that accidentally create more than one writer for the same run.
type RunWriter struct {
	store  *Store
	runID  string
	hosts  map[string]struct{}
	mu     sync.Mutex
	closed bool

	heartbeatCancel context.CancelFunc
	heartbeatWG     sync.WaitGroup
}

func StartRun(ctx context.Context, s *Store, start RunStarted) (*RunWriter, error) {
	if s == nil {
		return nil, fmt.Errorf("start delivery run: nil store")
	}
	if start.RunID == "" {
		start.RunID = uuid.NewString()
	}
	if start.OperationID == "" {
		start.OperationID = "run_started"
	}
	if start.StartedAt.IsZero() {
		start.StartedAt = time.Now().UTC()
	}
	hosts := uniqueSorted(start.Hosts)
	w := &RunWriter{store: s, runID: start.RunID, hosts: make(map[string]struct{}, len(hosts))}
	for _, host := range hosts {
		w.hosts[host] = struct{}{}
	}
	payload := map[string]any{
		"stage": start.Stage, "component": start.Component, "playbook": start.Playbook,
		"inventory": start.Inventory, "hosts": hosts,
	}
	if err := w.appendEvent(ctx, Event{OperationID: start.OperationID, Type: EventRunStarted, Payload: payload, CreatedAt: start.StartedAt}, true); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *RunWriter) RunID() string { return w.runID }

// EvidenceCount is a narrow read helper for execution tests and future query
// surfaces. It does not expose any mutating access to the evidence stream.
func (s *Store) EvidenceCount(runID string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM verify_evidence WHERE run_id=?`, runID).Scan(&count)
	return count, err
}

func (w *RunWriter) AppendEvent(ctx context.Context, event Event) error {
	if event.Type == EventRunStarted || event.Type == EventRunFinished {
		return fmt.Errorf("append delivery event %q: use StartRun or Finish", event.Type)
	}
	return w.appendEvent(ctx, event, false)
}

func (w *RunWriter) appendEvent(ctx context.Context, event Event, starting bool) error {
	if event.OperationID == "" || event.Type == "" {
		return fmt.Errorf("append delivery event: operation_id and type are required")
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		return fmt.Errorf("marshal delivery event payload: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed && !starting {
		return ErrRunFinished
	}
	return w.withImmediateTx(ctx, func(conn *sql.Conn) error {
		var existingType, existingPayload string
		var existingExit sql.NullInt64
		err := conn.QueryRowContext(ctx, `SELECT type, payload_json, exit_code FROM delivery_events WHERE run_id=? AND operation_id=?`, w.runID, event.OperationID).Scan(&existingType, &existingPayload, &existingExit)
		if err == nil {
			if existingType == event.Type && existingPayload == string(payload) && sameNullableInt(existingExit, event.ExitCode) {
				return nil
			}
			return ErrEvidenceConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var terminal int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM delivery_events WHERE run_id=? AND type=?`, w.runID, EventRunFinished).Scan(&terminal); err != nil {
			return err
		}
		if terminal > 0 {
			return ErrRunFinished
		}
		var count, maxSeq int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MAX(seq), 0) FROM delivery_events WHERE run_id=?`, w.runID).Scan(&count, &maxSeq); err != nil {
			return err
		}
		if starting {
			if count != 0 {
				return ErrEvidenceConflict
			}
			maxSeq = 0
		} else if count == 0 {
			return fmt.Errorf("delivery run %s has no run_started event", w.runID)
		}
		var exit any
		if event.ExitCode != nil {
			exit = *event.ExitCode
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO delivery_events (run_id, seq, operation_id, type, step, payload_json, exit_code, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			w.runID, maxSeq+1, event.OperationID, event.Type, event.Step, string(payload), exit, event.CreatedAt.UTC().Format(time.RFC3339Nano))
		return err
	})
}

func (w *RunWriter) AppendEvidence(ctx context.Context, rows []VerifyEvidence) error {
	for _, row := range rows {
		if err := w.appendEvidence(ctx, row); err != nil {
			return err
		}
	}
	return nil
}

func (w *RunWriter) appendEvidence(ctx context.Context, row VerifyEvidence) error {
	if row.SpecPath == "" || row.RowID == "" || row.Host == "" || row.OperationID == "" || row.Command == "" || row.ProbeStatus == "" || row.Verdict == "" {
		return fmt.Errorf("append verification evidence: required field is empty")
	}
	if row.Attempt < 1 {
		return fmt.Errorf("append verification evidence: attempt must be >= 1")
	}
	if len(w.hosts) > 0 {
		if _, ok := w.hosts[row.Host]; !ok {
			return fmt.Errorf("append verification evidence: host %q is outside the resolved run scope", row.Host)
		}
	}
	if row.StartedAt.IsZero() {
		row.StartedAt = time.Now().UTC()
	}
	if row.FinishedAt.IsZero() {
		row.FinishedAt = row.StartedAt
	}
	stdout, stdoutTruncated := truncateEvidence(row.Stdout)
	stderr, stderrTruncated := truncateEvidence(row.Stderr)
	hash := evidenceHash(row, stdout, stderr)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrRunFinished
	}
	return w.withImmediateTx(ctx, func(conn *sql.Conn) error {
		var existingHash string
		err := conn.QueryRowContext(ctx, `SELECT content_hash FROM verify_evidence WHERE run_id=? AND operation_id=?`, w.runID, row.OperationID).Scan(&existingHash)
		if err == nil {
			if existingHash == hash {
				return nil
			}
			return ErrEvidenceConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		err = conn.QueryRowContext(ctx, `SELECT content_hash FROM verify_evidence WHERE run_id=? AND spec_path=? AND row_id=? AND host=? AND attempt=?`, w.runID, row.SpecPath, row.RowID, row.Host, row.Attempt).Scan(&existingHash)
		if err == nil {
			if existingHash == hash {
				return nil
			}
			return ErrEvidenceConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var started, terminal int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*), SUM(CASE WHEN type=? THEN 1 ELSE 0 END) FROM delivery_events WHERE run_id=?`, EventRunFinished, w.runID).Scan(&started, &terminal); err != nil {
			return err
		}
		if started == 0 {
			return fmt.Errorf("delivery run %s has no run_started event", w.runID)
		}
		if terminal > 0 {
			return ErrRunFinished
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO verify_evidence (run_id,spec_path,row_id,host,attempt,operation_id,content_hash,command,expected,stdout,stderr,exit_code,probe_status,verdict,redacted,stdout_truncated,stderr_truncated,started_at,finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			w.runID, row.SpecPath, row.RowID, row.Host, row.Attempt, row.OperationID, hash, row.Command, row.Expected, stdout, stderr, row.ExitCode, row.ProbeStatus, row.Verdict, boolInt(row.Redacted), boolInt(stdoutTruncated), boolInt(stderrTruncated), row.StartedAt.UTC().Format(time.RFC3339Nano), row.FinishedAt.UTC().Format(time.RFC3339Nano))
		if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrEvidenceConflict
		}
		return err
	})
}

func (w *RunWriter) Finish(ctx context.Context, finish RunFinished) error {
	if finish.OperationID == "" {
		finish.OperationID = "run_finished"
	}
	if finish.Outcome == "" {
		return fmt.Errorf("finish delivery run: outcome is required")
	}
	if finish.FinishedAt.IsZero() {
		finish.FinishedAt = time.Now().UTC()
	}
	w.stopHeartbeat()
	finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	exit := finish.ExitCode
	err := w.appendEvent(finalCtx, Event{OperationID: finish.OperationID, Type: EventRunFinished, Payload: map[string]any{"outcome": finish.Outcome}, ExitCode: &exit, CreatedAt: finish.FinishedAt}, false)
	if err == nil {
		w.mu.Lock()
		w.closed = true
		w.mu.Unlock()
	}
	return err
}

func (w *RunWriter) StartHeartbeat(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	w.mu.Lock()
	if w.heartbeatCancel != nil || w.closed {
		w.mu.Unlock()
		return
	}
	hbCtx, cancel := context.WithCancel(ctx)
	w.heartbeatCancel = cancel
	w.heartbeatWG.Add(1)
	w.mu.Unlock()
	go func() {
		defer w.heartbeatWG.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-ticker.C:
				_ = w.AppendEvent(hbCtx, Event{OperationID: "heartbeat-" + uuid.NewString(), Type: EventHeartbeat, Payload: map[string]any{}})
			}
		}
	}()
}

func (w *RunWriter) stopHeartbeat() {
	w.mu.Lock()
	cancel := w.heartbeatCancel
	w.heartbeatCancel = nil
	w.mu.Unlock()
	if cancel != nil {
		cancel()
		w.heartbeatWG.Wait()
	}
}

func (w *RunWriter) withImmediateTx(ctx context.Context, fn func(*sql.Conn) error) (err error) {
	conn, err := w.store.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	if err = fn(conn); err != nil {
		return err
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

func uniqueSorted(in []string) []string {
	set := make(map[string]struct{}, len(in))
	for _, v := range in {
		if v != "" {
			set[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func sameNullableInt(got sql.NullInt64, want *int) bool {
	return (want == nil && !got.Valid) || (want != nil && got.Valid && got.Int64 == int64(*want))
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func truncateEvidence(value string) (string, bool) {
	if len(value) <= maxEvidenceBytes {
		return value, false
	}
	return value[:maxEvidenceBytes], true
}
func evidenceHash(row VerifyEvidence, stdout, stderr string) string {
	h := sha256.New()
	for _, value := range []string{row.SpecPath, row.RowID, row.Host, fmt.Sprint(row.Attempt), row.Command, row.Expected, stdout, stderr, fmt.Sprint(row.ExitCode), row.ProbeStatus, row.Verdict, fmt.Sprint(row.Redacted)} {
		_, _ = h.Write([]byte(value))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
