package agentcontroller

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Incident state machine values (spec §7). incidents.status always holds
// exactly one of these.
const (
	StatusOpen             = "OPEN"
	StatusQueued           = "QUEUED"
	StatusInvestigating    = "INVESTIGATING"
	StatusDiagnosed        = "DIAGNOSED"
	StatusResolvedExternal = "RESOLVED_EXTERNAL"
	StatusAgentFailed      = "AGENT_FAILED"
	StatusSuppressed       = "SUPPRESSED"
	StatusClosed           = "CLOSED"
)

func isTerminalStatus(status string) bool {
	switch status {
	case StatusResolvedExternal, StatusClosed:
		return true
	default:
		return false
	}
}

// Incident mirrors one incidents row.
type Incident struct {
	ID             string
	Source         string
	SourceIdentity string
	GroupKey       string
	Status         string
	Severity       string
	Host           string
	Site           string
	Component      string
	// Subject is the generic scope/correlation identity (SNMP monitoring
	// integration spec §10.1/schemaV5) — set once at creation, never
	// rewritten by a later re-fire, same convention as Host/Site/
	// Component above.
	Subject          IncidentSubject
	AlertName        string
	OpenedAt         time.Time
	UpdatedAt        time.Time
	ResolvedAt       *time.Time
	CurrentRevision  int64
	LastBodySHA256   string
	DispatchAttempts int
}

func nullableString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// IngestOutcome reports what IngestEvent actually did, so the caller
// (http.go / queue.go) knows whether a new Agent run needs enqueuing.
type IngestOutcome struct {
	IncidentID string
	// Created is true the first time this identity is seen.
	Created bool
	// Changed is true when this event actually changed the incident (new
	// identity, a revision bump, or a status transition) — false means
	// this was a pure replay (spec §7/C5: repeated identical firing
	// payloads do not create concurrent Agent runs).
	Changed bool
	// NeedsDispatch is true when the incident is now in a state that
	// should get a fresh Agent run enqueued (a new or re-escalated OPEN
	// incident) — never true for a resolved/suppressed transition.
	NeedsDispatch bool
}

// IngestEvent persists one normalized IncidentEvent atomically: create or
// update the incidents row, and append one incident_events row (spec
// §5.5/§8). It never invents a new active incident row for an identity
// that already has one — repeated firing events update the SAME row.
func (s *Store) IngestEvent(ev IncidentEvent, now time.Time) (out IngestOutcome, err error) {
	tx, txErr := s.db.Begin()
	if txErr != nil {
		return out, fmt.Errorf("begin ingest: %w", txErr)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	var existing struct {
		id             string
		status         string
		revision       int64
		lastBodySHA256 string
	}
	scanErr := tx.QueryRow(`
		SELECT id, status, current_revision, last_body_sha256
		FROM incidents
		WHERE source = ? AND source_identity = ?
		AND status NOT IN ('RESOLVED_EXTERNAL', 'CLOSED')
	`, ev.Source, ev.Episode).Scan(&existing.id, &existing.status, &existing.revision, &existing.lastBodySHA256)

	switch {
	case scanErr == sql.ErrNoRows && ev.Status == "resolved":
		// A resolve for an identity we have no active row for (e.g. the
		// controller restarted between fire and resolve, or Alertmanager
		// re-delivered after our own row already closed). Evidence is
		// still recorded, but no new active incident is invented for a
		// resolve-only event.
		out, err = s.recordOrphanResolve(tx, ev, now)
		if err != nil {
			return out, err
		}
		return out, tx.Commit()

	case scanErr == sql.ErrNoRows:
		out, err = s.createIncident(tx, ev, now)
		if err != nil {
			return out, err
		}
		return out, tx.Commit()

	case scanErr != nil:
		err = fmt.Errorf("lookup active incident: %w", scanErr)
		return out, err

	default:
		out, err = s.updateIncident(tx, existing.id, existing.status, existing.revision, existing.lastBodySHA256, ev, now)
		if err != nil {
			return out, err
		}
		return out, tx.Commit()
	}
}

func (s *Store) createIncident(tx *sql.Tx, ev IncidentEvent, now time.Time) (IngestOutcome, error) {
	id := uuid.NewString()
	status := StatusOpen
	var resolvedAt sql.NullString
	if ev.Status == "resolved" {
		// Fire-and-immediately-resolved (rare, but a fresh identity CAN
		// arrive already resolved after a controller restart lost the
		// firing event) — record it, don't dispatch an Agent for it.
		status = StatusResolvedExternal
		resolvedAt = nullableString(rfc3339(now))
	}
	if _, err := tx.Exec(`
		INSERT INTO incidents (
			id, source, source_identity, group_key, status, severity, host, site,
			component, alert_name, opened_at, updated_at, resolved_at,
			current_revision, last_body_sha256, subject_id, subject_kind, managed
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
	`, id, ev.Source, ev.Episode, ev.GroupKey, status, nullableString(ev.Severity),
		nullableString(ev.Host), nullableString(ev.Site), nullableString(ev.Component),
		ev.AlertName, rfc3339(now), rfc3339(now), resolvedAt, ev.AlertBodySHA256,
		ev.Subject.ID, ev.Subject.Kind, ev.Subject.Managed); err != nil {
		return IngestOutcome{}, fmt.Errorf("insert incident: %w", err)
	}
	if err := insertIncidentEvent(tx, id, ev, 1, now); err != nil {
		return IngestOutcome{}, err
	}
	return IngestOutcome{
		IncidentID:    id,
		Created:       true,
		Changed:       true,
		NeedsDispatch: status == StatusOpen,
	}, nil
}

func (s *Store) updateIncident(tx *sql.Tx, id, currentStatus string, currentRevision int64, lastBodySHA256 string, ev IncidentEvent, now time.Time) (IngestOutcome, error) {
	if ev.Status != "resolved" && ev.AlertBodySHA256 == lastBodySHA256 {
		// Pure replay (spec §7/C5) — touch updated_at only, no new
		// revision, no new run.
		if _, err := tx.Exec(`UPDATE incidents SET updated_at = ? WHERE id = ?`, rfc3339(now), id); err != nil {
			return IngestOutcome{}, fmt.Errorf("touch incident on replay: %w", err)
		}
		return IngestOutcome{IncidentID: id, Changed: false}, nil
	}

	newRevision := currentRevision + 1
	newStatus := currentStatus
	var resolvedAt sql.NullString
	needsDispatch := false

	if ev.Status == "resolved" {
		newStatus = StatusResolvedExternal
		resolvedAt = nullableString(rfc3339(now))
	} else if currentStatus == StatusSuppressed {
		// A re-firing event does not silently un-suppress an incident —
		// that is an operator decision, out of scope for Phase 1.
		newStatus = currentStatus
	} else {
		// Escalation/re-fire on an already-active incident: leave the
		// incident-level status where it is if an Agent run is already
		// in flight (INVESTIGATING/QUEUED); otherwise re-open it for a
		// fresh run (e.g. it had already reached DIAGNOSED/AGENT_FAILED
		// and the alert is still firing).
		if currentStatus == StatusDiagnosed || currentStatus == StatusAgentFailed {
			newStatus = StatusOpen
			needsDispatch = true
		}
	}

	// A fresh re-fire after a completed/failed run starts a NEW
	// investigation cycle, not a continuation of the old failure's
	// backoff/attempt budget.
	resetDispatchState := 0
	if needsDispatch {
		resetDispatchState = 1
	}
	if _, err := tx.Exec(`
		UPDATE incidents SET
			status = ?, severity = ?, updated_at = ?, resolved_at = ?,
			current_revision = ?, last_body_sha256 = ?,
			next_dispatch_at = CASE WHEN ? = 1 THEN '' ELSE next_dispatch_at END,
			dispatch_attempts = CASE WHEN ? = 1 THEN 0 ELSE dispatch_attempts END
		WHERE id = ?
	`, newStatus, nullableString(ev.Severity), rfc3339(now), resolvedAt, newRevision, ev.AlertBodySHA256,
		resetDispatchState, resetDispatchState, id); err != nil {
		return IngestOutcome{}, fmt.Errorf("update incident: %w", err)
	}
	if err := insertIncidentEvent(tx, id, ev, newRevision, now); err != nil {
		return IngestOutcome{}, err
	}
	return IngestOutcome{IncidentID: id, Changed: true, NeedsDispatch: needsDispatch}, nil
}

func (s *Store) recordOrphanResolve(tx *sql.Tx, ev IncidentEvent, now time.Time) (IngestOutcome, error) {
	id := uuid.NewString()
	if _, err := tx.Exec(`
		INSERT INTO incidents (
			id, source, source_identity, group_key, status, severity, host, site,
			component, alert_name, opened_at, updated_at, resolved_at,
			current_revision, last_body_sha256, subject_id, subject_kind, managed
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
	`, id, ev.Source, ev.Episode, ev.GroupKey, StatusResolvedExternal, nullableString(ev.Severity),
		nullableString(ev.Host), nullableString(ev.Site), nullableString(ev.Component),
		ev.AlertName, rfc3339(now), rfc3339(now), nullableString(rfc3339(now)), ev.AlertBodySHA256,
		ev.Subject.ID, ev.Subject.Kind, ev.Subject.Managed); err != nil {
		return IngestOutcome{}, fmt.Errorf("insert orphan-resolved incident: %w", err)
	}
	if err := insertIncidentEvent(tx, id, ev, 1, now); err != nil {
		return IngestOutcome{}, err
	}
	return IngestOutcome{IncidentID: id, Created: true, Changed: true}, nil
}

func insertIncidentEvent(tx *sql.Tx, incidentID string, ev IncidentEvent, revision int64, now time.Time) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal incident event: %w", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO incident_events (incident_id, event_kind, source_revision, payload_json, payload_sha256, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, incidentID, ev.Status, revision, string(payload), sha256Hex(payload), rfc3339(now)); err != nil {
		return fmt.Errorf("insert incident_event: %w", err)
	}
	return nil
}

// GetIncident returns one incident by ID, or nil if it does not exist.
func (s *Store) GetIncident(id string) (*Incident, error) {
	row := s.db.QueryRow(`
		SELECT id, source, source_identity, group_key, status,
			COALESCE(severity, ''), COALESCE(host, ''), COALESCE(site, ''),
			COALESCE(component, ''), alert_name, opened_at, updated_at,
			resolved_at, current_revision, last_body_sha256,
			subject_id, subject_kind, managed
		FROM incidents WHERE id = ?
	`, id)
	var inc Incident
	var openedAt, updatedAt string
	var resolvedAt sql.NullString
	if err := row.Scan(&inc.ID, &inc.Source, &inc.SourceIdentity, &inc.GroupKey, &inc.Status,
		&inc.Severity, &inc.Host, &inc.Site, &inc.Component, &inc.AlertName,
		&openedAt, &updatedAt, &resolvedAt, &inc.CurrentRevision, &inc.LastBodySHA256,
		&inc.Subject.ID, &inc.Subject.Kind, &inc.Subject.Managed); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get incident %s: %w", id, err)
	}
	inc.Subject.Site = inc.Site
	inc.OpenedAt, _ = time.Parse(time.RFC3339, openedAt)
	inc.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	if resolvedAt.Valid {
		t, _ := time.Parse(time.RFC3339, resolvedAt.String)
		inc.ResolvedAt = &t
	}
	return &inc, nil
}

// ListIncidentsNeedingDispatch returns OPEN incidents with no active run,
// excluding any still serving out a backoff delay from a prior transport/
// runtime failure (spec §13's "exponential backoff with cap").
func (s *Store) ListIncidentsNeedingDispatch(now time.Time, limit int) ([]Incident, error) {
	rows, err := s.db.Query(`
		SELECT i.id, i.source, i.source_identity, i.group_key, i.status,
			COALESCE(i.severity, ''), COALESCE(i.host, ''), COALESCE(i.site, ''),
			COALESCE(i.component, ''), i.alert_name, i.opened_at, i.updated_at,
			i.resolved_at, i.current_revision, i.last_body_sha256, i.dispatch_attempts,
			i.subject_id, i.subject_kind, i.managed
		FROM incidents i
		WHERE i.status = ?
		AND (i.next_dispatch_at = '' OR i.next_dispatch_at <= ?)
		AND NOT EXISTS (
			SELECT 1 FROM agent_runs r
			WHERE r.incident_id = i.id AND r.state IN ('QUEUED', 'INVESTIGATING')
		)
		ORDER BY i.updated_at ASC
		LIMIT ?
	`, StatusOpen, rfc3339(now), limit)
	if err != nil {
		return nil, fmt.Errorf("list dispatchable incidents: %w", err)
	}
	defer rows.Close()

	var out []Incident
	for rows.Next() {
		var inc Incident
		var openedAt, updatedAt string
		var resolvedAt sql.NullString
		if err := rows.Scan(&inc.ID, &inc.Source, &inc.SourceIdentity, &inc.GroupKey, &inc.Status,
			&inc.Severity, &inc.Host, &inc.Site, &inc.Component, &inc.AlertName,
			&openedAt, &updatedAt, &resolvedAt, &inc.CurrentRevision, &inc.LastBodySHA256, &inc.DispatchAttempts,
			&inc.Subject.ID, &inc.Subject.Kind, &inc.Subject.Managed); err != nil {
			return nil, fmt.Errorf("scan dispatchable incident: %w", err)
		}
		inc.Subject.Site = inc.Site
		inc.OpenedAt, _ = time.Parse(time.RFC3339, openedAt)
		inc.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		out = append(out, inc)
	}
	return out, rows.Err()
}

// CountIncidentsByStatus returns how many incidents currently sit in
// status — used by status.go's Status.Incidents.
func (s *Store) CountIncidentsByStatus(status string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM incidents WHERE status = ?`, status).Scan(&n)
	return n, err
}

// CountActiveRuns returns the number of runs currently QUEUED or
// INVESTIGATING — the global concurrency gate (spec §13).
func (s *Store) CountActiveRuns() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM agent_runs WHERE state IN ('QUEUED', 'INVESTIGATING')`).Scan(&n)
	return n, err
}

// CountActiveRunsForHost returns the number of active runs whose incident
// is scoped to host — the "max 1 active run per host" MVP gate (spec §13).
func (s *Store) CountActiveRunsForHost(host string) (int, error) {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM agent_runs r
		JOIN incidents i ON i.id = r.incident_id
		WHERE r.state IN ('QUEUED', 'INVESTIGATING') AND i.host = ?
	`, host).Scan(&n)
	return n, err
}

// EnqueueRun creates a new QUEUED agent_runs row for incidentID and moves
// the incident to QUEUED. The partial unique index on agent_runs
// guarantees this fails if one is already active for this incident.
func (s *Store) EnqueueRun(incidentID string, envelope IncidentEnvelopeV2, now time.Time) (runID string, err error) {
	runID = uuid.NewString()
	tx, txErr := s.db.Begin()
	if txErr != nil {
		return "", fmt.Errorf("begin enqueue: %w", txErr)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	input, marshalErr := json.Marshal(envelope)
	if marshalErr != nil {
		err = fmt.Errorf("marshal envelope: %w", marshalErr)
		return "", err
	}
	if _, execErr := tx.Exec(`
		INSERT INTO agent_runs (id, incident_id, state, attempt, input_sha256, created_at)
		VALUES (?, ?, ?, 1, ?, ?)
	`, runID, incidentID, StatusQueued, sha256Hex(input), rfc3339(now)); execErr != nil {
		err = fmt.Errorf("insert agent_run: %w", execErr)
		return "", err
	}
	if _, execErr := tx.Exec(`
		UPDATE incidents SET status = ?, updated_at = ?, next_dispatch_at = '', dispatch_attempts = dispatch_attempts + 1
		WHERE id = ?
	`, StatusQueued, rfc3339(now), incidentID); execErr != nil {
		err = fmt.Errorf("mark incident queued: %w", execErr)
		return "", err
	}
	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit enqueue: %w", commitErr)
		return "", err
	}
	return runID, nil
}

// StartRun marks runID INVESTIGATING and its incident INVESTIGATING.
func (s *Store) StartRun(runID, incidentID string, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin start run: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	if _, execErr := tx.Exec(`UPDATE agent_runs SET state = ?, started_at = ? WHERE id = ?`,
		StatusInvestigating, rfc3339(now), runID); execErr != nil {
		err = fmt.Errorf("mark run investigating: %w", execErr)
		return err
	}
	if _, execErr := tx.Exec(`UPDATE incidents SET status = ?, updated_at = ? WHERE id = ? AND status NOT IN (?, ?, ?)`,
		StatusInvestigating, rfc3339(now), incidentID, StatusResolvedExternal, StatusClosed, StatusSuppressed); execErr != nil {
		err = fmt.Errorf("mark incident investigating: %w", execErr)
		return err
	}
	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit start run: %w", commitErr)
		return err
	}
	return nil
}

// CompleteRunDiagnosed persists a valid DiagnosisResult and moves the run
// and (if not already resolved) the incident to DIAGNOSED.
func (s *Store) CompleteRunDiagnosed(runID, incidentID string, result DiagnosisResult, now time.Time) error {
	output, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal diagnosis result: %w", err)
	}
	tx, txErr := s.db.Begin()
	if txErr != nil {
		return fmt.Errorf("begin complete run: %w", txErr)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	if _, execErr := tx.Exec(`UPDATE agent_runs SET state = ?, finished_at = ?, output_json = ? WHERE id = ?`,
		StatusDiagnosed, rfc3339(now), string(output), runID); execErr != nil {
		err = fmt.Errorf("mark run diagnosed: %w", execErr)
		return err
	}
	if _, execErr := tx.Exec(`UPDATE incidents SET status = ?, updated_at = ? WHERE id = ? AND status NOT IN (?, ?, ?)`,
		StatusDiagnosed, rfc3339(now), incidentID, StatusResolvedExternal, StatusClosed, StatusSuppressed); execErr != nil {
		err = fmt.Errorf("mark incident diagnosed: %w", execErr)
		return err
	}
	for _, ev := range result.Evidence {
		if _, execErr := tx.Exec(`
			INSERT INTO agent_evidence (run_id, kind, source_tool, reference, summary, created_at)
			VALUES (?, 'diagnosis', ?, ?, ?, ?)
		`, runID, ev.Tool, ev.Ref, ev.Summary, rfc3339(now)); execErr != nil {
			err = fmt.Errorf("insert agent_evidence: %w", execErr)
			return err
		}
	}
	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit complete run: %w", commitErr)
		return err
	}
	return nil
}

// FailRunAndMaybeRetry moves the run to AGENT_FAILED — used for transport
// errors, timeouts, and malformed output (spec §10: malformed output is
// AGENT_FAILED, never a partial diagnosis) — and then either re-opens the
// incident for a bounded, backed-off retry (spec §13: "retry transport/
// runtime failure only", "exponential backoff with cap") or leaves it
// AGENT_FAILED once dispatchAttempts has reached maxAttempts. A resolved/
// suppressed/closed incident is never reopened by a lagging run outcome.
func (s *Store) FailRunAndMaybeRetry(runID, incidentID, errorClass, errorText string, dispatchAttempts, maxAttempts int, backoff time.Duration, now time.Time) (retried bool, err error) {
	tx, txErr := s.db.Begin()
	if txErr != nil {
		return false, fmt.Errorf("begin fail run: %w", txErr)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	if _, execErr := tx.Exec(`UPDATE agent_runs SET state = ?, finished_at = ?, error_class = ?, error_text = ? WHERE id = ?`,
		StatusAgentFailed, rfc3339(now), errorClass, errorText, runID); execErr != nil {
		err = fmt.Errorf("mark run failed: %w", execErr)
		return false, err
	}

	retried = dispatchAttempts < maxAttempts
	newStatus := StatusAgentFailed
	var nextDispatchAt string
	if retried {
		newStatus = StatusOpen
		nextDispatchAt = rfc3339(now.Add(backoff))
	}
	if _, execErr := tx.Exec(`
		UPDATE incidents SET status = ?, updated_at = ?, next_dispatch_at = ?
		WHERE id = ? AND status NOT IN (?, ?, ?)
	`, newStatus, rfc3339(now), nextDispatchAt, incidentID, StatusResolvedExternal, StatusClosed, StatusSuppressed); execErr != nil {
		err = fmt.Errorf("mark incident failed: %w", execErr)
		return false, err
	}
	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit fail run: %w", commitErr)
		return false, err
	}
	return retried, nil
}

// RecoverInFlightRuns handles any run left QUEUED/INVESTIGATING by an
// unclean shutdown — a deterministic restart recovery (spec §7/C11): no
// lease timestamp arithmetic, because Phase 1 runs exactly one controller
// process (no HA — spec §3 non-goals). The controller cannot know whether
// the Agent Runtime actually received a request that was in flight at
// crash time, so it treats every such run as lost: mark it AGENT_FAILED
// for audit, and reopen its incident OPEN (immediately dispatchable, not
// counted against the transport-failure retry budget) so the SAME
// scheduler path that creates every other run (queue.go's EnqueueRun)
// picks it up fresh — there is deliberately no second "resume a stale
// run" code path.
func (s *Store) RecoverInFlightRuns(now time.Time) (recovered int, err error) {
	tx, txErr := s.db.Begin()
	if txErr != nil {
		return 0, fmt.Errorf("begin recover: %w", txErr)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	rows, queryErr := tx.Query(`SELECT id, incident_id FROM agent_runs WHERE state IN (?, ?)`,
		StatusQueued, StatusInvestigating)
	if queryErr != nil {
		err = fmt.Errorf("query in-flight runs: %w", queryErr)
		return 0, err
	}
	type pair struct{ runID, incidentID string }
	var inFlight []pair
	for rows.Next() {
		var p pair
		if scanErr := rows.Scan(&p.runID, &p.incidentID); scanErr != nil {
			rows.Close()
			err = fmt.Errorf("scan in-flight run: %w", scanErr)
			return 0, err
		}
		inFlight = append(inFlight, p)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}

	for _, p := range inFlight {
		if _, execErr := tx.Exec(`
			UPDATE agent_runs SET state = ?, finished_at = ?, error_class = 'controller_restart', error_text = 'in-flight at controller shutdown'
			WHERE id = ?
		`, StatusAgentFailed, rfc3339(now), p.runID); execErr != nil {
			err = fmt.Errorf("recover run %s: %w", p.runID, execErr)
			return 0, err
		}
		if _, execErr := tx.Exec(`
			UPDATE incidents SET status = ?, updated_at = ?, next_dispatch_at = ''
			WHERE id = ? AND status NOT IN (?, ?, ?)
		`, StatusOpen, rfc3339(now), p.incidentID, StatusResolvedExternal, StatusClosed, StatusSuppressed); execErr != nil {
			err = fmt.Errorf("recover incident %s: %w", p.incidentID, execErr)
			return 0, err
		}
	}
	if commitErr := tx.Commit(); commitErr != nil {
		err = fmt.Errorf("commit recover: %w", commitErr)
		return 0, err
	}
	return len(inFlight), nil
}
