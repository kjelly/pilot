package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
)

// RunFilter limits a read-only delivery history query.
type RunFilter struct {
	Limit     int
	Host      string
	Component string
}

// DeliveryRun is the read-only projection of one append-only run stream.
type DeliveryRun struct {
	RunID           string
	StartedAt       string
	LastHeartbeatAt string
	FinishedAt      string
	Outcome         string
	ExitCode        *int
	Stage           string
	Component       string
	Components      []string
	Playbook        string
	Inventory       string
	Hosts           []string
	Metadata        map[string]any
}

// RunEvidence is the query-safe detail of one host × row observation.
type RunEvidence struct {
	SpecPath        string
	RowID           string
	Host            string
	Attempt         int
	ExitCode        int
	ProbeStatus     string
	Verdict         string
	Command         string
	Expected        string
	Stdout          string
	Stderr          string
	Redacted        bool
	StdoutTruncated bool
	StderrTruncated bool
	StartedAt       string
	FinishedAt      string
}

// PendingSpecHost is the latest recorded observation of a spec on one host.
// It intentionally makes no claim about hosts never recorded in the store;
// callers must provide inventory scope separately for that stronger question.
type PendingSpecHost struct {
	Host        string
	Verdict     string
	ProbeStatus string
	RunID       string
	FinishedAt  string
}

// EvidenceDiff records a changed, added, or removed host × row observation
// between two immutable runs.
type EvidenceDiff struct {
	SpecPath string
	RowID    string
	Host     string
	Before   string
	After    string
}

// ListRuns returns newest runs first. It never mutates evidence.
func (s *Store) ListRuns(filter RunFilter) ([]DeliveryRun, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	query := `SELECT r.run_id,r.started_at,COALESCE(r.last_heartbeat_at,''),COALESCE(r.finished_at,''),COALESCE(r.outcome,''),r.exit_code,
		COALESCE(e.payload_json,'{}')
		FROM delivery_runs r JOIN delivery_events e ON e.run_id=r.run_id AND e.type=?`
	args := []any{EventRunStarted}
	if filter.Component != "" {
		query += ` WHERE (json_extract(e.payload_json, '$.component')=? OR EXISTS (SELECT 1 FROM json_each(e.payload_json, '$.components') c WHERE c.value=?))`
		args = append(args, filter.Component, filter.Component)
	}
	if filter.Host != "" {
		if filter.Component == "" {
			query += " WHERE "
		} else {
			query += " AND "
		}
		query += `(EXISTS (SELECT 1 FROM json_each(e.payload_json, '$.hosts') h WHERE h.value=?) OR EXISTS (SELECT 1 FROM verify_evidence v WHERE v.run_id=r.run_id AND v.host=?))`
		args = append(args, filter.Host, filter.Host)
	}
	query += " ORDER BY r.started_at DESC LIMIT ?"
	args = append(args, filter.Limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list delivery runs: %w", err)
	}
	defer rows.Close()
	out := make([]DeliveryRun, 0)
	for rows.Next() {
		run, err := scanDeliveryRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// GetRun returns one run projection and its ordered immutable evidence.
func (s *Store) GetRun(runID string) (DeliveryRun, []RunEvidence, error) {
	row := s.db.QueryRow(`SELECT r.run_id,r.started_at,COALESCE(r.last_heartbeat_at,''),COALESCE(r.finished_at,''),COALESCE(r.outcome,''),r.exit_code,
		COALESCE(e.payload_json,'{}') FROM delivery_runs r JOIN delivery_events e ON e.run_id=r.run_id AND e.type=? WHERE r.run_id=?`, EventRunStarted, runID)
	run, err := scanDeliveryRun(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return DeliveryRun{}, nil, fmt.Errorf("delivery run %q not found", runID)
		}
		return DeliveryRun{}, nil, err
	}
	rows, err := s.db.Query(`SELECT spec_path,row_id,host,attempt,COALESCE(exit_code,0),probe_status,verdict,command,expected,COALESCE(stdout,''),COALESCE(stderr,''),redacted,stdout_truncated,stderr_truncated,started_at,finished_at FROM verify_evidence WHERE run_id=? ORDER BY spec_path,row_id,host,attempt`, runID)
	if err != nil {
		return DeliveryRun{}, nil, err
	}
	defer rows.Close()
	evidence := make([]RunEvidence, 0)
	for rows.Next() {
		var item RunEvidence
		var redacted, stdoutTruncated, stderrTruncated int
		if err := rows.Scan(&item.SpecPath, &item.RowID, &item.Host, &item.Attempt, &item.ExitCode, &item.ProbeStatus, &item.Verdict, &item.Command, &item.Expected, &item.Stdout, &item.Stderr, &redacted, &stdoutTruncated, &stderrTruncated, &item.StartedAt, &item.FinishedAt); err != nil {
			return DeliveryRun{}, nil, err
		}
		item.Redacted = redacted != 0
		item.StdoutTruncated = stdoutTruncated != 0
		item.StderrTruncated = stderrTruncated != 0
		evidence = append(evidence, item)
	}
	return run, evidence, rows.Err()
}

// LastSuccess returns the newest successful delivery that included host.
func (s *Store) LastSuccess(host string) (DeliveryRun, error) {
	runs, err := s.ListRuns(RunFilter{Host: host, Limit: 500})
	if err != nil {
		return DeliveryRun{}, err
	}
	for _, run := range runs {
		if run.Outcome == "success" || run.Outcome == "partial_success" {
			return run, nil
		}
	}
	return DeliveryRun{}, fmt.Errorf("no successful delivery recorded for host %q", host)
}

// PendingSpec returns the latest evidence for each host that did not pass the
// requested spec. It is an evidence query, not an inventory discovery API.
func (s *Store) PendingSpec(specPath string) ([]PendingSpecHost, error) {
	rows, err := s.db.Query(`SELECT v.host,v.verdict,v.probe_status,v.run_id,v.finished_at
		FROM verify_evidence v
		JOIN (SELECT host,MAX(evidence_id) evidence_id FROM verify_evidence WHERE spec_path=? GROUP BY host) latest ON latest.evidence_id=v.evidence_id
		WHERE v.verdict NOT IN ('pass','not_applicable') ORDER BY v.host`, specPath)
	if err != nil {
		return nil, fmt.Errorf("query pending spec %s: %w", specPath, err)
	}
	defer rows.Close()
	pending := make([]PendingSpecHost, 0)
	for rows.Next() {
		var item PendingSpecHost
		if err := rows.Scan(&item.Host, &item.Verdict, &item.ProbeStatus, &item.RunID, &item.FinishedAt); err != nil {
			return nil, err
		}
		pending = append(pending, item)
	}
	return pending, rows.Err()
}

// DiffRuns compares the latest observation for each host × row in two runs.
func (s *Store) DiffRuns(beforeID, afterID string) ([]EvidenceDiff, error) {
	before, err := s.evidenceVerdicts(beforeID)
	if err != nil {
		return nil, err
	}
	after, err := s.evidenceVerdicts(afterID)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]struct{}, len(before)+len(after))
	for key := range before {
		keys[key] = struct{}{}
	}
	for key := range after {
		keys[key] = struct{}{}
	}
	diffs := make([]EvidenceDiff, 0)
	for key := range keys {
		if before[key] == after[key] {
			continue
		}
		ref := parseEvidenceKey(key)
		diffs = append(diffs, EvidenceDiff{SpecPath: ref[0], RowID: ref[1], Host: ref[2], Before: before[key], After: after[key]})
	}
	sort.Slice(diffs, func(i, j int) bool { return evidenceDiffKey(diffs[i]) < evidenceDiffKey(diffs[j]) })
	return diffs, nil
}

func (s *Store) evidenceVerdicts(runID string) (map[string]string, error) {
	rows, err := s.db.Query(`SELECT spec_path,row_id,host,verdict FROM verify_evidence WHERE run_id=? ORDER BY evidence_id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var specPath, rowID, host, verdict string
		if err := rows.Scan(&specPath, &rowID, &host, &verdict); err != nil {
			return nil, err
		}
		out[evidenceKey(specPath, rowID, host)] = verdict
	}
	return out, rows.Err()
}

func scanDeliveryRun(scanner interface{ Scan(...any) error }) (DeliveryRun, error) {
	var run DeliveryRun
	var exit sql.NullInt64
	var payload string
	if err := scanner.Scan(&run.RunID, &run.StartedAt, &run.LastHeartbeatAt, &run.FinishedAt, &run.Outcome, &exit, &payload); err != nil {
		return DeliveryRun{}, err
	}
	if exit.Valid {
		value := int(exit.Int64)
		run.ExitCode = &value
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		return DeliveryRun{}, fmt.Errorf("decode run payload: %w", err)
	}
	run.Stage, _ = decoded["stage"].(string)
	run.Component, _ = decoded["component"].(string)
	run.Playbook, _ = decoded["playbook"].(string)
	run.Inventory, _ = decoded["inventory"].(string)
	run.Components = stringSlice(decoded["components"])
	if len(run.Components) == 0 && run.Component != "" {
		run.Components = []string{run.Component}
	}
	run.Hosts = stringSlice(decoded["hosts"])
	if metadata, ok := decoded["metadata"].(map[string]any); ok {
		run.Metadata = metadata
	}
	return run, nil
}

func stringSlice(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func evidenceKey(specPath, rowID, host string) string {
	return specPath + "\x00" + rowID + "\x00" + host
}
func parseEvidenceKey(key string) [3]string {
	var out [3]string
	start := 0
	for i := 0; i < len(out)-1; i++ {
		for j := start; j < len(key); j++ {
			if key[j] == 0 {
				out[i] = key[start:j]
				start = j + 1
				break
			}
		}
	}
	out[2] = key[start:]
	return out
}
func evidenceDiffKey(diff EvidenceDiff) string {
	return evidenceKey(diff.SpecPath, diff.RowID, diff.Host)
}
