package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"
)

// EvidenceArchive is an immutable export proof. ArchiveID must be supplied to
// PruneEvidenceArchive; a path alone is never sufficient authorization.
type EvidenceArchive struct {
	ArchiveID string    `json:"archiveID"`
	Path      string    `json:"path"`
	SHA256    string    `json:"sha256"`
	Before    time.Time `json:"before"`
	RunIDs    []string  `json:"runIDs"`
}

type archivedEvidence struct {
	RunID string           `json:"runID"`
	Rows  []map[string]any `json:"rows"`
}

type archiveDocument struct {
	Format    string             `json:"format"`
	CreatedAt time.Time          `json:"createdAt"`
	Before    time.Time          `json:"before"`
	Runs      []string           `json:"runs"`
	Events    []map[string]any   `json:"events"`
	Evidence  []archivedEvidence `json:"evidence"`
}

// ArchiveEvidenceBefore exports every finished delivery strictly before before
// to a new file. It never overwrites a path and records an append-only admin
// completion event containing the hash and exact eligible run IDs.
func (s *Store) ArchiveEvidenceBefore(ctx context.Context, before time.Time, path string) (EvidenceArchive, error) {
	if before.IsZero() || path == "" {
		return EvidenceArchive{}, fmt.Errorf("archive evidence: before and path are required")
	}
	runIDs, err := s.finishedRunsBefore(ctx, before)
	if err != nil {
		return EvidenceArchive{}, err
	}
	archive := EvidenceArchive{ArchiveID: uuid.NewString(), Path: path, Before: before.UTC(), RunIDs: runIDs}
	if err := s.appendAdminEvent(ctx, archive.ArchiveID+":requested", "archive_requested", archive); err != nil {
		return EvidenceArchive{}, err
	}
	document, err := s.archiveDocument(ctx, archive)
	if err != nil {
		return EvidenceArchive{}, err
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return EvidenceArchive{}, fmt.Errorf("encode evidence archive: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return EvidenceArchive{}, fmt.Errorf("create evidence archive: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		_ = file.Close()
		return EvidenceArchive{}, fmt.Errorf("write evidence archive: %w", err)
	}
	if err := file.Close(); err != nil {
		return EvidenceArchive{}, fmt.Errorf("close evidence archive: %w", err)
	}
	digest := sha256.Sum256(append(encoded, '\n'))
	archive.SHA256 = hex.EncodeToString(digest[:])
	if err := s.appendAdminEvent(ctx, archive.ArchiveID+":completed", "archive_completed", archive); err != nil {
		return EvidenceArchive{}, err
	}
	return archive, nil
}

// PruneEvidenceArchive removes only the completed archive's exact run set,
// after verifying the on-disk archive hash. It is the sole code path that
// enables the scoped SQLite delete gate, and leaves a separate admin audit.
func (s *Store) PruneEvidenceArchive(ctx context.Context, archiveID string) (int, error) {
	if archiveID == "" {
		return 0, fmt.Errorf("prune evidence: archive id is required")
	}
	archive, err := s.completedArchive(ctx, archiveID)
	if err != nil {
		return 0, err
	}
	contents, err := os.ReadFile(archive.Path)
	if err != nil {
		return 0, fmt.Errorf("read evidence archive: %w", err)
	}
	digest := sha256.Sum256(contents)
	if hex.EncodeToString(digest[:]) != archive.SHA256 {
		return 0, fmt.Errorf("evidence archive hash does not match recorded completion event")
	}
	if err := s.appendAdminEvent(ctx, archiveID+":prune_requested", "prune_requested", archive); err != nil {
		return 0, err
	}
	if len(archive.RunIDs) == 0 {
		if err := s.appendAdminEvent(ctx, archiveID+":prune_completed", "prune_completed", map[string]any{"archiveID": archiveID, "runs": 0}); err != nil {
			return 0, err
		}
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_admin_mode (enabled) VALUES (1)`); err != nil {
		return 0, err
	}
	placeholders, args := sqlPlaceholders(archive.RunIDs)
	if _, err := tx.ExecContext(ctx, `DELETE FROM verify_evidence WHERE run_id IN (`+placeholders+`)`, args...); err != nil {
		return 0, fmt.Errorf("prune verify evidence: %w", err)
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM delivery_events WHERE run_id IN (`+placeholders+`)`, args...)
	if err != nil {
		return 0, fmt.Errorf("prune delivery events: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM evidence_admin_mode`); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := s.appendAdminEvent(ctx, archiveID+":prune_completed", "prune_completed", map[string]any{"archiveID": archiveID, "runs": len(archive.RunIDs), "delivery_events": count}); err != nil {
		return 0, err
	}
	return len(archive.RunIDs), nil
}

func (s *Store) finishedRunsBefore(ctx context.Context, before time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT run_id FROM delivery_runs WHERE finished_at IS NOT NULL AND finished_at < ? ORDER BY run_id`, before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) archiveDocument(ctx context.Context, archive EvidenceArchive) (archiveDocument, error) {
	doc := archiveDocument{Format: "pilot-evidence-archive/v1", CreatedAt: time.Now().UTC(), Before: archive.Before, Runs: archive.RunIDs}
	if len(archive.RunIDs) == 0 {
		return doc, nil
	}
	placeholders, args := sqlPlaceholders(archive.RunIDs)
	events, err := s.rowsAsMaps(ctx, `SELECT run_id,seq,operation_id,type,step,payload_json,exit_code,created_at FROM delivery_events WHERE run_id IN (`+placeholders+`) ORDER BY run_id,seq`, args...)
	if err != nil {
		return doc, err
	}
	doc.Events = events
	evidence, err := s.rowsAsMaps(ctx, `SELECT run_id,spec_path,row_id,host,attempt,operation_id,content_hash,command,expected,stdout,stderr,exit_code,probe_status,verdict,redacted,stdout_truncated,stderr_truncated,started_at,finished_at FROM verify_evidence WHERE run_id IN (`+placeholders+`) ORDER BY run_id,evidence_id`, args...)
	if err != nil {
		return doc, err
	}
	byRun := make(map[string][]map[string]any)
	for _, row := range evidence {
		byRun[fmt.Sprint(row["run_id"])] = append(byRun[fmt.Sprint(row["run_id"])], row)
	}
	for _, id := range archive.RunIDs {
		doc.Evidence = append(doc.Evidence, archivedEvidence{RunID: id, Rows: byRun[id]})
	}
	return doc, nil
}

func (s *Store) rowsAsMaps(ctx context.Context, query string, args ...any) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var result []map[string]any
	for rows.Next() {
		values := make([]any, len(columns))
		destinations := make([]any, len(columns))
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(columns))
		for i, value := range values {
			if raw, ok := value.([]byte); ok {
				row[columns[i]] = string(raw)
			} else {
				row[columns[i]] = value
			}
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *Store) appendAdminEvent(ctx context.Context, eventID, typ string, payload any) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO evidence_admin_events (event_id,type,payload_json,created_at) VALUES (?,?,?,?)`, eventID, typ, string(encoded), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("append evidence admin event: %w", err)
	}
	return nil
}

func (s *Store) completedArchive(ctx context.Context, archiveID string) (EvidenceArchive, error) {
	var payload string
	err := s.db.QueryRowContext(ctx, `SELECT payload_json FROM evidence_admin_events WHERE event_id=? AND type='archive_completed'`, archiveID+":completed").Scan(&payload)
	if err != nil {
		return EvidenceArchive{}, fmt.Errorf("find completed evidence archive: %w", err)
	}
	var archive EvidenceArchive
	if err := json.Unmarshal([]byte(payload), &archive); err != nil {
		return EvidenceArchive{}, fmt.Errorf("decode completed evidence archive: %w", err)
	}
	if archive.ArchiveID != archiveID {
		return EvidenceArchive{}, fmt.Errorf("archive completion event has inconsistent id")
	}
	sort.Strings(archive.RunIDs)
	return archive, nil
}

func sqlPlaceholders(ids []string) (string, []any) {
	parts := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		parts[i], args[i] = "?", id
	}
	return join(parts, ","), args
}

func join(parts []string, separator string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for _, part := range parts[1:] {
		result += separator + part
	}
	return result
}
