// audit.go implements spec.md v3.1 §15: an append-only audit trail for
// explicit Pilot security operations. No recurring worker is involved —
// AppendAuditEvent is called once per explicit CLI invocation, at the
// point that invocation concludes.
package accessgrants

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
)

// AccessAuditEvent is one recorded Pilot security operation (§15's
// suggested model).
type AccessAuditEvent struct {
	ID         string    `json:"id"`
	At         time.Time `json:"at"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	SourceKind string    `json:"source_kind"`
	Resource   string    `json:"resource"`
	Reason     string    `json:"reason,omitempty"`
	Ticket     string    `json:"ticket,omitempty"`
	Outcome    string    `json:"outcome"`
	ErrorCode  string    `json:"error_code,omitempty"`
}

// §15.1's minimum event action vocabulary this delivery emits. Not every
// action §15.1 lists is wired to an emission point yet — see
// ReconcileOnce/DriftOnce/RepairManaged's callers for what actually fires
// today; this const block exists so every caller spells the action the
// same way rather than hand-typing strings that can silently drift apart.
const (
	AuditActionAccessDriftDetected     = "access_drift_detected"
	AuditActionAccessDriftRepaired     = "access_drift_repaired"
	AuditActionExplicitAccessReconcile = "explicit_access_reconcile"
)

const auditLogFilename = "audit.jsonl"

// AppendAuditEvent appends ev as one JSON line to <stateDir>/access/audit.jsonl
// (mode 0600, created if missing) under an exclusive advisory lock — the
// same flock(2)-on-a-sidecar-file convention internal/statefile uses,
// adapted for append-only rather than atomic-rewrite semantics (§15.3: a
// crashed writer must never truncate or corrupt prior entries, which an
// atomic-rewrite-on-every-append design would risk under a read-modify-
// write race). ev.ID/ev.At are filled in when unset.
func AppendAuditEvent(stateDir string, ev AccessAuditEvent) error {
	if stateDir == "" {
		return fmt.Errorf("accessgrants: state dir is required to record an audit event")
	}
	if ev.ID == "" {
		ev.ID = uuid.NewString()
	}
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}

	dir := filepath.Join(stateDir, "access")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("accessgrants: mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, auditLogFilename)

	lockFile, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("accessgrants: open audit lock: %w", err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("accessgrants: lock audit log: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("accessgrants: open audit log: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("accessgrants: encode audit event: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("accessgrants: write audit event: %w", err)
	}
	return nil
}
