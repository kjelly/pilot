package agentcontroller

import (
	"fmt"
	"time"

	"github.com/kjelly/pilot/internal/policy"
)

// AutonomyState is the operator-controlled autonomy mode (design doc §9)
// plus who last changed it and why — DB state (autonomy_state singleton
// row), not a static config file, so `autonomy enable/disable` takes
// effect on the very next evaluation without an operator hand-editing
// YAML on the controller host.
type AutonomyState struct {
	Mode      string
	Actor     string
	Reason    string
	UpdatedAt time.Time
}

var validAutonomyModes = map[string]bool{
	policy.ModeDisabled: true, policy.ModeShadow: true, policy.ModeEnforced: true,
}

// AutonomyMode reads the current operator-controlled mode.
func (s *Store) AutonomyMode() (AutonomyState, error) {
	var st AutonomyState
	var actor, reason, updatedAt string
	err := s.db.QueryRow(`SELECT mode, COALESCE(actor, ''), COALESCE(reason, ''), updated_at FROM autonomy_state WHERE id = 1`).
		Scan(&st.Mode, &actor, &reason, &updatedAt)
	if err != nil {
		return AutonomyState{}, fmt.Errorf("read autonomy_state: %w", err)
	}
	st.Actor, st.Reason = actor, reason
	// The seed row (schemaV3) uses SQLite's datetime('now'), not
	// RFC3339 — every SetAutonomyMode call after that uses rfc3339(now)
	// like every other timestamp in this store. Tolerate either: this
	// field is informational display only, never guard-relevant math.
	if t, perr := time.Parse(time.RFC3339, updatedAt); perr == nil {
		st.UpdatedAt = t
	} else if t, perr := time.Parse("2006-01-02 15:04:05", updatedAt); perr == nil {
		st.UpdatedAt = t.UTC()
	}
	return st, nil
}

// SetAutonomyMode records an operator's mode change. actor is required
// (design doc §9: "Persist actor/reason/time") — never Agent-supplied
// text, always the CLI caller's own operator identity, same rule
// Store.Approve/Reject already enforce for human plan decisions.
func (s *Store) SetAutonomyMode(mode, actor, reason string, now time.Time) (AutonomyState, error) {
	if !validAutonomyModes[mode] {
		return AutonomyState{}, fmt.Errorf("invalid autonomy mode %q — must be disabled, shadow, or enforced", mode)
	}
	if actor == "" {
		return AutonomyState{}, fmt.Errorf("actor is required — autonomy mode changes must come from trusted operator context")
	}
	if _, err := s.db.Exec(`UPDATE autonomy_state SET mode = ?, actor = ?, reason = ?, updated_at = ? WHERE id = 1`,
		mode, actor, reason, rfc3339(now)); err != nil {
		return AutonomyState{}, fmt.Errorf("set autonomy mode: %w", err)
	}
	return AutonomyState{Mode: mode, Actor: actor, Reason: reason, UpdatedAt: now}, nil
}
