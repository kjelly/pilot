package detection

// LifecycleState is one host's adaptive-anomaly state (spec §20).
type LifecycleState string

const (
	StateNormal     LifecycleState = "normal"
	StateCandidate  LifecycleState = "candidate"
	StateFiring     LifecycleState = "firing"
	StateRecovering LifecycleState = "recovering"
)

// Severity is the active severity of a firing/recovering episode (spec §20).
type Severity string

const (
	SeverityNone     Severity = ""
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Threshold constants shared across candidate gating (spec §18) and the
// lifecycle state machine (spec §20). CandidateThreshold and
// ModelTriggerThreshold are the same 0.65 value under two spec-traceable
// names because spec §18's MODEL_TRIGGER and spec §20's "candidate >= 0.65"
// are the same numeric gate.
const (
	CandidateThreshold    = 0.65
	ModelTriggerThreshold = CandidateThreshold
	WarningThreshold      = 0.80
	CriticalThreshold     = 0.95
	RecoveryThreshold     = 0.60
)

// LifecycleAction is what a Transition asks the caller (the engine) to do
// about a host's SignalEvent episode.
type LifecycleAction string

const (
	ActionNone             LifecycleAction = "none"
	ActionCreateWarning    LifecycleAction = "create_warning"
	ActionCreateCritical   LifecycleAction = "create_critical"
	ActionEscalateCritical LifecycleAction = "escalate_critical"
	ActionEnterRecovering  LifecycleAction = "enter_recovering"
	ActionReturnToFiring   LifecycleAction = "return_to_firing"
	ActionResolve          LifecycleAction = "resolve"
)

// Transition describes one Advance() call's effect on episode state.
type Transition struct {
	Action    LifecycleAction
	FromState LifecycleState
	ToState   LifecycleState
	// Severity is the resulting active severity for create/escalate/
	// enter-recovering/return-to-firing actions, and the just-resolved
	// severity for ActionResolve. Empty for ActionNone.
	Severity Severity
}

// HostLifecycle is one host's mutable adaptive-anomaly state machine
// (spec §20). Zero value is not valid — use NewHostLifecycle.
type HostLifecycle struct {
	State                LifecycleState
	Severity             Severity
	PriorSeverity        Severity
	WarningHistory       []bool // last up to 4 valid-cycle booleans, oldest first
	CriticalStreak       int
	RecoveryStreak       int
	CandidateClearStreak int
}

// NewHostLifecycle returns a fresh host starting in the normal state.
func NewHostLifecycle() *HostLifecycle {
	return &HostLifecycle{State: StateNormal}
}

func countTrue(bs []bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

// Advance applies one valid fused score to the state machine (spec §20).
// Callers MUST NOT call Advance for an invalid cycle (spec §20.7: invalid
// telemetry/source cycles do not advance any counter, create, fire, or
// resolve anything — the active episode, if any, simply stays active).
func (h *HostLifecycle) Advance(score float64) Transition {
	// §20.1: every valid cycle updates these three counters first,
	// regardless of which state the host is currently in.
	h.WarningHistory = append(h.WarningHistory, score >= WarningThreshold)
	if len(h.WarningHistory) > 4 {
		h.WarningHistory = h.WarningHistory[len(h.WarningHistory)-4:]
	}
	if score >= CriticalThreshold {
		h.CriticalStreak++
	} else {
		h.CriticalStreak = 0
	}
	if score < RecoveryThreshold {
		h.RecoveryStreak++
	} else {
		h.RecoveryStreak = 0
	}

	switch h.State {
	case StateNormal:
		return h.advanceNormal(score)
	case StateCandidate:
		return h.advanceCandidate(score)
	case StateFiring:
		return h.advanceFiring()
	case StateRecovering:
		return h.advanceRecovering(score)
	default:
		return Transition{Action: ActionNone, FromState: h.State, ToState: h.State}
	}
}

// checkFiringTrigger implements the priority rule shared by normal and
// candidate (spec §20.2/§20.3): two consecutive critical-threshold cycles
// beats three-of-last-four warning-threshold cycles.
func (h *HostLifecycle) checkFiringTrigger() (LifecycleAction, Severity, bool) {
	if h.CriticalStreak >= 2 {
		return ActionCreateCritical, SeverityCritical, true
	}
	if countTrue(h.WarningHistory) >= 3 {
		return ActionCreateWarning, SeverityWarning, true
	}
	return ActionNone, SeverityNone, false
}

func (h *HostLifecycle) advanceNormal(score float64) Transition {
	from := h.State
	if action, sev, ok := h.checkFiringTrigger(); ok {
		h.State = StateFiring
		h.Severity = sev
		return Transition{Action: action, FromState: from, ToState: h.State, Severity: sev}
	}
	if score >= CandidateThreshold {
		h.State = StateCandidate
		h.CandidateClearStreak = 0
	}
	return Transition{Action: ActionNone, FromState: from, ToState: h.State}
}

func (h *HostLifecycle) advanceCandidate(score float64) Transition {
	from := h.State
	if action, sev, ok := h.checkFiringTrigger(); ok {
		h.State = StateFiring
		h.Severity = sev
		return Transition{Action: action, FromState: from, ToState: h.State, Severity: sev}
	}
	if score < CandidateThreshold {
		h.CandidateClearStreak++
	} else {
		h.CandidateClearStreak = 0
	}
	if h.CandidateClearStreak >= 2 {
		h.State = StateNormal
		h.CandidateClearStreak = 0
	}
	return Transition{Action: ActionNone, FromState: from, ToState: h.State}
}

func (h *HostLifecycle) advanceFiring() Transition {
	from := h.State
	if h.Severity == SeverityWarning {
		if h.CriticalStreak >= 2 {
			h.Severity = SeverityCritical
			return Transition{Action: ActionEscalateCritical, FromState: from, ToState: h.State, Severity: SeverityCritical}
		}
		if h.RecoveryStreak >= 1 {
			h.PriorSeverity = SeverityWarning
			h.State = StateRecovering
			return Transition{Action: ActionEnterRecovering, FromState: from, ToState: h.State, Severity: SeverityWarning}
		}
		return Transition{Action: ActionNone, FromState: from, ToState: h.State, Severity: h.Severity}
	}
	// SeverityCritical: never downgrades to warning within the same episode.
	if h.RecoveryStreak >= 1 {
		h.PriorSeverity = SeverityCritical
		h.State = StateRecovering
		return Transition{Action: ActionEnterRecovering, FromState: from, ToState: h.State, Severity: SeverityCritical}
	}
	return Transition{Action: ActionNone, FromState: from, ToState: h.State, Severity: h.Severity}
}

func (h *HostLifecycle) advanceRecovering(score float64) Transition {
	from := h.State
	if h.RecoveryStreak >= 4 {
		resolved := h.PriorSeverity
		h.State = StateNormal
		h.Severity = SeverityNone
		h.PriorSeverity = SeverityNone
		h.RecoveryStreak = 0
		return Transition{Action: ActionResolve, FromState: from, ToState: h.State, Severity: resolved}
	}
	if score >= RecoveryThreshold {
		h.State = StateFiring
		h.Severity = h.PriorSeverity
		h.RecoveryStreak = 0
		return Transition{Action: ActionReturnToFiring, FromState: from, ToState: h.State, Severity: h.Severity}
	}
	return Transition{Action: ActionNone, FromState: from, ToState: h.State, Severity: h.PriorSeverity}
}
