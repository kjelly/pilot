// edit_audit.go defines the frame-observer/recorder boundary
// docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md's
// Phase 1 calls for: a stable interface automationDriver notifies as it
// drives a scenario, independent of whether anything is actually
// listening. Phase 1 only ships the interface and a no-op default —
// the artifact-writing implementation (session.cast, trace.jsonl on
// disk under .pilot/audit/edit/...) is Phase 2's job.
package cmd

// AuditRecorder observes an automationDriver run without altering it —
// see the spec's "Recorder 不得改變 router state，也不得自行發送按鍵"
// invariant. Every method may be called from the same goroutine the
// driver runs on; a recorder that needs to persist data should do so
// synchronously or hand off internally, since the driver does not wait
// for or retry a failed call beyond surfacing its error.
type AuditRecorder interface {
	// RecordActionStart is called once per scenario step, before it's
	// dispatched to the action registry's Run function.
	RecordActionStart(step editAction) error
	// RecordKeys is called once per tea.KeyMsg the driver sends while
	// executing the current step — keys may be placeholders (e.g.
	// "«redacted»") rather than literal text, matching whatever the
	// driver itself would have recorded to a trace.
	RecordKeys(keys []string) error
	// RecordFrame is called after each key is applied, with the
	// resulting router state — the frame is read from the live
	// editRouterModel.View(), never synthesized.
	RecordFrame(event FrameEvent) error
	// RecordActionResult is called once per scenario step, after
	// dispatch returns — err is nil on success.
	RecordActionResult(step editAction, err error) error
}

// FrameEvent is one observed frame of the live TUI, taken immediately
// after a key was applied.
type FrameEvent struct {
	Sequence int
	ScreenID string
	View     string
}

// noopAuditRecorder is the default AuditRecorder: every existing
// automationDriver construction (CLI --actions path) leaves recorder
// unset, so it behaves exactly as it did before AuditRecorder existed.
type noopAuditRecorder struct{}

func (noopAuditRecorder) RecordActionStart(editAction) error         { return nil }
func (noopAuditRecorder) RecordKeys([]string) error                  { return nil }
func (noopAuditRecorder) RecordFrame(FrameEvent) error               { return nil }
func (noopAuditRecorder) RecordActionResult(editAction, error) error { return nil }
