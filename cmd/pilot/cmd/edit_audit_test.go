package cmd

import (
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

// fakeAuditRecorder counts AuditRecorder calls without altering
// anything — enforcing edit_audit.go's "Recorder 不得改變 router
// state，也不得自行發送按鍵" invariant by construction (it has no
// access to *editRouterModel or automationDriver at all).
type fakeAuditRecorder struct {
	actionStarts  int
	actionResults int
	keyBatches    int
	frames        int
}

func (f *fakeAuditRecorder) RecordActionStart(editAction) error         { f.actionStarts++; return nil }
func (f *fakeAuditRecorder) RecordKeys([]string) error                  { f.keyBatches++; return nil }
func (f *fakeAuditRecorder) RecordFrame(FrameEvent) error               { f.frames++; return nil }
func (f *fakeAuditRecorder) RecordActionResult(editAction, error) error { f.actionResults++; return nil }

func TestAutomationDriver_RecorderReceivesOneCallPerActionAndKey(t *testing.T) {
	dir := t.TempDir()
	role := inventory.Roles()[0].Name
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "enable_role", Host: "web-1", Role: role},
			{Action: "save_hosts"},
		},
	}

	rec := &fakeAuditRecorder{}
	r := newEditRouterModel(dir)
	d := automationDriver{recorder: rec}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	if rec.actionStarts != len(scenario.Steps) {
		t.Fatalf("actionStarts = %d, want %d", rec.actionStarts, len(scenario.Steps))
	}
	if rec.actionResults != len(scenario.Steps) {
		t.Fatalf("actionResults = %d, want %d", rec.actionResults, len(scenario.Steps))
	}
	if rec.keyBatches == 0 || rec.keyBatches != rec.frames {
		t.Fatalf("keyBatches = %d, frames = %d; want equal and non-zero (one RecordFrame per RecordKeys)", rec.keyBatches, rec.frames)
	}
}

func TestAutomationDriver_NilRecorderBehavesLikeNoop(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps:   []editAction{{Action: "create_host", Host: "web-1"}, {Action: "save_hosts"}},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{} // recorder left nil, exactly like every pre-Phase-1 construction
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() with nil recorder error = %v", err)
	}
}

func TestNoopAuditRecorder_AllMethodsReturnNil(t *testing.T) {
	var rec noopAuditRecorder
	if err := rec.RecordActionStart(editAction{}); err != nil {
		t.Fatalf("RecordActionStart() error = %v", err)
	}
	if err := rec.RecordKeys(nil); err != nil {
		t.Fatalf("RecordKeys() error = %v", err)
	}
	if err := rec.RecordFrame(FrameEvent{}); err != nil {
		t.Fatalf("RecordFrame() error = %v", err)
	}
	if err := rec.RecordActionResult(editAction{}, nil); err != nil {
		t.Fatalf("RecordActionResult() error = %v", err)
	}
}
