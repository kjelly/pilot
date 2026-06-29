package agent

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/ollama"
	"github.com/anomalyco/pilot/internal/sanitizer"
	"github.com/anomalyco/pilot/internal/tools"
)

// capturingApprover records the last proposal it was asked about and
// auto-approves. Used to assert on proposal metadata (rationale/risk).
type capturingApprover struct{ last *Proposal }

func (c *capturingApprover) Ask(p *Proposal) Decision { c.last = p; return DecisionApproved }

func newRationaleTestLoop(t *testing.T, app *capturingApprover) *Loop {
	t.Helper()
	reg := tools.NewRegistry()
	if err := reg.Register(&tools.Spec{
		Name:        "run_command",
		Description: "runs a read-only command",
		Parameters:  json.RawMessage(`{"type":"object","properties":{"command":{"type":"string"}}}`),
		Execute: func(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
			return &tools.Result{Content: "ok"}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	return NewLoop(Config{
		RunID:        "r",
		Tools:        reg,
		Sanitizer:    sanitizer.New(),
		Approver:     app,
		StreamWriter: io.Discard,
		MaxIter:      1,
	})
}

// TestHandleToolCall_FallbackRationaleFromAssistantText pins fix "A":
// when the model omits an explicit _rationale arg, the proposal's
// rationale falls back to the turn's assistant narration instead of
// being blank.
func TestHandleToolCall_FallbackRationaleFromAssistantText(t *testing.T) {
	app := &capturingApprover{}
	loop := newRationaleTestLoop(t, app)
	loop.lastAssistantText = "No inventory was provided. Let me check the current state."

	tc := ollama.ToolCall{Function: ollama.ToolCallFunction{Name: "run_command", Arguments: json.RawMessage(`{"command":"ls"}`)}}
	if _, err := loop.handleToolCall(context.Background(), tc); err != nil {
		t.Fatalf("handleToolCall: %v", err)
	}
	if app.last == nil {
		t.Fatal("approver was never asked")
	}
	if !strings.Contains(app.last.Rationale, "Let me check the current state") {
		t.Errorf("expected fallback rationale from assistant text, got %q", app.last.Rationale)
	}
}

// TestHandleToolCall_ExplicitRationaleWins pins that an explicit
// _rationale arg takes precedence over the assistant-text fallback.
func TestHandleToolCall_ExplicitRationaleWins(t *testing.T) {
	app := &capturingApprover{}
	loop := newRationaleTestLoop(t, app)
	loop.lastAssistantText = "some narration that should be ignored"

	tc := ollama.ToolCall{Function: ollama.ToolCallFunction{Name: "run_command", Arguments: json.RawMessage(`{"command":"ls","_rationale":"verify the package is installed","_risk_level":"low"}`)}}
	if _, err := loop.handleToolCall(context.Background(), tc); err != nil {
		t.Fatalf("handleToolCall: %v", err)
	}
	if app.last == nil {
		t.Fatal("approver was never asked")
	}
	if app.last.Rationale != "verify the package is installed" {
		t.Errorf("explicit _rationale should win, got %q", app.last.Rationale)
	}
	if app.last.RiskLevel != RiskLow {
		t.Errorf("explicit _risk_level=low should be honoured, got %q", app.last.RiskLevel)
	}
}

// TestRecordAndMaybeBreakLoop_ReturnsFalseUntilThirdCall is a regression
// test for the "agent loop runs the playbook infinitely" bug. The LLM
// used to call run_ansible with the same args 5-10 times in a row,
// each time seeing the same PLAY RECAP and deciding "let me try again".
// We now return true (abort signal) on the THIRD identical call so
// the agent loop terminates cleanly.
func TestRecordAndMaybeBreakLoop_ReturnsFalseUntilThirdCall(t *testing.T) {
	loop := &Loop{
		recentToolCalls: make(map[string]int),
		cfg:             Config{Sanitizer: sanitizer.New()},
	}
	tc := ollama.ToolCall{
		Function: ollama.ToolCallFunction{
			Name:      "run_ansible",
			Arguments: []byte(`{"playbook":"x.yaml"}`),
		},
	}

	// First two calls: no abort, no history change.
	for i := 0; i < 2; i++ {
		before := len(loop.history)
		if loop.recordAndMaybeBreakLoop(tc, "result "+string(rune('0'+i))) {
			t.Errorf("call %d: recordAndMaybeBreakLoop returned true (abort) too early; should wait for the third identical call", i)
		}
		if len(loop.history) != before {
			t.Errorf("call %d: history should be unchanged, but %d new entries were appended", i, len(loop.history)-before)
		}
	}

	// Verify the counter is at 2.
	if c := loop.recentToolCalls[loop.toolCallKey(tc)]; c != 2 {
		t.Errorf("counter should be 2 after 2 calls, got %d", c)
	}

	// Third call: returns true (abort) AND appends the LOOP GUARD footer.
	before := len(loop.history)
	abort := loop.recordAndMaybeBreakLoop(tc, "result 2")
	if !abort {
		t.Error("third call: recordAndMaybeBreakLoop should return true to signal abort")
	}
	if len(loop.history) != before+1 {
		t.Fatalf("third call: expected 1 new history entry, got %d", len(loop.history)-before)
	}
	if !strings.Contains(loop.history[len(loop.history)-1].Content, "LOOP GUARD") {
		t.Errorf("third call: expected LOOP GUARD footer in appended result, got: %q", loop.history[len(loop.history)-1].Content)
	}
	if c := loop.recentToolCalls[loop.toolCallKey(tc)]; c != 3 {
		t.Errorf("counter should be 3, got %d", c)
	}
}

// TestToolCallKey_DifferentArgsProduceDifferentKeys guards against a
// regression where the loop guard might conflate legitimately different
// tool calls (e.g. run_ansible with different playbooks).
func TestToolCallKey_DifferentArgsProduceDifferentKeys(t *testing.T) {
	loop := &Loop{
		recentToolCalls: make(map[string]int),
	}
	tc1 := ollama.ToolCall{Function: ollama.ToolCallFunction{Name: "run_ansible", Arguments: []byte(`{"playbook":"a.yaml"}`)}}
	tc2 := ollama.ToolCall{Function: ollama.ToolCallFunction{Name: "run_ansible", Arguments: []byte(`{"playbook":"b.yaml"}`)}}
	if loop.toolCallKey(tc1) == loop.toolCallKey(tc2) {
		t.Error("different playbooks should produce different keys")
	}
	tc3 := ollama.ToolCall{Function: ollama.ToolCallFunction{Name: "read_file", Arguments: []byte(`{"path":"/etc/hosts"}`)}}
	if loop.toolCallKey(tc1) == loop.toolCallKey(tc3) {
		t.Error("different tool names should produce different keys")
	}
}

// TestRecordAndMaybeBreakPostSuccess_NudgeThenAbort is a regression test
// for the "agent keeps probing after the playbook already succeeded" bug.
// A weaker model (e.g. minimax-m3) used to run run_ansible to a clean
// PLAY RECAP (failed=0) and then issue an unbounded stream of DIFFERENT
// read-only run_command probes, which the identical-args loop guard never
// catches. This guard nudges on the 2nd probe and aborts on the 3rd.
func TestRecordAndMaybeBreakPostSuccess_NudgeThenAbort(t *testing.T) {
	loop := &Loop{
		recentToolCalls: make(map[string]int),
		cfg:             Config{Sanitizer: sanitizer.New()},
	}
	ansibleTC := ollama.ToolCall{Function: ollama.ToolCallFunction{Name: "run_ansible", Arguments: []byte(`{"playbook":"x.yaml"}`)}}

	// A successful playbook run arms the guard but is not itself a probe.
	if loop.recordAndMaybeBreakPostSuccess(ansibleTC, &tools.Result{Content: "PLAY RECAP ... failed=0"}) {
		t.Fatal("a successful playbook run must not abort")
	}
	if !loop.playbookSucceeded {
		t.Fatal("playbookSucceeded should be set after a clean run_ansible")
	}

	// Each probe uses DIFFERENT args, so the identical-args guard would
	// never fire — this guard must catch it anyway.
	probe := func(cmd string) ollama.ToolCall {
		return ollama.ToolCall{Function: ollama.ToolCallFunction{Name: "run_command", Arguments: []byte(`{"command":"` + cmd + `"}`)}}
	}

	// 1st probe: allowed silently (verifying the result is legitimate).
	before := len(loop.history)
	if loop.recordAndMaybeBreakPostSuccess(probe("ls"), &tools.Result{}) {
		t.Error("1st post-success probe should not abort")
	}
	if len(loop.history) != before {
		t.Error("1st probe should not append any history")
	}

	// 2nd probe: soft nudge appended, no abort.
	if loop.recordAndMaybeBreakPostSuccess(probe("cat /etc/hosts"), &tools.Result{}) {
		t.Error("2nd post-success probe should not abort yet")
	}
	if last := loop.history[len(loop.history)-1].Content; !strings.Contains(last, "NOTE") {
		t.Errorf("2nd probe should append a NOTE nudge, got: %q", last)
	}

	// 3rd probe: LOOP GUARD footer + abort.
	if !loop.recordAndMaybeBreakPostSuccess(probe("uname -a"), &tools.Result{}) {
		t.Error("3rd post-success probe should abort")
	}
	if last := loop.history[len(loop.history)-1].Content; !strings.Contains(last, "LOOP GUARD") {
		t.Errorf("3rd probe should append a LOOP GUARD footer, got: %q", last)
	}
}

// TestRecordAndMaybeBreakPostSuccess_FailedRunResetsBudget pins that a
// FAILED playbook run clears the success flag, so the model gets a fresh
// budget of probes to diagnose and fix the failure.
func TestRecordAndMaybeBreakPostSuccess_FailedRunResetsBudget(t *testing.T) {
	loop := &Loop{recentToolCalls: make(map[string]int), cfg: Config{Sanitizer: sanitizer.New()}}
	ansibleTC := ollama.ToolCall{Function: ollama.ToolCallFunction{Name: "run_ansible", Arguments: []byte(`{"playbook":"x.yaml"}`)}}
	probe := ollama.ToolCall{Function: ollama.ToolCallFunction{Name: "run_command", Arguments: []byte(`{"command":"ls"}`)}}

	loop.recordAndMaybeBreakPostSuccess(ansibleTC, &tools.Result{}) // success
	loop.recordAndMaybeBreakPostSuccess(probe, &tools.Result{})     // probe 1

	// A failed playbook run must reset the window.
	loop.recordAndMaybeBreakPostSuccess(ansibleTC, &tools.Result{IsError: true})
	if loop.playbookSucceeded {
		t.Error("a failed playbook run must clear playbookSucceeded")
	}
	if loop.postSuccessProbes != 0 {
		t.Errorf("probe counter should reset to 0 after a failed run, got %d", loop.postSuccessProbes)
	}
	// Now probes should not be counted/aborted (no success in effect).
	if loop.recordAndMaybeBreakPostSuccess(probe, &tools.Result{}) {
		t.Error("probe after a failed run should not abort (fresh budget)")
	}
}

// TestRecordAndMaybeBreakLoop_FreshLoopStartsEmpty pins that the
// counter is on the Loop struct, not a global, so a new run starts
// fresh.
func TestRecordAndMaybeBreakLoop_FreshLoopStartsEmpty(t *testing.T) {
	l1 := &Loop{recentToolCalls: make(map[string]int), cfg: Config{Sanitizer: sanitizer.New()}}
	tc := ollama.ToolCall{Function: ollama.ToolCallFunction{Name: "x", Arguments: []byte(`{}`)}}
	for i := 0; i < 3; i++ {
		l1.recordAndMaybeBreakLoop(tc, "ok")
	}
	if l1.recentToolCalls[l1.toolCallKey(tc)] != 3 {
		t.Fatal("first loop counter not at 3")
	}
	l2 := &Loop{recentToolCalls: make(map[string]int), cfg: Config{Sanitizer: sanitizer.New()}}
	if c := l2.recentToolCalls[l2.toolCallKey(tc)]; c != 0 {
		t.Errorf("second loop counter should start at 0, got %d", c)
	}
}
