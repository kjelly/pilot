// Package tui: tests for the Update state machine and View rendering.
//
// We test the model directly without spinning up a tea.Program so the
// tests are fast and do not need a real terminal.
package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/anomalyco/pilot/internal/agent"
	"github.com/anomalyco/pilot/internal/store"
)

func newTestModel() *Model {
	m := newModel(nil)
	m.SetSize(120, 40) // give it a reasonable viewport
	return m
}

func key(r rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
}

func enterKey() tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyEnter}
}

// --- Run lifecycle ----------------------------------------------------------

func TestUpdateRunStartedClearsState(t *testing.T) {
	m := newTestModel()
	m.proposalCount = 5
	m.iter = 7

	updated, _ := m.Update(RunStartedMsg{RunID: "abc12345-xyz", Goal: "do thing"})
	m = updated.(*Model)

	if m.runID != "abc12345-xyz" {
		t.Errorf("runID not set: %s", m.runID)
	}
	if m.iter != 0 {
		t.Errorf("iter not reset: %d", m.iter)
	}
	if m.proposalCount != 0 {
		t.Errorf("proposalCount not reset: %d", m.proposalCount)
	}
	if !strings.Contains(m.chat, "do thing") {
		t.Errorf("goal not echoed in chat: %s", m.chat)
	}
}

func TestUpdateLLMChunkAppendsContent(t *testing.T) {
	m := newTestModel()
	updated, _ := m.Update(LLMChunkMsg{Content: "hello world"})
	m = updated.(*Model)
	if !strings.Contains(m.chat, "hello world") {
		t.Errorf("chunk not in chat: %s", m.chat)
	}
}

func TestUpdateLLMChunkThinkingHiddenByDefault(t *testing.T) {
	m := newTestModel()
	updated, _ := m.Update(LLMChunkMsg{Thinking: "secret reasoning"})
	m = updated.(*Model)
	if strings.Contains(m.chat, "secret reasoning") {
		t.Errorf("thinking leaked when showThinking=false: %s", m.chat)
	}
}

func TestUpdateLLMChunkThinkingVisibleAfterToggle(t *testing.T) {
	m := newTestModel()
	// press 't' to toggle
	updated, _ := m.Update(key('t'))
	m = updated.(*Model)
	if !m.showThinking {
		t.Fatal("showThinking not toggled on")
	}
	// now send a thinking chunk
	updated, _ = m.Update(LLMChunkMsg{Thinking: "secret reasoning"})
	m = updated.(*Model)
	if !strings.Contains(m.chat, "secret reasoning") {
		t.Errorf("thinking not visible after toggle: %s", m.chat)
	}
}

func TestUpdateLLMDoneSeparatesTurn(t *testing.T) {
	m := newTestModel()
	updated, _ := m.Update(LLMChunkMsg{Content: "first turn"})
	m = updated.(*Model)
	updated, _ = m.Update(LLMChunkMsg{Done: true})
	m = updated.(*Model)
	updated, _ = m.Update(LLMChunkMsg{Content: "second turn"})
	m = updated.(*Model)
	// both turns should be present, separated by a blank line
	if !strings.Contains(m.chat, "first turn") || !strings.Contains(m.chat, "second turn") {
		t.Errorf("turns lost: %s", m.chat)
	}
}

func TestUpdateStatusRefreshesCounters(t *testing.T) {
	m := newTestModel()
	updated, _ := m.Update(StatusUpdateMsg{
		Iter: 3, MaxIter: 20, ProposalCount: 2, PendingCount: 1,
		CurrentTool: "run_ansible", CurrentHost: "web01",
	})
	m = updated.(*Model)
	if m.iter != 3 || m.proposalCount != 2 || m.currentTool != "run_ansible" {
		t.Errorf("status not applied: %+v", m)
	}
}

// --- Proposal approval ------------------------------------------------------

func TestUpdateProposalRequestEntersApprovingMode(t *testing.T) {
	m := newTestModel()
	reply := make(chan agent.Decision, 1)
	prop := &agent.Proposal{ID: "p-1234", Tool: "run_ansible", RiskLevel: "medium", Rationale: "test"}
	updated, _ := m.Update(ProposalRequestMsg{Proposal: prop, Reply: reply})
	m = updated.(*Model)
	if m.mode != ModeApproving {
		t.Errorf("not in approving mode: %v", m.mode)
	}
	if m.proposalCount != 1 || m.pendingCount != 1 {
		t.Errorf("counters not updated: %d/%d", m.proposalCount, m.pendingCount)
	}
}

func TestUpdateApproveKeySendsDecision(t *testing.T) {
	m := newTestModel()
	reply := make(chan agent.Decision, 1)
	prop := &agent.Proposal{ID: "p", Tool: "read_file", RiskLevel: "low"}
	updated, _ := m.Update(ProposalRequestMsg{Proposal: prop, Reply: reply})
	m = updated.(*Model)

	updated, cmd := m.Update(key('y'))
	m = updated.(*Model)
	// Execute the returned tea.Cmd to actually fire the reply.
	if cmd != nil {
		_ = cmd()
	}

	select {
	case d := <-reply:
		if d != agent.DecisionApproved {
			t.Errorf("expected DecisionApproved, got %v", d)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no decision sent on 'y'")
	}
	if m.mode != ModeRunning {
		t.Errorf("not back to running mode: %v", m.mode)
	}
}

func TestUpdateRejectKeySendsDecision(t *testing.T) {
	m := newTestModel()
	reply := make(chan agent.Decision, 1)
	updated, _ := m.Update(ProposalRequestMsg{Proposal: &agent.Proposal{ID: "p", Tool: "x"}, Reply: reply})
	m = updated.(*Model)
	_, cmd := m.Update(key('n'))
	if cmd != nil {
		_ = cmd()
	}

	select {
	case d := <-reply:
		if d != agent.DecisionRejected {
			t.Errorf("expected DecisionRejected, got %v", d)
		}
	default:
		t.Fatal("no decision sent on 'n'")
	}
}

func TestUpdateAbortKeySendsDecision(t *testing.T) {
	m := newTestModel()
	reply := make(chan agent.Decision, 1)
	updated, _ := m.Update(ProposalRequestMsg{Proposal: &agent.Proposal{ID: "p"}, Reply: reply})
	m = updated.(*Model)
	_, cmd := m.Update(key('a'))
	if cmd != nil {
		_ = cmd()
	}
	select {
	case d := <-reply:
		if d != agent.DecisionAbort {
			t.Errorf("expected DecisionAbort, got %v", d)
		}
	default:
		t.Fatal("no decision sent on 'a'")
	}
}

func TestUpdateArrowKeysCycleSelectedOption(t *testing.T) {
	m := newTestModel()
	updated, _ := m.Update(ProposalRequestMsg{Proposal: &agent.Proposal{ID: "p"}, Reply: make(chan agent.Decision, 1)})
	m = updated.(*Model)

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(*Model)
	if m.modalSelectedIdx != 1 {
		t.Errorf("down did not advance: %d", m.modalSelectedIdx)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = updated.(*Model)
	if m.modalSelectedIdx != 0 {
		t.Errorf("up did not go back: %d", m.modalSelectedIdx)
	}
	// wrap around from -1 to 4
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = updated.(*Model)
	if m.modalSelectedIdx != 4 {
		t.Errorf("up did not wrap to 4: %d", m.modalSelectedIdx)
	}
}

func TestUpdateEnterAppliesHighlightedOption(t *testing.T) {
	m := newTestModel()
	reply := make(chan agent.Decision, 1)
	updated, _ := m.Update(ProposalRequestMsg{Proposal: &agent.Proposal{ID: "p"}, Reply: reply})
	m = updated.(*Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown}) // index = 1 (ApproveAll)
	m = updated.(*Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown}) // index = 2 (Reject)
	m = updated.(*Model)
	_, cmd := m.Update(enterKey())
	if cmd != nil {
		_ = cmd()
	}
	select {
	case d := <-reply:
		if d != agent.DecisionRejected {
			t.Errorf("enter on highlight=2 should reject, got %v", d)
		}
	default:
		t.Fatal("no decision on enter")
	}
}

// --- Ask user ---------------------------------------------------------------

func TestUpdateAskUserReplyWithNumber(t *testing.T) {
	m := newTestModel()
	reply := make(chan string, 1)
	updated, _ := m.Update(AskUserMsg{
		Question: "pick one",
		Options:  []string{"a", "b", "c"},
		Reply:    reply,
	})
	m = updated.(*Model)
	if m.mode != ModeAskUser {
		t.Errorf("not in ask mode: %v", m.mode)
	}
	_, cmd := m.Update(key('2'))
	if cmd != nil {
		_ = cmd()
	}
	select {
	case ans := <-reply:
		if ans != "b" {
			t.Errorf("expected 'b', got %q", ans)
		}
	default:
		t.Fatal("no answer sent on '2'")
	}
}

func TestUpdateAskUserEscCancels(t *testing.T) {
	m := newTestModel()
	reply := make(chan string, 1)
	updated, _ := m.Update(AskUserMsg{Question: "q", Options: []string{"a"}, Reply: reply})
	m = updated.(*Model)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd != nil {
		_ = cmd()
	}
	select {
	case ans := <-reply:
		if !strings.Contains(ans, "cancel") {
			t.Errorf("expected cancel message, got %q", ans)
		}
	default:
		t.Fatal("no answer on esc")
	}
}

// --- View rendering ---------------------------------------------------------

func TestViewMainRendersBothPanes(t *testing.T) {
	m := newTestModel()
	updated, _ := m.Update(LLMChunkMsg{Content: "hi from llm"})
	m = updated.(*Model)
	view := m.View()
	if !strings.Contains(view, "Chat") {
		t.Errorf("view missing Chat pane: %s", view)
	}
	if !strings.Contains(view, "Activity") {
		t.Errorf("view missing Activity pane: %s", view)
	}
	if !strings.Contains(view, "hi from llm") {
		t.Errorf("view missing streamed text: %s", view)
	}
}

func TestViewApproveModalShowsProposal(t *testing.T) {
	m := newTestModel()
	updated, _ := m.Update(ProposalRequestMsg{
		Proposal: &agent.Proposal{
			ID: "abcdefgh-1234", Tool: "run_ansible", Host: "web01",
			RiskLevel: "high", Rationale: "needs reboot",
		},
		Reply: make(chan agent.Decision, 1),
	})
	m = updated.(*Model)
	view := m.View()
	if !strings.Contains(view, "abcdefgh") { // first 8 chars
		t.Errorf("view missing proposal short id: %s", view)
	}
	if !strings.Contains(view, "run_ansible") {
		t.Errorf("view missing tool name: %s", view)
	}
	if !strings.Contains(view, "web01") {
		t.Errorf("view missing host: %s", view)
	}
	if !strings.Contains(view, "needs reboot") {
		t.Errorf("view missing rationale: %s", view)
	}
}

func TestViewStatusBarShowsCounters(t *testing.T) {
	m := newTestModel()
	updated, _ := m.Update(StatusUpdateMsg{Iter: 3, MaxIter: 20, ProposalCount: 2, CurrentTool: "read_file"})
	m = updated.(*Model)
	view := m.View()
	if !strings.Contains(view, "3/20") {
		t.Errorf("status bar missing iter: %s", view)
	}
	if !strings.Contains(view, "proposals 2") {
		t.Errorf("status bar missing proposals: %s", view)
	}
}

// --- TTY detection ----------------------------------------------------------

func TestIsSupportedReturnsBool(t *testing.T) {
	// Just ensure it doesn't panic and returns a bool.
	_ = IsSupported(0)          // invalid fd → false
	_ = IsSupported(uintptr(0)) // also fine
}

func TestHistoryModeNavigation(t *testing.T) {
	m := newTestModel()
	if m.mode != ModeRunning {
		t.Fatalf("expected initial mode running, got %v", m.mode)
	}

	// Press tab to switch to history mode
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = updated.(*Model)
	if m.mode != ModeHistory {
		t.Fatalf("expected ModeHistory after tab, got %v", m.mode)
	}

	// Mock some history runs
	m.historyRuns = []*store.Run{
		{ID: "run-1", Playbook: "pb1.yml", Status: "success"},
		{ID: "run-2", Playbook: "pb2.yml", Status: "failed"},
	}
	m.selectedRunIdx = 0

	// Press down arrow
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(*Model)
	if m.selectedRunIdx != 1 {
		t.Errorf("expected selectedRunIdx 1 after Down, got %d", m.selectedRunIdx)
	}

	// Press down arrow again (wraps to 0)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(*Model)
	if m.selectedRunIdx != 0 {
		t.Errorf("expected selectedRunIdx 0 after Down wrap, got %d", m.selectedRunIdx)
	}

	// Press up arrow (wraps to 1)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = updated.(*Model)
	if m.selectedRunIdx != 1 {
		t.Errorf("expected selectedRunIdx 1 after Up wrap, got %d", m.selectedRunIdx)
	}

	// Press esc to switch back to running mode
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(*Model)
	if m.mode != ModeRunning {
		t.Fatalf("expected ModeRunning after esc, got %v", m.mode)
	}
}
