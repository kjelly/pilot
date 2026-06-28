package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/anomalyco/pilot/internal/agent"
)

// TestDetailsToggleOnApprovalModal verifies that pressing '?' while
// the approval modal is open flips modalExpanded.
func TestDetailsToggleOnApprovalModal(t *testing.T) {
	m := newModel(nil)
	m.width = 120
	m.height = 40
	m.mode = ModeApproving
	m.approving = &agent.Proposal{
		ID:        "test-id-123",
		Tool:      "read_file",
		RiskLevel: "low",
	}
	if m.modalExpanded {
		t.Fatal("freshly created model should not be expanded")
	}

	// Press '?' once → expanded.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	m2 := updated.(*Model)
	if !m2.modalExpanded {
		t.Fatal("first '?' press should toggle modalExpanded to true")
	}

	// Press '?' again → collapsed.
	updated, _ = m2.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	m3 := updated.(*Model)
	if m3.modalExpanded {
		t.Fatal("second '?' press should toggle back to false")
	}
}

// TestProposalRequestResetsExpansion ensures each new proposal starts
// in collapsed state — otherwise an expanded state would carry over
// from one approval to the next.
func TestProposalRequestResetsExpansion(t *testing.T) {
	m := newModel(nil)
	m.modalExpanded = true
	m.mode = ModeApproving

	updated, _ := m.Update(ProposalRequestMsg{
		Proposal: &agent.Proposal{ID: "new"},
		Reply:    make(chan agent.Decision, 1),
	})
	m2 := updated.(*Model)
	if m2.modalExpanded {
		t.Fatal("new ProposalRequestMsg must reset modalExpanded to false")
	}
}

// TestExpandedRenderingContainsFullArgs verifies the rendered view
// actually shows more content when expanded.
func TestExpandedRenderingContainsFullArgs(t *testing.T) {
	m := newModel(nil)
	m.width = 200
	m.height = 60
	m.mode = ModeApproving
	// Long args that would be truncated at 400 chars.
	longArgs := make([]byte, 800)
	for i := range longArgs {
		longArgs[i] = 'x'
	}
	m.approving = &agent.Proposal{
		ID:       "abc",
		Tool:     "run_ansible",
		Args:     longArgs,
		RiskLevel: "medium",
	}

	collapsed := m.View()
	if !m.modalExpanded {
		// default is collapsed
	}
	m.modalExpanded = true
	expanded := m.View()

	if collapsed == expanded {
		t.Fatal("expanded view should differ from collapsed view when args > 400 chars")
	}
	// Expanded view should contain at least some of the extra 'x'
	// characters that the truncated view would not.
	count := 0
	for _, c := range []byte(expanded) {
		if c == 'x' {
			count++
		}
	}
	if count < 500 {
		t.Errorf("expanded view should contain most of the 800-char args, got %d 'x'", count)
	}
}
