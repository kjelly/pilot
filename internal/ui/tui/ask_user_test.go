package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/anomalyco/pilot/internal/agent"
)

func TestAskUserFreeTextAccumulates(t *testing.T) {
	m := newModel(nil)
	m.width = 120
	m.height = 40
	m.mode = ModeAskUser
	m.askingQuestion = "Describe the error"
	m.askingOptions = nil
	m.askingReply = make(chan string, 1)
	// New question resets the buffer.
	updated, _ := m.Update(AskUserMsg{
		Question: "Describe the error",
		Reply:    m.askingReply,
	})
	m = updated.(*Model)
	if len(m.askingBuffer) != 0 {
		t.Fatalf("fresh AskUserMsg should reset buffer, got %v", m.askingBuffer)
	}

	// Type "hello".
	for _, r := range "hello" {
		updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = updated.(*Model)
	}
	if string(m.askingBuffer) != "hello" {
		t.Fatalf("after typing 'hello', buffer = %q, want %q", string(m.askingBuffer), "hello")
	}

	// Backspace once → "hell".
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	m = updated.(*Model)
	if string(m.askingBuffer) != "hell" {
		t.Fatalf("after backspace, buffer = %q, want %q", string(m.askingBuffer), "hell")
	}

	// ENTER submits the buffer. Update returns (model, tea.Cmd);
	// invoke the cmd so its side-effect (the channel send) actually
	// happens in the test.
	// Capture reply channel BEFORE Update because sendAnswer nil's
	// the model's field after sending (the captured closure still has
	// the channel and writes to it).
	reply := m.askingReply
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		cmd()
	}
	_ = updated
	select {
	case got := <-reply:
		if got != "hell" {
			t.Errorf("ENTER submitted %q, want %q", got, "hell")
		}
	default:
		t.Fatal("ENTER should have submitted an answer")
	}
}

func TestAskUserNumberedOptionStillWorks(t *testing.T) {
	m := newModel(nil)
	m.width = 120
	m.height = 40
	m.mode = ModeAskUser
	m.askingQuestion = "Pick one"
	m.askingOptions = []string{"yes", "no", "maybe"}
	m.askingReply = make(chan string, 1)

	// Press '2' → "no".
	reply := m.askingReply
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	if cmd != nil {
		cmd()
	}
	_ = updated
	select {
	case got := <-reply:
		if got != "no" {
			t.Errorf("'2' should submit %q, got %q", "no", got)
		}
	default:
		t.Fatal("numbered option should submit immediately")
	}
}


func TestAskUserEscCancels(t *testing.T) {
	m := newModel(nil)
	m.width = 120
	m.height = 40
	m.mode = ModeAskUser
	m.askingQuestion = "Q?"
	m.askingReply = make(chan string, 1)

	reply := m.askingReply
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd != nil {
		cmd()
	}
	_ = updated
	select {
	case got := <-reply:
		if got != "(cancelled)" {
			t.Errorf("ESC should submit %q, got %q", "(cancelled)", got)
		}
	default:
		t.Fatal("ESC should have submitted")
	}
}


func TestAskUserOptionsEnterPicksFirst(t *testing.T) {
	m := newModel(nil)
	m.width = 120
	m.height = 40
	m.mode = ModeAskUser
	m.askingQuestion = "Pick one"
	m.askingOptions = []string{"yes", "no"}
	m.askingReply = make(chan string, 1)

	reply := m.askingReply
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		cmd()
	}
	_ = updated
	select {
	case got := <-reply:
		if got != "yes" {
			t.Errorf("ENTER with options should pick first, got %q", got)
		}
	default:
		t.Fatal("ENTER should submit")
	}
}


// Ensure agent.Proposal import is used (linter sometimes flags unused).
var _ = agent.Proposal{}
