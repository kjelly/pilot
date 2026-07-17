package cmd

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

func TestTextInputModel_PrefillsDefaultValue(t *testing.T) {
	m := newTextInputModel("label", "10.0.0.1", nil)
	if m.Value() != "10.0.0.1" {
		t.Fatalf("Value() = %q, want the prefilled default", m.Value())
	}
}

func TestTextInputModel_TypingReplacesRatherThanAppending(t *testing.T) {
	// promptText's promptui.Prompt{AllowEdit:true} pre-fills the current
	// value with the cursor at the end, so naive typing appends — a
	// documented gotcha for scripted/trec-driven input (see
	// .agents/skills/pilot-trec-verification/SKILL.md). bubbles/
	// textinput does the same (cursor at end after SetValue+CursorEnd)
	// by design — a caller that wants a clean field clears it first
	// (e.g. ctrl+u) rather than this model silently clearing on focus,
	// matching promptText's own behavior exactly.
	m := newTextInputModel("label", "old", nil)
	for _, r := range "new" {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = next.(textInputModel)
	}
	if m.Value() != "oldnew" {
		t.Fatalf("Value() = %q, want %q (append, matching promptText's existing AllowEdit behavior)", m.Value(), "oldnew")
	}
}

func TestTextInputModel_EnterConfirmsWhenValid(t *testing.T) {
	m := newTextInputModel("label", "hello", nil)
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(textInputModel)
	if !m.Finished() || m.Canceled() {
		t.Fatal("expected finished+not-canceled after enter with no validator")
	}
	if m.Value() != "hello" {
		t.Fatalf("Value() = %q, want %q", m.Value(), "hello")
	}
}

func TestTextInputModel_EnterBlockedByFailingValidator(t *testing.T) {
	validate := func(s string) error {
		if s == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}
	m := newTextInputModel("label", "", validate)
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(textInputModel)
	if m.Finished() {
		t.Fatal("expected enter to be blocked when validate fails")
	}
	if !strings.Contains(m.View(), "不能留空") {
		t.Fatalf("expected validation error in view, got:\n%s", m.View())
	}
}

func TestTextInputModel_EnterSucceedsAfterFixingValidationError(t *testing.T) {
	validate := func(s string) error {
		if s == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}
	m := newTextInputModel("label", "", validate)
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(textInputModel)
	if m.Finished() {
		t.Fatal("expected first enter (empty value) to be blocked")
	}
	for _, r := range "x" {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = next.(textInputModel)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(textInputModel)
	if !m.Finished() || m.Canceled() {
		t.Fatal("expected enter to succeed once the value is non-empty")
	}
}

func TestTextInputModel_EscCancels(t *testing.T) {
	m := newTextInputModel("label", "x", nil)
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(textInputModel)
	if !m.Finished() || !m.Canceled() {
		t.Fatal("expected finished+canceled after esc")
	}
}

func TestTextInputModel_ViewShowsLabel(t *testing.T) {
	m := newTextInputModel("SSH key 路徑", "", nil)
	if !strings.Contains(m.View(), "SSH key 路徑") {
		t.Fatalf("expected label in view, got:\n%s", m.View())
	}
}

func TestTextInputModel_Teatest_HappyPath(t *testing.T) {
	m := screenTestHarness{s: newTextInputModel("label", "", nil)}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))
	tm.Type("hello")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	got := final.(screenTestHarness).s.(textInputModel)
	if got.Canceled() {
		t.Fatal("enter should not cancel")
	}
	if got.Value() != "hello" {
		t.Fatalf("Value() = %q, want %q", got.Value(), "hello")
	}
}

func TestTextInputModel_Teatest_EscCancels(t *testing.T) {
	m := screenTestHarness{s: newTextInputModel("label", "x", nil)}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	if !final.(screenTestHarness).s.(textInputModel).Canceled() {
		t.Fatal("expected canceled after esc")
	}
}
