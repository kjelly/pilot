package cmd

import (
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"
)

func TestConfirmModel_YKeyAnswersYesRegardlessOfDefault(t *testing.T) {
	m := newConfirmModel("q", false)
	next, _ := m.Update(tea.KeyPressMsg{Text: "y", Code: 'y'})
	m = next.(confirmModel)
	if !m.Finished() || !m.Value() {
		t.Fatalf("expected finished+true after 'y', got finished=%v value=%v", m.Finished(), m.Value())
	}
}

func TestConfirmModel_NKeyAnswersNoRegardlessOfDefault(t *testing.T) {
	m := newConfirmModel("q", true)
	next, _ := m.Update(tea.KeyPressMsg{Text: "n", Code: 'n'})
	m = next.(confirmModel)
	if !m.Finished() || m.Value() {
		t.Fatalf("expected finished+false after 'n', got finished=%v value=%v", m.Finished(), m.Value())
	}
}

func TestConfirmModel_EnterUsesDefault(t *testing.T) {
	m := newConfirmModel("q", true)
	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(confirmModel)
	if !m.Finished() || !m.Value() {
		t.Fatal("expected enter to answer the default (true)")
	}

	m2 := newConfirmModel("q", false)
	next2, _ := m2.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m2 = next2.(confirmModel)
	if !m2.Finished() || m2.Value() {
		t.Fatal("expected enter to answer the default (false)")
	}
}

func TestConfirmModel_LFEnterUsesDefault(t *testing.T) {
	m := newConfirmModel("q", true)
	next, _ := m.Update(tea.KeyPressMsg{Code: 'j', Mod: tea.ModCtrl})
	m = next.(confirmModel)
	if !m.Finished() || !m.Value() {
		t.Fatal("expected LF/ctrl+j Return to answer the default")
	}
}

// TestConfirmModel_EscResolvesToNoNotAbort matches promptConfirm's
// existing contract: a cancel on a yes/no question resolves to the
// safe "no" answer, it does not propagate as a wizard-level abort —
// Canceled() must stay false so the router doesn't confuse this with
// errDeployAborted.
func TestConfirmModel_EscResolvesToNoNotAbort(t *testing.T) {
	m := newConfirmModel("q", true)
	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(confirmModel)
	if !m.Finished() || m.Value() {
		t.Fatal("expected esc to resolve to a finished 'no' answer")
	}
	if m.Canceled() {
		t.Fatal("confirmModel must never report Canceled() — cancel maps to 'no', not an abort")
	}
}

func TestConfirmModel_UnrecognizedKeyDoesNotFinish(t *testing.T) {
	m := newConfirmModel("q", true)
	next, _ := m.Update(tea.KeyPressMsg{Text: "x", Code: 'x'})
	m = next.(confirmModel)
	if m.Finished() {
		t.Fatal("unrecognized key should not finish the screen")
	}
}

func TestConfirmModel_ViewShowsDefaultHint(t *testing.T) {
	yes := newConfirmModel("要繼續嗎？", true)
	if !strings.Contains(viewContent(yes.View()), "[Y/n]") {
		t.Fatalf("expected [Y/n] hint for defaultYes, got:\n%s", viewContent(yes.View()))
	}
	no := newConfirmModel("要繼續嗎？", false)
	if !strings.Contains(viewContent(no.View()), "[y/N]") {
		t.Fatalf("expected [y/N] hint for !defaultYes, got:\n%s", viewContent(no.View()))
	}
}

func TestConfirmModel_ScreenIDFallsBackWhenUnset(t *testing.T) {
	m := newConfirmModel("q", false)
	if got := m.automationScreenID(); got != "confirm" {
		t.Fatalf("automationScreenID() = %q, want legacy fallback %q", got, "confirm")
	}
}

func TestConfirmModel_ScreenIDUsesExplicitID(t *testing.T) {
	m := newConfirmModelWithScreenID("confirm.discard", "q", false)
	if got := m.automationScreenID(); got != "confirm.discard" {
		t.Fatalf("automationScreenID() = %q, want %q", got, "confirm.discard")
	}
}

func TestConfirmModel_Teatest_HappyPath(t *testing.T) {
	m := screenTestHarness{s: newConfirmModel("q", false)}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))
	tm.Type("y")

	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	got := final.(screenTestHarness).s.(confirmModel)
	if !got.Value() {
		t.Fatal("expected 'y' to answer true")
	}
}
