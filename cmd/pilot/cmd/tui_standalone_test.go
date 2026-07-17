// TestStandaloneScreen_QuitsOnceFinished guards against regressing a
// real bug found via a PTY test: runSelectProgram/runTextProgram/
// runConfirmProgram (deploy_tui.go) run a bare selectModel/
// textInputModel/confirmModel directly under tea.NewProgram without
// wrapping it in standaloneScreen, the Program never quits — the
// primitives deliberately never call tea.Quit themselves (see
// tui_screen.go's doc comment), so nothing ever ends the Program once
// the user finishes the prompt. This is a fast, non-PTY regression
// test for that specific mechanism.
package cmd

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

func TestStandaloneScreen_QuitsOnceFinished(t *testing.T) {
	m := standaloneScreen{s: newSelectModel("t", []string{"a", "b"})}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
}

func TestStandaloneScreen_UnfinishedScreenDoesNotQuit(t *testing.T) {
	m := standaloneScreen{s: newSelectModel("t", []string{"a", "b"})}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Send(tea.KeyMsg{Type: tea.KeyDown}) // moves cursor, does not finish
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
	got := tm.FinalModel(t).(standaloneScreen).s.(selectModel)
	if got.Selected() != 1 {
		t.Fatalf("Selected() = %d, want 1 (the down-then-enter choice, proving the down keypress wasn't lost to a premature quit)", got.Selected())
	}
}
