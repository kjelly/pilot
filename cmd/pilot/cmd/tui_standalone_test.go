// TestStandaloneScreen_QuitsOnceFinished guards against regressing a
// real bug found via a PTY test: runSelectProgram/runTextProgram/
// runConfirmProgram (deploy_tui.go) run a bare screen directly under
// tea.NewProgram without wrapping it in standaloneScreen, the Program
// never quits — no screen this router composes calls tea.Quit itself
// (see tui_screen.go's doc comment), so nothing ever ends the Program
// once the user finishes the prompt. This is a fast, non-PTY regression
// test for that specific mechanism, using a Huh-backed select screen as
// its fixture (Phase 5 of the TUI v2 + Huh migration removed the
// hand-written primitives this test originally used).
package cmd

import (
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/kjelly/pilot/internal/tui"
)

func newTestSelectScreen() tui.SelectScreen {
	return tui.NewHuhFactory().Select(tui.SelectSpec{
		Title:   "t",
		Choices: []tui.Choice{{ID: "a", Label: "a"}, {ID: "b", Label: "b"}},
	})
}

func TestStandaloneScreen_QuitsOnceFinished(t *testing.T) {
	m := standaloneScreen{s: newTestSelectScreen()}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})

	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
}

func TestStandaloneScreen_UnfinishedScreenDoesNotQuit(t *testing.T) {
	m := standaloneScreen{s: newTestSelectScreen()}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown}) // moves cursor, does not finish
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})

	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
	got := tm.FinalModel(t).(standaloneScreen).s.(tui.SelectScreen)
	if got.Selected() != 1 {
		t.Fatalf("Selected() = %d, want 1 (the down-then-enter choice, proving the down keypress wasn't lost to a premature quit)", got.Selected())
	}
}
