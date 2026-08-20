// L1 unit tests for the editRouterModel core (transitionTo, banner
// handling, cancel/quit/err propagation) — see edit_tui_flows_test.go
// for L3 teatest coverage of full wizard flows through real screens.
package cmd

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/tui"
)

// newTestSelect is this file's stand-in for the pre-Phase-5 newSelectModel:
// a bare, unnamed-screen-ID select built straight off the production
// factory, for router-mechanics tests that don't care which widget
// provider backs the screen.
func newTestSelect(title string, labels ...string) screen {
	choices := make([]tui.Choice, len(labels))
	for i, l := range labels {
		choices[i] = tui.Choice{Label: l}
	}
	return tui.NewHuhFactory().Select(tui.SelectSpec{Title: title, Choices: choices})
}

func newTestConfirm(question string, defaultYes bool) screen {
	return tui.NewHuhFactory().Confirm(tui.ConfirmSpec{Title: question, Default: defaultYes})
}

func TestEditRouter_TransitionTo_ReplacesCurrentScreen(t *testing.T) {
	var r editRouterModel
	r.transitionTo(newTestSelect("first", "a"), "", func(r *editRouterModel, s screen) tea.Cmd {
		return r.transitionTo(newTestSelect("second", "b"), "", nil)
	})

	nm, _ := r.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	r2 := nm.(editRouterModel)
	if !strings.Contains(viewContent(r2.View()), "second") {
		t.Fatalf("expected router to transition to the second screen, got view:\n%s", viewContent(r2.View()))
	}
	if strings.Contains(viewContent(r2.View()), "first") {
		t.Fatalf("expected the first screen to be gone, got view:\n%s", viewContent(r2.View()))
	}
}

func TestEditRouter_BannerShownThenClearedByNextTransition(t *testing.T) {
	var r editRouterModel
	r.transitionTo(newTestConfirm("q", true), "hello banner", func(r *editRouterModel, s screen) tea.Cmd {
		return r.transitionTo(newTestConfirm("q2", true), "", nil)
	})
	if !strings.Contains(viewContent(r.View()), "hello banner") {
		t.Fatalf("expected banner in view, got:\n%s", viewContent(r.View()))
	}

	nm, _ := r.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	r2 := nm.(editRouterModel)
	if strings.Contains(viewContent(r2.View()), "hello banner") {
		t.Fatalf("expected banner to be cleared by the next transition, got:\n%s", viewContent(r2.View()))
	}
}

func TestEditRouter_CancelDefaultsToQuit(t *testing.T) {
	var r editRouterModel
	r.transitionTo(newTestSelect("t", "a"), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return quitWizard(r)
		}
		return nil
	})

	nm, cmd := r.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	r2 := nm.(editRouterModel)
	if !r2.quit {
		t.Fatal("expected esc (the default cancel handler) to set quit")
	}
	if cmd == nil {
		t.Fatal("expected a tea.Quit cmd once quit is set")
	}
}

func TestEditRouter_ErrForcesQuit(t *testing.T) {
	var r editRouterModel
	r.transitionTo(newTestConfirm("q", true), "", func(r *editRouterModel, s screen) tea.Cmd {
		r.err = fmt.Errorf("boom")
		return nil
	})

	nm, cmd := r.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	r2 := nm.(editRouterModel)
	if r2.err == nil {
		t.Fatal("expected err to propagate onto the router")
	}
	if cmd == nil {
		t.Fatal("expected a tea.Quit cmd once err is set")
	}
}

func TestEditRouter_NoCurrentScreenQuits(t *testing.T) {
	var r editRouterModel
	_, cmd := r.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("expected a tea.Quit cmd when there is no current screen")
	}
}

func TestEditRouter_UnfinishedScreenDoesNotInvokeCallback(t *testing.T) {
	invoked := false
	var r editRouterModel
	r.transitionTo(newTestSelect("t", "a", "b"), "", func(r *editRouterModel, s screen) tea.Cmd {
		invoked = true
		return nil
	})

	nm, _ := r.Update(tea.KeyPressMsg{Code: tea.KeyDown}) // moves cursor, does not finish the screen
	r2 := nm.(editRouterModel)
	if invoked {
		t.Fatal("callback should not run until the screen reports Finished()")
	}
	if !strings.Contains(viewContent(r2.View()), "t") {
		t.Fatalf("expected the same screen still showing, got:\n%s", viewContent(r2.View()))
	}
}
