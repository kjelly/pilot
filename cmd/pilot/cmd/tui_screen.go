// tui_screen.go defines the shared contract every router-embedded
// wizard screen satisfies, plus standaloneScreen, the wrapper one-shot
// (non-router) prompts use.
//
// Unlike a standalone `tea.NewProgram(...).Run()` invocation (the
// pattern the old per-screen promptui/bubbletea call sites used —
// e.g. today's promptRoleChecklist), router-embedded screens run
// inside one long-lived router Program (editRouterModel) — so
// pressing enter/esc on a screen must never return tea.Quit: that
// would end the whole wizard session, not just this one screen.
// Instead a screen marks itself Finished() and the router reads its
// result, then decides the next screen to show.
package cmd

import (
	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/tui"
)

// screen is the contract a router-embedded wizard screen satisfies in
// addition to tea.Model — currently just an alias-by-embedding for
// tui.Screen (Finished/Canceled/AutomationState), the Pilot-owned UI
// contract from internal/tui. r.current is always a Huh-backed screen
// built through a Factory in production (see editRouterModel.uiFactory
// and internal/tui/huh_factory.go); this interface carries no method
// of its own so any future widget provider stays swappable too.
type screen interface {
	tui.Screen
}

// standaloneScreen wraps a single `screen` in its own tea.Program,
// quitting once it reports Finished() — for one-shot prompts run
// outside any router (see deploy_tui.go's runSelectProgram/
// runTextProgram/runConfirmProgram). The screens themselves
// deliberately never call tea.Quit (see the package doc comment
// above) because pilot edit's router needs to keep its single
// continuous Program alive across screen transitions; a standalone
// prompt has no router to do that job, so this wrapper does it
// instead.
type standaloneScreen struct {
	s screen
}

func (h standaloneScreen) Init() tea.Cmd { return h.s.Init() }

func (h standaloneScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := h.s.Update(msg)
	h.s = next.(screen)
	if h.s.Finished() {
		return h, tea.Quit
	}
	return h, cmd
}

func (h standaloneScreen) View() tea.View { return h.s.View() }
