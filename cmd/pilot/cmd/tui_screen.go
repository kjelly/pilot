// tui_screen.go defines the shared contract every embedded wizard
// screen (selectModel, multiSelectModel, textInputModel, confirmModel)
// satisfies, plus the list-window scrolling math selectModel and
// multiSelectModel both need.
//
// Unlike a standalone `tea.NewProgram(...).Run()` invocation (the
// pattern the old per-screen promptui/bubbletea call sites used —
// e.g. today's promptRoleChecklist), these screens run embedded
// inside one long-lived router Program (editRouterModel /
// deployWizardModel) — so pressing enter/esc on a screen must never
// return tea.Quit: that would end the whole wizard session, not just
// this one screen. Instead a screen marks itself Finished() and the
// router reads its result, then decides the next screen to show.
package cmd

import tea "github.com/charmbracelet/bubbletea"

// screen is the contract a router-embedded wizard screen satisfies in
// addition to tea.Model.
type screen interface {
	tea.Model
	// Finished reports whether the user has confirmed or canceled this
	// screen. The router should stop forwarding messages to it and
	// read its result instead once this is true.
	Finished() bool
	// Canceled reports whether the screen finished via esc/ctrl+c
	// rather than a genuine confirm (enter). The router maps this to
	// the shared errDeployAborted sentinel.
	Canceled() bool
	// automationScreenID identifies the primitive screen type for the
	// semantic automation driver without changing the rendered UI.
	automationScreenID() string
}

// listChromeLines is how many lines a scrollable list screen
// (selectModel, multiSelectModel) spends on title, help text, and the
// two always-reserved scroll-indicator rows — subtracted from
// terminal height to size the visible item window.
const listChromeLines = 6

// listVisibleRows is how many item rows fit on screen at once. Before
// the terminal size is known (height == 0, i.e. no WindowSizeMsg yet)
// it falls back to a reasonable default rather than aggressively
// clamping to a tiny window on the first frame.
func listVisibleRows(itemCount, height int) int {
	if height == 0 {
		return min(itemCount, 15)
	}
	return min(itemCount, max(height-listChromeLines, 3))
}

// standaloneScreen wraps a single `screen` in its own tea.Program,
// quitting once it reports Finished() — for one-shot prompts run
// outside any router (see deploy_tui.go's runSelectProgram/
// runTextProgram/runConfirmProgram). The screen primitives themselves
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

func (h standaloneScreen) View() string { return h.s.View() }

// listClampWindow returns a new windowStart that keeps cursor inside
// [windowStart, windowStart+rows) and windowStart itself inside a
// valid range — call after every cursor move or resize so scrolling
// follows the cursor instead of leaving it to run off either edge of
// the visible window.
func listClampWindow(cursor, windowStart, itemCount, height int) int {
	rows := listVisibleRows(itemCount, height)
	if cursor < windowStart {
		windowStart = cursor
	}
	if cursor >= windowStart+rows {
		windowStart = cursor - rows + 1
	}
	windowStart = min(windowStart, max(itemCount-rows, 0))
	windowStart = max(windowStart, 0)
	return windowStart
}
