package cmd

import tea "github.com/charmbracelet/bubbletea"

// screenTestHarness wraps a single `screen` so it can be driven end to
// end through teatest, quitting once the screen reports Finished() —
// mirroring, in miniature, what the real router (editRouterModel /
// deployWizardModel, Phase 2/4) will do. The primitives themselves
// deliberately never call tea.Quit (see tui_screen.go), so exercising
// them through a real tea.Program at all requires some wrapper that
// owns the quit decision — this is that wrapper, kept test-only so it
// doesn't leak router policy into production code before the router
// exists.
type screenTestHarness struct {
	s screen
}

func (h screenTestHarness) Init() tea.Cmd { return h.s.Init() }

func (h screenTestHarness) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := h.s.Update(msg)
	h.s = next.(screen)
	if h.s.Finished() {
		return h, tea.Quit
	}
	return h, cmd
}

func (h screenTestHarness) View() string { return h.s.View() }
