package cmd

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

// confirmModel is an embedded yes/no screen — the router-based
// replacement for promptConfirm. It matches promptConfirm's existing
// contract exactly: esc/ctrl+c (or any unrecognized key) resolves to
// "no" rather than propagating a wizard-level cancel — a yes/no
// question the user didn't answer defaults to the safest choice, it
// doesn't abort the whole wizard. See tui_screen.go for why it never
// calls tea.Quit; Canceled() always reports false here for the same
// reason (there is no separate "aborted" outcome for a confirm).
type confirmModel struct {
	question   string
	defaultYes bool
	answered   bool
	value      bool
}

func newConfirmModel(question string, defaultYes bool) confirmModel {
	return confirmModel{question: question, defaultYes: defaultYes}
}

func (m confirmModel) Init() tea.Cmd { return nil }

func (m confirmModel) Finished() bool { return m.answered }
func (m confirmModel) Canceled() bool { return false }

func (m confirmModel) automationScreenID() string { return "confirm" }

// Value is the yes/no answer — valid once Finished().
func (m confirmModel) Value() bool { return m.value }

func (m confirmModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch keyMsg.String() {
	case "y", "Y":
		m.value, m.answered = true, true
	case "n", "N":
		m.value, m.answered = false, true
	case "enter":
		m.value, m.answered = m.defaultYes, true
	case "esc", "ctrl+c":
		m.value, m.answered = false, true
	}
	return m, nil
}

func (m confirmModel) View() string {
	suffix := " [y/N]"
	if m.defaultYes {
		suffix = " [Y/n]"
	}
	return fmt.Sprintf("%s%s\n", m.question, suffix)
}
