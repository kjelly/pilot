package cmd

import (
	"fmt"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// textInputModel is an embedded single-line text entry screen — the
// router-based replacement for promptText. It wraps
// github.com/charmbracelet/bubbles/textinput rather than hand-rolling
// cursor/unicode/backspace handling, which promptui got for free from
// chzyer/readline. See tui_screen.go for why it never calls tea.Quit.
type textInputModel struct {
	label     string
	validate  func(string) error
	input     textinput.Model
	err       string
	confirmed bool
	canceled  bool
}

// newTextInputModel builds a textInputModel pre-filled with def. Like
// promptText, it re-prompts (stays not Finished()) until validate
// passes or the user cancels; validate may be nil (no validation,
// matching promptText's nil-validator callers).
func newTextInputModel(label, def string, validate func(string) error) textInputModel {
	ti := textinput.New()
	ti.SetValue(def)
	ti.CursorEnd()
	// Focus here, not in Init(): tea.Model.Init() only returns a
	// tea.Cmd, it can't return an updated model, so any state Focus()
	// sets on ti would be discarded the moment Init() returned if
	// called there instead of before the value is stored on the model.
	ti.Focus()
	return textInputModel{label: label, validate: validate, input: ti}
}

func (m textInputModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m textInputModel) Finished() bool { return m.confirmed || m.canceled }
func (m textInputModel) Canceled() bool { return m.canceled }

func (m textInputModel) automationScreenID() string { return "text-input" }

func (m textInputModel) automationLabel() string { return m.label }

// Value is the entered text — valid once Finished() && !Canceled().
func (m textInputModel) Value() string { return m.input.Value() }

func (m textInputModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "enter":
			v := m.input.Value()
			if m.validate != nil {
				if err := m.validate(v); err != nil {
					m.err = err.Error()
					return m, nil
				}
			}
			m.err = ""
			m.confirmed = true
			return m, nil
		case "esc", "ctrl+c":
			m.canceled = true
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m textInputModel) View() string {
	s := fmt.Sprintf("%s\n%s\n", m.label, m.input.View())
	if m.err != "" {
		s += "⚠ " + m.err + "\n"
	}
	return s
}
