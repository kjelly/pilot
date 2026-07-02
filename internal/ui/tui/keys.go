// Package tui: key bindings.
package tui

import "github.com/charmbracelet/bubbletea"

// Keymap holds the bindings used by the TUI. We keep them centralised so
// the help view can be generated from the same source.
type Keymap struct {
	// Global
	Quit    keyBinding
	Help    keyBinding
	Tab     keyBinding
	Toggle  keyBinding // toggle thinking visibility
	Refresh keyBinding

	// Approval modal
	Approve keyBinding
	Reject  keyBinding
	Details keyBinding
	Abort   keyBinding
	UpDown  keyBinding

	// Ask user
	Select keyBinding
	Cancel keyBinding
}

type keyBinding struct {
	Key   string
	Label string
}

var defaultKeymap = Keymap{
	Quit:    keyBinding{"ctrl+c", "quit"},
	Help:    keyBinding{"?", "help"},
	Tab:     keyBinding{"tab", "history"},
	Toggle:  keyBinding{"t", "thinking"},
	Refresh: keyBinding{"ctrl+l", "refresh"},

	Approve: keyBinding{"y", "approve"},
	Reject:  keyBinding{"n", "reject"},
	Details: keyBinding{"?", "details"},
	Abort:   keyBinding{"a", "abort"},
	UpDown:  keyBinding{"↑/↓", "navigate"},

	Select: keyBinding{"1-9/enter", "select"},
	Cancel: keyBinding{"esc", "cancel"},
}

// KeysFor returns a slice of bindings to render in the help bar for a
// particular mode.
func (k Keymap) KeysFor(mode string) []keyBinding {
	switch mode {
	case "main":
		return []keyBinding{k.Tab, k.Toggle, k.Help, k.Quit}
	case "history":
		return []keyBinding{keyBinding{"tab", "back"}, k.UpDown, keyBinding{"ctrl+r", "refresh"}, k.Quit}
	case "approve":
		return []keyBinding{k.Approve, k.Reject, k.Details, k.Abort, k.Quit}
	case "ask":
		return []keyBinding{k.Select, k.Cancel, k.Quit}
	}
	return []keyBinding{k.Quit}
}

// HelpLine formats a slice of bindings into "y approve · n reject · ? help".
func HelpLine(bindings []keyBinding) string {
	parts := make([]string, 0, len(bindings))
	for _, b := range bindings {
		parts = append(parts, b.Key+" "+b.Label)
	}
	return joinDots(parts)
}

func joinDots(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += " · " + p
	}
	return out
}

// isQuit returns true if the key is a quit key in any mode.
func isQuit(msg tea.KeyMsg) bool {
	return msg.Type == tea.KeyCtrlC
}

// keyMatches returns true if a tea.KeyMsg matches a string binding like
// "y", "?", "ctrl+c", "ctrl+r", "ctrl+l", "tab", "enter", "esc", "up", "down".
func keyMatches(msg tea.KeyMsg, binding string) bool {
	switch binding {
	case "ctrl+c":
		return msg.Type == tea.KeyCtrlC
	case "ctrl+r":
		return msg.Type == tea.KeyCtrlR
	case "ctrl+l":
		return msg.Type == tea.KeyCtrlL
	case "tab":
		return msg.Type == tea.KeyTab
	case "enter":
		return msg.Type == tea.KeyEnter
	case "esc":
		return msg.Type == tea.KeyEsc
	case "up":
		return msg.Type == tea.KeyUp
	case "down":
		return msg.Type == tea.KeyDown
	case "left":
		return msg.Type == tea.KeyLeft
	case "right":
		return msg.Type == tea.KeyRight
	case "?":
		return msg.Type == tea.KeyRunes && len(msg.Runes) == 1 && msg.Runes[0] == '?'
	}
	if len(binding) == 1 && msg.Type == tea.KeyRunes {
		for _, r := range msg.Runes {
			if string(r) == binding {
				return true
			}
		}
	}
	return false
}
