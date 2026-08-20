package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

// Canonical key presses for the adapter tests, constructed exactly the
// way cmd/pilot/cmd's post-Bubble-Tea-v2 tests construct theirs.
var (
	keyEnter    = tea.KeyPressMsg{Code: tea.KeyEnter}
	keyEsc      = tea.KeyPressMsg{Code: tea.KeyEsc}
	keyUp       = tea.KeyPressMsg{Code: tea.KeyUp}
	keyDown     = tea.KeyPressMsg{Code: tea.KeyDown}
	keySpace    = tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
	keyBackspce = tea.KeyPressMsg{Code: tea.KeyBackspace}
	keyCtrlC    = tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}
	keySlash    = tea.KeyPressMsg{Code: '/', Text: "/"}
	keyTab      = tea.KeyPressMsg{Code: tea.KeyTab}
)

func runeKey(r rune) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: r, Text: string(r)}
}

// send delivers one message and asserts the adapter kept its identity —
// these screens are pointer models, so the router's
// `r.current = nm.(screen)` re-assignment must hand back the same
// instance rather than a copy that silently drops state.
func send(t *testing.T, s Screen, msg tea.Msg) tea.Cmd {
	t.Helper()
	m, cmd := s.Update(msg)
	if m != tea.Model(s) {
		t.Fatalf("Update returned a different model instance: got %T, want the same %T", m, s)
	}
	return cmd
}

func sendKeys(t *testing.T, s Screen, keys ...tea.KeyPressMsg) {
	t.Helper()
	for _, k := range keys {
		send(t, s, k)
	}
}

// typeText types each rune of text as its own key press, the way a
// terminal delivers it.
func typeText(t *testing.T, s Screen, text string) {
	t.Helper()
	for _, r := range text {
		send(t, s, runeKey(r))
	}
}

func itemIDs(st AutomationState) []string {
	out := make([]string, len(st.Items))
	for i, it := range st.Items {
		out[i] = it.ID
	}
	return out
}

func checkedIDsOf(st AutomationState) []string {
	var out []string
	for _, it := range st.Items {
		if it.Checked {
			out = append(out, it.ID)
		}
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fruitSpec() SelectSpec {
	return SelectSpec{
		ScreenID: "fruit.list",
		Title:    "Pick a fruit",
		Choices: []Choice{
			{ID: "a", Label: "Alpha"},
			{ID: "b", Label: "Beta"},
			{ID: "g", Label: "Gamma"},
		},
	}
}
