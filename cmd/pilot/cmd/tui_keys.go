// tui_keys.go is Pilot's canonical key layer — see the migration spec's
// "Keyboard Migration" requirements. It exists so business/automation code
// (mainly edit_automation_driver.go/edit_automation_driver_presets.go/
// prompt_automation.go) builds a synthesized keypress through a handful of
// named constructors instead of scattering raw tea.KeyPressMsg{...} struct
// literals through those files. tuiKeyName (tui_screen.go) is this layer's
// reverse direction: tea.KeyPressMsg -> canonical key name.
package cmd

import tea "charm.land/bubbletea/v2"

func keyUp() tea.KeyPressMsg    { return tea.KeyPressMsg{Code: tea.KeyUp} }
func keyDown() tea.KeyPressMsg  { return tea.KeyPressMsg{Code: tea.KeyDown} }
func keyEnter() tea.KeyPressMsg { return tea.KeyPressMsg{Code: tea.KeyEnter} }
func keyEsc() tea.KeyPressMsg   { return tea.KeyPressMsg{Code: tea.KeyEsc} }
func keySpace() tea.KeyPressMsg { return tea.KeyPressMsg{Code: tea.KeySpace} }
func keyCtrlU() tea.KeyPressMsg { return tea.KeyPressMsg{Code: 'u', Mod: tea.ModCtrl} }

// keyRuneMsg builds the tea.KeyPressMsg for a single typed rune (e.g.
// confirmYesNo's explicit "y"/"n" answer).
func keyRuneMsg(r rune) tea.KeyPressMsg {
	return tea.KeyPressMsg{Text: string(r), Code: r}
}

// keyTextMsg builds the tea.KeyPressMsg for a synthesized keystroke that
// types value's characters at once — the canonical replacement for the v1
// tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(value)} literal these driver
// files used to construct directly. Bubbles v2's textinput.Model.Update
// reads the whole Text field in a single Update call (confirmed empirically
// against the real charm.land/bubbles/v2/textinput package — see this
// migration's commit message), so one message here is equivalent to v1's
// single multi-rune KeyMsg.
func keyTextMsg(value string) tea.KeyPressMsg {
	runes := []rune(value)
	var code rune
	if len(runes) > 0 {
		code = runes[0]
	}
	return tea.KeyPressMsg{Text: value, Code: code}
}
