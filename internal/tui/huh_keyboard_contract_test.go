package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

// TestAllHuhScreenFamiliesKeyboardContract is the Huh-backed counterpart
// of cmd/pilot/cmd's former TestAllEmbeddedScreenFamiliesKeyboardContract
// (removed in Phase 5 of the TUI v2 + Huh migration along with the
// hand-written primitives it exercised) — the keyboard regression gate for
// every pilot edit/deploy screen, now that all of them are Huh-backed in
// production. Routers only compose these screen kinds, so a
// terminal-specific control-code regression (Return arriving as Ctrl-J,
// Esc arriving as Ctrl-[ or a raw rune) is caught here once, regardless of
// which menu or roster field exposes that screen. See Core Invariant 3 and
// the migration spec's "Keyboard Migration" / "Return / Ctrl-J
// Compatibility" requirements.
func TestAllHuhScreenFamiliesKeyboardContract(t *testing.T) {
	type screenCase struct {
		name       string
		newScreen  func() Screen
		wantCancel bool
	}

	screens := []screenCase{
		{
			name:       "select",
			newScreen:  func() Screen { return NewHuhSelect(fruitSpec()) },
			wantCancel: true,
		},
		{
			name:       "multi select",
			newScreen:  func() Screen { return NewHuhMultiSelect(rolesSpec()) },
			wantCancel: true,
		},
		{
			name:       "input",
			newScreen:  func() Screen { return NewHuhInput(InputSpec{Title: "text", Default: "value"}) },
			wantCancel: true,
		},
		{
			name:       "secret input",
			newScreen:  func() Screen { return NewHuhInput(InputSpec{Title: "secret", Default: "value", Secret: true}) },
			wantCancel: true,
		},
		{
			name:       "confirm",
			newScreen:  func() Screen { return NewHuhConfirm(ConfirmSpec{Title: "confirm", Default: true}) },
			wantCancel: false, // Confirm maps cancel to its safe "no" answer.
		},
	}

	completeKeys := []struct {
		name string
		msg  tea.KeyPressMsg
	}{
		{name: "named enter", msg: tea.KeyPressMsg{Code: tea.KeyEnter}},
		{name: "LF ctrl+j", msg: tea.KeyPressMsg{Code: 'j', Mod: tea.ModCtrl}},
		{name: "raw CR rune", msg: tea.KeyPressMsg{Code: '\r', Text: "\r"}},
		{name: "raw LF rune", msg: tea.KeyPressMsg{Code: '\n', Text: "\n"}},
	}
	cancelKeys := []struct {
		name string
		msg  tea.KeyPressMsg
	}{
		{name: "named escape", msg: tea.KeyPressMsg{Code: tea.KeyEsc}},
		{name: "ctrl bracket", msg: tea.KeyPressMsg{Code: '[', Mod: tea.ModCtrl}},
		{name: "raw escape rune", msg: tea.KeyPressMsg{Code: 27, Text: "\x1b"}},
		{name: "ctrl+c", msg: tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}},
	}

	for _, family := range screens {
		for _, key := range completeKeys {
			t.Run(family.name+"/complete/"+key.name, func(t *testing.T) {
				s := family.newScreen()
				send(t, s, key.msg)
				if !s.Finished() || s.Canceled() {
					t.Fatalf("%s did not complete cleanly: finished=%t canceled=%t", key.name, s.Finished(), s.Canceled())
				}
			})
		}
		for _, key := range cancelKeys {
			t.Run(family.name+"/cancel/"+key.name, func(t *testing.T) {
				s := family.newScreen()
				send(t, s, key.msg)
				if !s.Finished() {
					t.Fatalf("%s did not finish", key.name)
				}
				if s.Canceled() != family.wantCancel {
					t.Fatalf("%s canceled=%t, want %t", key.name, s.Canceled(), family.wantCancel)
				}
			})
		}
	}
}
