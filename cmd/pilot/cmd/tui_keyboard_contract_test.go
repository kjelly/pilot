package cmd

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

// TestAllEmbeddedScreenFamiliesKeyboardContract is the keyboard regression
// gate for every pilot edit/deploy page. Routers only compose these four
// screen families, so a terminal-specific control-code regression is caught
// here once, regardless of which menu or roster field exposes that screen.
func TestAllEmbeddedScreenFamiliesKeyboardContract(t *testing.T) {
	screens := []struct {
		name       string
		newScreen  func() screen
		wantCancel bool
	}{
		{
			name:       "single select",
			newScreen:  func() screen { return newSelectModel("select", []string{"one"}) },
			wantCancel: true,
		},
		{
			name: "multi select",
			newScreen: func() screen {
				return newMultiSelectModel("multi", []multiSelectItem{{Label: "one"}})
			},
			wantCancel: true,
		},
		{
			name:       "text input",
			newScreen:  func() screen { return newTextInputModel("text", "value", nil) },
			wantCancel: true,
		},
		{
			name:       "secret text input",
			newScreen:  func() screen { return newSecretTextInputModel("secret", "value", nil) },
			wantCancel: true,
		},
		{
			name:       "confirmation",
			newScreen:  func() screen { return newConfirmModel("confirm", true) },
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
				next, _ := family.newScreen().Update(key.msg)
				got := next.(screen)
				if !got.Finished() || got.Canceled() {
					t.Fatalf("%s did not complete cleanly: finished=%t canceled=%t", key.name, got.Finished(), got.Canceled())
				}
			})
		}
		for _, key := range cancelKeys {
			t.Run(family.name+"/cancel/"+key.name, func(t *testing.T) {
				next, _ := family.newScreen().Update(key.msg)
				got := next.(screen)
				if !got.Finished() {
					t.Fatalf("%s did not finish", key.name)
				}
				if got.Canceled() != family.wantCancel {
					t.Fatalf("%s canceled=%t, want %t", key.name, got.Canceled(), family.wantCancel)
				}
			})
		}
	}
}
