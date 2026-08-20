package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestHuhConfirmEnterTakesDefault(t *testing.T) {
	for _, def := range []bool{true, false} {
		s := NewHuhConfirm(ConfirmSpec{ScreenID: "deploy.apply", Title: "要套用嗎?", Default: def})
		s.Init()
		if s.Finished() {
			t.Fatalf("confirm finished before any key")
		}
		cmd := send(t, s, keyEnter)
		if !s.Finished() {
			t.Fatalf("default=%v: enter did not finish the screen", def)
		}
		if s.Canceled() {
			t.Fatalf("default=%v: Canceled()=true; a confirm has no cancel outcome", def)
		}
		if got := s.Value(); got != def {
			t.Fatalf("default=%v: Value=%v", def, got)
		}
		if cmd != nil {
			t.Fatalf("default=%v: enter returned a command", def)
		}
	}
}

func TestHuhConfirmChooseYesAndNo(t *testing.T) {
	for _, tc := range []struct {
		name string
		def  bool
		key  tea.KeyPressMsg
		want bool
	}{
		{"y-over-default-no", false, runeKey('y'), true},
		{"Y-over-default-no", false, runeKey('Y'), true},
		{"n-over-default-yes", true, runeKey('n'), false},
		{"N-over-default-yes", true, runeKey('N'), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewHuhConfirm(ConfirmSpec{Title: "確定?", Default: tc.def})
			s.Init()
			cmd := send(t, s, tc.key)
			if !s.Finished() {
				t.Fatalf("key did not finish the screen")
			}
			if s.Canceled() {
				t.Fatalf("Canceled()=true")
			}
			if got := s.Value(); got != tc.want {
				t.Fatalf("Value=%v want %v", got, tc.want)
			}
			if cmd != nil {
				t.Fatalf("answer key returned a command; huh's field-advance cascade must be swallowed")
			}
		})
	}
}

// Esc and Ctrl-C resolve to "No" without inventing a Canceled outcome
// that confirmModel never had. This needed no leak-prevention: a bare
// Esc never reaches huh's Form-level abort at all (huh binds Quit to
// Ctrl-C only), so the adapter simply answers "No" itself.
func TestHuhConfirmEscAndCtrlCResolveToNo(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  tea.KeyPressMsg
	}{
		{"esc", keyEsc},
		{"ctrl+c", keyCtrlC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Default true, so "resolved to No" cannot be confused with
			// "took the default".
			s := NewHuhConfirm(ConfirmSpec{Title: "刪除?", Default: true})
			s.Init()
			cmd := send(t, s, tc.key)
			if !s.Finished() {
				t.Fatalf("%s did not finish the screen", tc.name)
			}
			if s.Canceled() {
				t.Fatalf("%s produced Canceled()=true; ConfirmScreen.Canceled must always be false", tc.name)
			}
			if s.Value() {
				t.Fatalf("%s resolved to yes; want no", tc.name)
			}
			if cmd != nil {
				t.Fatalf("%s returned a command", tc.name)
			}
		})
	}
}

func TestHuhConfirmUnrecognizedKeyIsInert(t *testing.T) {
	s := NewHuhConfirm(ConfirmSpec{Title: "確定?", Default: true})
	s.Init()
	sendKeys(t, s, runeKey('q'), runeKey('7'), keyUp, keyDown, keyTab)
	if s.Finished() {
		t.Fatalf("an unrecognized key answered the question")
	}
	send(t, s, keyEnter)
	if !s.Finished() || !s.Value() {
		t.Fatalf("finished=%v value=%v", s.Finished(), s.Value())
	}
}

func TestHuhConfirmAutomationState(t *testing.T) {
	s := NewHuhConfirm(ConfirmSpec{Title: "要套用嗎?", Default: true})
	s.Init()
	st := s.AutomationState()
	if st.ScreenID != "confirm" {
		t.Fatalf("ScreenID=%q want the generic fallback %q", st.ScreenID, "confirm")
	}
	if st.Kind != ScreenConfirm {
		t.Fatalf("Kind=%q", st.Kind)
	}
	if st.Title != "要套用嗎?" {
		t.Fatalf("Title=%q", st.Title)
	}
	if len(st.Items) != 0 || st.FocusedIndex != -1 {
		t.Fatalf("confirm reported list fields: %+v", st)
	}
	if st.Secret || st.HasValue || st.FilterActive || st.ValidationError != "" {
		t.Fatalf("confirm reported unrelated fields: %+v", st)
	}
}

func TestHuhConfirmFinishedScreenIgnoresFurtherKeys(t *testing.T) {
	s := NewHuhConfirm(ConfirmSpec{Title: "確定?", Default: true})
	s.Init()
	send(t, s, runeKey('y'))
	sendKeys(t, s, runeKey('n'), keyEsc, keyCtrlC)
	if !s.Value() {
		t.Fatalf("Value flipped after the screen finished")
	}
	if s.Canceled() {
		t.Fatalf("Canceled()=true")
	}
}

func TestHuhConfirmRendersQuestion(t *testing.T) {
	s := NewHuhConfirm(ConfirmSpec{Title: "要覆寫 hosts.yml 嗎?", Default: false})
	s.Init()
	if content := s.View().Content; content == "" {
		t.Fatalf("confirm rendered an empty view")
	}
}
