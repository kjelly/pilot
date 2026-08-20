package tui

import (
	tea "charm.land/bubbletea/v2"
	huh "charm.land/huh/v2"
)

// huhConfirmScreen is the Huh v2-backed ConfirmScreen implementation.
//
// It preserves confirmModel's existing contract exactly, which the
// migration spec calls out as deliberate rather than a defect to fix:
// Esc/Ctrl-C resolve to "No" (value=false, finished) instead of
// producing a separate cancel outcome, and Canceled() is therefore
// always false. A yes/no question the user did not answer takes the
// safest branch; it does not abort the surrounding wizard.
//
// Delivering that turned out to need no leak-prevention at all, only a
// direct intercept: a bare Esc never reaches Huh's Form-level abort in
// the first place (measured — Form.State stays StateNormal across
// repeated Esc presses, and only Ctrl-C sets StateAborted). So there is
// no StateAborted to map back to "No"; the adapter simply answers "No"
// itself and never forwards either key.
//
// The y / Y / n / N / Return bindings are Huh's own defaults and
// already match confirmModel: y-family sets true and submits, n-family
// sets false and submits, and Return submits whatever is currently
// selected (the spec default, unless the user moved the selection with
// Huh's ←/→ toggle).
type huhConfirmScreen struct {
	huhFormBridge

	spec  ConfirmSpec
	field *huh.Confirm
	value bool

	answered bool
}

var _ ConfirmScreen = (*huhConfirmScreen)(nil)

// NewHuhConfirm builds a Huh v2-backed yes/no screen.
func NewHuhConfirm(spec ConfirmSpec) ConfirmScreen {
	s := &huhConfirmScreen{spec: spec, value: spec.Default}
	s.field = huh.NewConfirm().Title(spec.Title).Value(&s.value)
	s.form = newPilotForm(s.field)
	return s
}

func (s *huhConfirmScreen) Init() tea.Cmd { return s.form.Init() }

func (s *huhConfirmScreen) Finished() bool { return s.answered }

// Canceled always reports false: a confirm has no cancel outcome
// distinct from answering "No".
func (s *huhConfirmScreen) Canceled() bool { return false }

// Value is the yes/no answer — valid once Finished().
func (s *huhConfirmScreen) Value() bool { return s.value }

// AutomationState implements Screen.
func (s *huhConfirmScreen) AutomationState() AutomationState {
	return AutomationState{
		ScreenID:     screenIDOr(s.spec.ScreenID, "confirm"),
		Kind:         ScreenConfirm,
		Title:        s.spec.Title,
		FocusedIndex: -1,
	}
}

func (s *huhConfirmScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if s.answered {
		return s, nil
	}
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return s, s.update(msg)
	}

	switch huhKeyName(key) {
	case "esc", "ctrl+c":
		s.value, s.answered = false, true
		return s, nil

	case "y", "Y", "n", "N":
		// Huh's Accept/Reject bindings set the bound value; its
		// field-advance command is swallowed so it cannot complete the
		// next screen's Form (see huhSelectScreen).
		_ = s.update(key)
		s.answered = true
		return s, nil

	case "enter":
		_ = s.update(huhEnterKey)
		s.answered = true
		return s, nil

	case "tab", "shift+tab":
		_ = s.update(key)
		return s, nil

	default:
		// Any other key is inert, matching confirmModel: only an
		// explicit answer finishes this screen.
		return s, s.update(key)
	}
}

func (s *huhConfirmScreen) View() tea.View { return s.view() }
