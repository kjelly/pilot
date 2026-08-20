package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	huh "charm.land/huh/v2"
)

// huhInputScreen is the Huh v2-backed InputScreen implementation,
// including the secret (masked) variant.
//
// Esc is intercepted unconditionally here: an Input has no filter, and
// a bare Esc does not abort a Huh Form (measured — Form.State stays
// StateNormal through repeated Esc presses), so Huh would simply
// swallow it and Pilot's "esc cancels this screen" expectation would
// silently stop working.
//
// Trim semantics match the hand-written textInputModel: Huh itself does
// not trim (a typed "  hi  " stays "  hi  " in the bound value), so
// Value() trims on read and the validator Pilot installs sees the
// trimmed text — the same value the router will end up storing.
type huhInputScreen struct {
	huhFormBridge

	spec  InputSpec
	field *huh.Input
	value string

	confirmed bool
	canceled  bool
}

var _ InputScreen = (*huhInputScreen)(nil)

// NewHuhInput builds a Huh v2-backed single-line text entry screen.
// InputSpec.Secret selects password masking.
func NewHuhInput(spec InputSpec) InputScreen {
	s := &huhInputScreen{spec: spec, value: spec.Default}

	field := huh.NewInput().Title(spec.Title).Value(&s.value)
	if spec.Secret {
		field = field.EchoMode(huh.EchoModePassword)
	}
	if spec.Validate != nil {
		validate := spec.Validate
		field = field.Validate(func(v string) error {
			return validate(strings.TrimSpace(v))
		})
	}

	s.field = field
	s.form = newPilotForm(field)
	return s
}

func (s *huhInputScreen) Init() tea.Cmd { return s.form.Init() }

func (s *huhInputScreen) Finished() bool { return s.confirmed || s.canceled }
func (s *huhInputScreen) Canceled() bool { return s.canceled }

// Value is the entered text with leading/trailing whitespace discarded,
// so every edit-menu text field stores a clean value consistently.
func (s *huhInputScreen) Value() string { return strings.TrimSpace(s.value) }

func (s *huhInputScreen) validationError() string {
	if err := s.field.Error(); err != nil {
		return err.Error()
	}
	return ""
}

// AutomationState implements Screen. A secret's typed value never
// appears here (Core Invariant 6): Secret and HasValue are booleans,
// and the text itself is reachable only through Value() on the live
// screen, exactly like any other InputScreen.
func (s *huhInputScreen) AutomationState() AutomationState {
	return AutomationState{
		ScreenID:        screenIDOr(s.spec.ScreenID, "text-input"),
		Kind:            ScreenInput,
		Title:           s.spec.Title,
		Secret:          s.spec.Secret,
		HasValue:        s.Value() != "",
		ValidationError: s.validationError(),
		FocusedIndex:    -1,
	}
}

func (s *huhInputScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if s.Finished() {
		return s, nil
	}
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return s, s.update(msg)
	}

	switch huhKeyName(key) {
	case "ctrl+c", "esc":
		s.canceled = true
		return s, nil

	case "enter":
		// Forwarded so Huh runs the validator and renders its own error
		// line; the resulting field-advance command is swallowed so it
		// cannot leak into the next screen (see huhSelectScreen).
		_ = s.update(huhEnterKey)
		if s.field.Error() == nil {
			s.confirmed = true
		}
		// A rejected value keeps the screen open, unfinished, with the
		// message visible — the same re-prompt loop promptText had.
		return s, nil

	case "tab", "shift+tab":
		_ = s.update(key)
		return s, nil

	default:
		return s, s.update(key)
	}
}

func (s *huhInputScreen) View() tea.View { return s.view() }
