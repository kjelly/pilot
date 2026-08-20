package tui

import (
	tea "charm.land/bubbletea/v2"
	huh "charm.land/huh/v2"
)

// huhSelectScreen is the Huh v2-backed SelectScreen implementation.
//
// Cancel/submit semantics are Pilot's, not Huh's. Two measured facts
// about Huh v2.0.3 drive that split:
//
//  1. A bare Esc never aborts a Huh Form. Huh's default keymap binds
//     Quit to Ctrl-C only; Esc belongs entirely to the field's own
//     filter handling, so Form.State stays StateNormal no matter how
//     many times Esc is pressed. Pilot's screens have always treated
//     Esc as "cancel this screen", so the adapter intercepts Esc itself
//     whenever there is no filter left to clear, and never relies on
//     StateAborted appearing.
//
//  2. Submitting a Huh Form resolves through a command cascade
//     (nextFieldMsg -> nextGroupMsg -> StateCompleted). Those commands
//     must NOT be returned to Pilot's router: the router forwards every
//     message to whatever screen is current, so a cascade command
//     outliving this screen would be delivered to the *next* screen's
//     Form and complete it without the user touching anything. The
//     adapter therefore swallows the commands produced by field-advance
//     keys and decides "finished" synchronously, which also keeps
//     Finished() true on the very same Update that handled Return —
//     the contract editRouterModel already expects.
type huhSelectScreen struct {
	huhFormBridge

	spec   SelectSpec
	field  *huh.Select[choiceValue]
	filter huhListFilter
	value  choiceValue

	confirmed bool
	canceled  bool
}

var _ SelectScreen = (*huhSelectScreen)(nil)

// NewHuhSelect builds a Huh v2-backed single-choice list screen.
func NewHuhSelect(spec SelectSpec) SelectScreen {
	s := &huhSelectScreen{spec: spec}

	keys := make([]string, len(spec.Choices))
	for i, c := range spec.Choices {
		keys[i] = huhOptionKey(c.Label, c.Description)
	}
	keys = huhUniqueKeys(keys)
	s.filter.keys = keys

	options := make([]huh.Option[choiceValue], len(spec.Choices))
	for i, c := range spec.Choices {
		options[i] = huh.NewOption(keys[i], choiceValue{Index: i, ID: c.ID})
	}

	// Bind the initial value before handing Huh the options: Options()
	// resolves the starting cursor by matching an option's value
	// against the bound accessor.
	s.value = choiceValue{Index: -1}
	if spec.InitialID != "" {
		for i, c := range spec.Choices {
			if c.ID == spec.InitialID {
				s.value = choiceValue{Index: i, ID: c.ID}
				break
			}
		}
	}
	if s.value.Index < 0 && len(spec.Choices) > 0 {
		s.value = choiceValue{Index: 0, ID: spec.Choices[0].ID}
	}

	s.field = huh.NewSelect[choiceValue]().
		Title(spec.Title).
		Value(&s.value).
		Options(options...)
	s.form = newPilotForm(s.field)
	return s
}

func (s *huhSelectScreen) Init() tea.Cmd { return s.form.Init() }

func (s *huhSelectScreen) Finished() bool { return s.confirmed || s.canceled }
func (s *huhSelectScreen) Canceled() bool { return s.canceled }

// Selected is the chosen item's index into the original spec order —
// the migration compatibility helper for index-keyed router callbacks.
// Like the hand-written selectModel it tracks the cursor at all times
// and reports -1 when nothing is selectable (empty or zero-result list).
func (s *huhSelectScreen) Selected() int {
	if v, ok := s.field.Hovered(); ok {
		return v.Index
	}
	return -1
}

// SelectedID is the chosen item's stable Pilot ID.
func (s *huhSelectScreen) SelectedID() string {
	if v, ok := s.field.Hovered(); ok {
		return v.ID
	}
	return ""
}

// AutomationState implements Screen. Items is the currently visible
// (filtered) result set; filtering changes which items are observable
// and navigable but never an item's stable ID.
func (s *huhSelectScreen) AutomationState() AutomationState {
	matches := s.filter.matches()
	items := make([]AutomationItem, len(matches))
	for i, idx := range matches {
		c := s.spec.Choices[idx]
		items[i] = AutomationItem{ID: c.ID, Label: c.Label, Description: c.Description}
	}
	focused := -1
	if v, ok := s.field.Hovered(); ok {
		for i, idx := range matches {
			if idx == v.Index {
				focused = i
				break
			}
		}
	}
	return AutomationState{
		ScreenID:     screenIDOr(s.spec.ScreenID, "select"),
		Kind:         ScreenSelect,
		Title:        s.spec.Title,
		Items:        items,
		FocusedIndex: focused,
		FilterActive: s.field.GetFiltering() || s.filter.query != "",
	}
}

func (s *huhSelectScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if s.Finished() {
		return s, nil
	}
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return s, s.update(msg)
	}

	name := huhKeyName(key)
	filtering := s.field.GetFiltering()

	switch name {
	case "ctrl+c":
		// Never forwarded: Huh's Quit binding would set StateAborted
		// and blank the Form's View while Pilot's router still owns the
		// frame. Pilot's own canceled flag is the single source of
		// truth for a canceled screen.
		s.canceled = true
		return s, nil

	case "esc":
		if !filtering && s.filter.query == "" {
			// A "clean" Esc — no filter to clear. Huh would silently
			// absorb this, so Pilot cancels the screen itself.
			s.canceled = true
			return s, nil
		}
		// Let Huh run its native filter handling (leave capture mode,
		// then clear the query on a second Esc).
		s.filter.applyKey(name, key, filtering, false)
		return s, s.update(huhEscKey)

	case "enter":
		_, hovered := s.field.Hovered()
		s.filter.applyKey(name, key, filtering, false)
		// Swallow the field-advance cascade; see the type comment.
		_ = s.update(huhEnterKey)
		if !filtering && hovered {
			// An empty source list, or a filter matching nothing,
			// leaves nothing hovered: Return must not fabricate a
			// selection. While filtering, Return only leaves filter
			// mode — matching the hand-written screens, where Return
			// during a search commits the search rather than the row.
			s.confirmed = true
		}
		return s, nil

	case "tab", "shift+tab":
		s.filter.applyKey(name, key, filtering, false)
		_ = s.update(key)
		return s, nil

	default:
		s.filter.applyKey(name, key, filtering, false)
		return s, s.update(key)
	}
}

func (s *huhSelectScreen) View() tea.View { return s.view() }
