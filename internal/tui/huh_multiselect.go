package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	huh "charm.land/huh/v2"
)

// huhMultiSelectScreen is the Huh v2-backed MultiSelectScreen
// implementation. See huhSelectScreen's type comment for why Esc and
// the submit cascade are Pilot-owned rather than delegated to Huh's
// Form state.
//
// Checked state is read back from the accessor Pilot binds to the Huh
// field, never from Huh's unexported option flags: the migration spec
// requires the adapter to hold the canonical checked-ID set through a
// bound accessor rather than reflecting into the widget. Huh keeps that
// slice in original option order and includes options currently hidden
// by a filter, which is exactly what CheckedIDs/CheckedLabels promise.
type huhMultiSelectScreen struct {
	huhFormBridge

	spec   MultiSelectSpec
	field  *huh.MultiSelect[choiceValue]
	filter huhListFilter

	// checked is bound to the Huh field as its accessor: Huh rewrites
	// it on every toggle, so it is the canonical checked set rather
	// than a copy that could drift.
	checked []choiceValue

	confirmed bool
	canceled  bool
}

var _ MultiSelectScreen = (*huhMultiSelectScreen)(nil)

// NewHuhMultiSelect builds a Huh v2-backed checklist screen.
func NewHuhMultiSelect(spec MultiSelectSpec) MultiSelectScreen {
	m := &huhMultiSelectScreen{spec: spec}

	keys := make([]string, len(spec.Choices))
	for i, c := range spec.Choices {
		keys[i] = huhOptionKey(c.Label, c.Description)
	}
	keys = huhUniqueKeys(keys)
	m.filter.keys = keys

	options := make([]huh.Option[choiceValue], len(spec.Choices))
	for i, c := range spec.Choices {
		v := choiceValue{Index: i, ID: c.ID}
		options[i] = huh.NewOption(keys[i], v).Selected(c.Checked)
		if c.Checked {
			m.checked = append(m.checked, v)
		}
	}

	m.field = huh.NewMultiSelect[choiceValue]().
		Title(spec.Title).
		Options(options...).
		Value(&m.checked).
		Height(huhListFieldHeight(spec.Title, len(spec.Choices)))
	m.form = newPilotForm(m.field)
	return m
}

// huhListFieldHeight is the explicit field height a Huh MultiSelect must
// be given so that every option actually renders.
//
// Leaving the height unset is not an option, measured against huh
// v2.0.3: MultiSelect.updateViewportSize() computes an automatic height
// as "one line per option" (which never included the title) and then
// subtracts the title/description height from it anyway, so an
// auto-height checklist silently drops its LAST option row — and a
// single-option checklist renders no rows at all, just an empty frame.
// huh's Select does not have this defect (its height-0 branch skips the
// subtraction), which is why only checklist screens were affected.
//
// Sizing the field to "the title's lines plus one line per option" makes
// that subtraction land on exactly the number of options, reproducing
// Select's own auto-height behaviour. options is floored at 1 so an
// empty option set still renders its title rather than collapsing.
//
// Known limit, inherited rather than introduced: a title long enough to
// wrap counts as more rendered lines than it has newlines, so a wrapped
// title would still cost one option row. Pilot's checklist titles are
// single-line and short enough not to wrap at any usual terminal width.
func huhListFieldHeight(title string, options int) int {
	if options < 1 {
		options = 1
	}
	return options + strings.Count(title, "\n") + 1
}

func (m *huhMultiSelectScreen) Init() tea.Cmd { return m.form.Init() }

func (m *huhMultiSelectScreen) Finished() bool { return m.confirmed || m.canceled }
func (m *huhMultiSelectScreen) Canceled() bool { return m.canceled }

// CheckedIDs returns the stable Pilot ID of every checked item, in the
// original spec's order.
func (m *huhMultiSelectScreen) CheckedIDs() []string {
	var out []string
	for _, v := range m.checked {
		out = append(out, v.ID)
	}
	return out
}

// CheckedLabels is the migration compatibility helper for callers still
// keyed on human labels.
func (m *huhMultiSelectScreen) CheckedLabels() []string {
	var out []string
	for _, v := range m.checked {
		if v.Index >= 0 && v.Index < len(m.spec.Choices) {
			out = append(out, m.spec.Choices[v.Index].Label)
		}
	}
	return out
}

func (m *huhMultiSelectScreen) isChecked(index int) bool {
	for _, v := range m.checked {
		if v.Index == index {
			return true
		}
	}
	return false
}

// AutomationState implements Screen. Items is the currently visible
// (filtered) result set; filtering never changes an item's stable ID or
// its checked state.
func (m *huhMultiSelectScreen) AutomationState() AutomationState {
	matches := m.filter.matches()
	items := make([]AutomationItem, len(matches))
	for i, idx := range matches {
		c := m.spec.Choices[idx]
		items[i] = AutomationItem{
			ID:          c.ID,
			Label:       c.Label,
			Description: c.Description,
			Checked:     m.isChecked(idx),
		}
	}
	focused := -1
	if v, ok := m.field.Hovered(); ok {
		for i, idx := range matches {
			if idx == v.Index {
				focused = i
				break
			}
		}
	}
	return AutomationState{
		ScreenID:     screenIDOr(m.spec.ScreenID, "multi-select"),
		Kind:         ScreenMultiSelect,
		Title:        m.spec.Title,
		Items:        items,
		FocusedIndex: focused,
		FilterActive: m.field.GetFiltering() || m.filter.query != "",
	}
}

func (m *huhMultiSelectScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.Finished() {
		return m, nil
	}
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return m, m.update(msg)
	}

	name := huhKeyName(key)
	filtering := m.field.GetFiltering()

	switch name {
	case "ctrl+c":
		m.canceled = true
		return m, nil

	case "esc":
		if !filtering && m.filter.query == "" {
			m.canceled = true
			return m, nil
		}
		m.filter.applyKey(name, key, filtering, true)
		return m, m.update(huhEscKey)

	case "enter":
		_, hovered := m.field.Hovered()
		m.filter.applyKey(name, key, filtering, true)
		_ = m.update(huhEnterKey)
		// An empty *source* list is a legal answer for an optional
		// checklist (a sudo rule may use direct commands with no
		// command groups), so Return commits it — Huh's MultiSelect
		// already behaves this way natively, unlike its Select. A
		// non-empty list filtered to zero results is different: Return
		// must not silently submit a typo, and for this field Huh binds
		// Return to "leave filter mode" while filtering anyway.
		if !filtering && (hovered || len(m.spec.Choices) == 0) {
			m.confirmed = true
		}
		return m, nil

	case "tab", "shift+tab":
		m.filter.applyKey(name, key, filtering, true)
		_ = m.update(key)
		return m, nil

	default:
		m.filter.applyKey(name, key, filtering, true)
		return m, m.update(key)
	}
}

func (m *huhMultiSelectScreen) View() tea.View { return m.view() }
