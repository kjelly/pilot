package tui

import (
	tea "charm.land/bubbletea/v2"
)

// Screen is the contract every wizard control satisfies, independent
// of whether it is implemented by hand (today) or by a Huh/Bubbles
// adapter (later phases of the migration). Business/router/automation
// code depends only on this and the typed result interfaces below —
// never on a concrete widget type (Core Invariant 2/3).
type Screen interface {
	tea.Model
	// Finished reports whether the user has confirmed or canceled this
	// screen.
	Finished() bool
	// Canceled reports whether the screen finished via esc/ctrl+c
	// rather than a genuine confirm. Confirm screens always report
	// false here (see ConfirmScreen doc).
	Canceled() bool
	// AutomationState returns a Pilot-owned immutable snapshot for
	// semantic automation. It must never expose secret values or
	// widget-provider-private state.
	AutomationState() AutomationState
}

// SelectScreen is a single-choice list screen's typed result. Selected
// is a migration compatibility helper for the ~120 existing router
// callback call sites keyed on original-choice index; new code should
// prefer SelectedID.
type SelectScreen interface {
	Screen
	SelectedID() string
	Selected() int
}

// MultiSelectScreen is a checklist screen's typed result. CheckedLabels
// is a migration compatibility helper; new code should prefer
// CheckedIDs.
type MultiSelectScreen interface {
	Screen
	CheckedIDs() []string
	CheckedLabels() []string
}

// InputScreen is a single-line text entry screen's typed result.
type InputScreen interface {
	Screen
	Value() string
}

// ConfirmScreen is a yes/no screen's typed result. Canceled() always
// reports false here: esc/ctrl+c collapses to "no" rather than a
// separate cancel outcome (see Current State to Preserve in the
// migration spec).
type ConfirmScreen interface {
	Screen
	Value() bool
}
