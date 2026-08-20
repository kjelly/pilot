// Package tui defines Pilot's own UI contract for wizard screens
// (select, multi-select, input, confirm): the Screen/typed-result
// interfaces, the immutable AutomationState snapshot, and the
// Spec/Factory types routers use to describe "what control is needed"
// without depending on any particular widget provider's concrete
// types. See docs/superpowers/specs/2026-08-19-pilot-tui-v2-huh-migration-spec.md.
package tui

// ScreenKind identifies which kind of control an AutomationState
// snapshot describes.
type ScreenKind string

const (
	ScreenSelect      ScreenKind = "select"
	ScreenMultiSelect ScreenKind = "multi-select"
	ScreenInput       ScreenKind = "input"
	ScreenConfirm     ScreenKind = "confirm"
)

// AutomationItem is one selectable/checkable row as seen by semantic
// automation. ID is the stable machine identity (Core Invariant 5);
// Label/Description are human presentation and may contain Chinese
// text, emoji, or dynamic counts that automation must never treat as
// identity.
type AutomationItem struct {
	ID          string
	Label       string
	Description string
	Checked     bool
}

// AutomationState is an immutable, Pilot-owned snapshot of a screen's
// machine-observable state. It must never expose a secret input's
// typed value (Core Invariant 6) and must never leak a widget
// provider's concrete/private types (Core Invariant 3).
type AutomationState struct {
	ScreenID string
	Kind     ScreenKind
	Title    string
	Items    []AutomationItem
	Secret   bool

	// FocusedIndex is the current cursor position within Items (the
	// filtered/visible result set), or -1 when not applicable
	// (Input/Confirm screens, or an empty Select/MultiSelect list).
	// Automation uses this to compute how many Up/Down keys move the
	// cursor onto a target item — this is inherent to driving a
	// keyboard-navigated list and is not a widget implementation
	// detail.
	FocusedIndex int

	// FilterActive reports whether a Select/MultiSelect's "/" filter
	// is currently capturing keystrokes.
	FilterActive bool

	// HasValue reports whether an Input/secret-Input screen currently
	// holds a non-empty value, without exposing the value itself.
	HasValue bool

	// ValidationError is an Input screen's current validator rejection
	// message (empty when the last submit attempt succeeded or none
	// was made yet). Never populated from a secret's typed value.
	ValidationError string
}
