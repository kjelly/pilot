package tui

// Factory builds Screen implementations from Pilot-owned specs.
// Routers inject a Factory rather than constructing widgets directly,
// so the widget provider (today's hand-written primitives; Huh v2 in
// a later migration phase) can change without touching router or
// workflow code.
type Factory interface {
	Select(SelectSpec) SelectScreen
	MultiSelect(MultiSelectSpec) MultiSelectScreen
	Input(InputSpec) InputScreen
	Confirm(ConfirmSpec) ConfirmScreen
}
