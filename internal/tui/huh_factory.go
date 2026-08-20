package tui

// huhFactory builds every wizard control from Huh v2 fields.
//
// It is the Huh-backed sibling of the hand-written primitives in
// cmd/pilot/cmd, satisfying the identical Factory contract. Routers
// depend on Factory, so swapping which one is injected changes the
// widget provider without touching a line of router or workflow code
// (Core Invariant 2).
type huhFactory struct{}

var _ Factory = huhFactory{}

// NewHuhFactory returns a Factory whose screens are backed by Huh v2.
func NewHuhFactory() Factory { return huhFactory{} }

func (huhFactory) Select(spec SelectSpec) SelectScreen { return NewHuhSelect(spec) }

func (huhFactory) MultiSelect(spec MultiSelectSpec) MultiSelectScreen {
	return NewHuhMultiSelect(spec)
}

func (huhFactory) Input(spec InputSpec) InputScreen { return NewHuhInput(spec) }

func (huhFactory) Confirm(spec ConfirmSpec) ConfirmScreen { return NewHuhConfirm(spec) }
