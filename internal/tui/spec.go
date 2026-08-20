package tui

// Choice is one option a Select/MultiSelect spec offers. ID is the
// stable machine identity a Factory implementation must bind as the
// underlying widget's option value (Core Invariant 5); Label/
// Description are presentation-only.
type Choice struct {
	ID          string
	Label       string
	Description string
}

// SelectSpec describes a single-choice list screen. Routers build a
// SelectSpec to say "I need a choice among these options" without
// knowing whether the Factory backing them builds a hand-written list
// or a Huh field.
type SelectSpec struct {
	ScreenID  string
	Title     string
	Choices   []Choice
	InitialID string
}

// MultiSelectChoice is one row of a MultiSelectSpec, carrying its
// initial checked state alongside the shared Choice fields.
type MultiSelectChoice struct {
	Choice
	Checked bool
}

// MultiSelectSpec describes a checklist screen.
type MultiSelectSpec struct {
	ScreenID string
	Title    string
	Choices  []MultiSelectChoice
}

// InputSpec describes a single-line text entry screen.
type InputSpec struct {
	ScreenID string
	Title    string
	Default  string
	Secret   bool
	Validate func(string) error
}

// ConfirmSpec describes a yes/no screen.
type ConfirmSpec struct {
	ScreenID string
	Title    string
	Default  bool
}
