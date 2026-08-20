package tui

import (
	huh "charm.land/huh/v2"
)

// PilotHuhTheme is the single construction point for the Huh theme every
// Huh-backed Pilot screen renders with, per the migration spec's "Theme
// and Rendering Boundary" section: workflow/router code states *what*
// control it needs (a Spec) and never styles anything itself, so no
// business package imports lipgloss and no screen invents its own
// palette.
//
// The baseline is Huh's own ThemeBase rather than the flashier
// ThemeCharm: Pilot's hand-written screens render as plain text today,
// and Pilot records live wizard sessions (session.cast / presentation
// recordings / audit frames). A near-colorless theme keeps those
// artifacts stable and diffable instead of embedding a wall of 24-bit
// SGR sequences that change with every upstream palette tweak.
func PilotHuhTheme() huh.Theme {
	return huh.ThemeFunc(huh.ThemeBase)
}

// newPilotForm wraps exactly one field in exactly one single-group Huh
// form, themed consistently.
//
// One field per Form is deliberate (Core Invariant 1): the Pilot router
// stays authoritative for screen ownership and transitions, so a Huh
// Form is only ever a single embedded control — never a multi-step form
// that internally owns a Pilot workflow.
//
// The Form (rather than a bare huh.Field) is what applies the default
// KeyMap, the theme, and the FieldPosition that enables the field's
// Submit binding; a bare field constructed outside a Form has a
// zero-value keymap and therefore no working key bindings at all.
func newPilotForm(field huh.Field) *huh.Form {
	return huh.NewForm(huh.NewGroup(field)).
		WithTheme(PilotHuhTheme()).
		WithShowHelp(true).
		WithShowErrors(true)
}
