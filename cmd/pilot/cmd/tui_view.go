// tui_view.go centralizes the two v2-only View() concerns the migration
// spec calls out by name: composing a router banner in front of a child
// screen's tea.View without dropping its terminal metadata (composeView),
// and extracting a screen's rendered content as a plain string for
// audit/recording purposes (viewContent) — see "View Migration" / "View
// Composition" in docs/superpowers/specs/2026-08-19-pilot-tui-v2-huh-migration-spec.md.
package cmd

import (
	"strings"

	tea "charm.land/bubbletea/v2"
)

// composeView prepends prefix (editRouterModel's banner, plus the blank
// line that already separated it from the screen body) to child's rendered
// content, while preserving every other tea.View field child set — most
// importantly Cursor: a nil tea.NewView(prefix+child.Content) rebuild would
// silently drop it (and any other metadata, e.g. BackgroundColor/
// WindowTitle), which the spec explicitly forbids. When child has a
// Cursor whose position is expressed in the child view's own coordinate
// space, prefix's line count is added to its Y so the cursor still lands on
// the right screen row once prefix is stacked above the child's content.
func composeView(prefix string, child tea.View) tea.View {
	v := child
	v.Content = prefix + child.Content
	if child.Cursor != nil {
		shifted := *child.Cursor
		shifted.Y += strings.Count(prefix, "\n")
		v.Cursor = &shifted
	}
	return v
}

// viewContent extracts view's rendered content as a plain string — the one
// call site every audit/recording/trace consumer uses instead of assuming
// tea.Model.View() still returns a string outright. Centralizing this means
// only this function needs to change if tea.View's shape grows again.
func viewContent(view tea.View) string {
	return view.Content
}
