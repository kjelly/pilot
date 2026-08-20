package cmd

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

// TestComposeView_ContentIsPrefixPlusChild covers the migration spec's
// "View Composition" requirement (a): composeView's Content must be exactly
// prefix + child.Content, matching what editRouterModel.View() used to build
// by hand with a bare string concatenation before v2.
func TestComposeView_ContentIsPrefixPlusChild(t *testing.T) {
	child := tea.NewView("child body")
	got := composeView("banner\n\n", child)
	want := "banner\n\nchild body"
	if got.Content != want {
		t.Fatalf("Content = %q, want %q", got.Content, want)
	}
}

// TestComposeView_NoPrefixIsIdentity covers the router's no-banner case
// (editRouterModel.View() passes prefix == "" whenever r.banner is empty):
// composeView must not alter the child view at all in that case.
func TestComposeView_NoPrefixIsIdentity(t *testing.T) {
	child := tea.NewView("child body")
	got := composeView("", child)
	if got.Content != "child body" {
		t.Fatalf("Content = %q, want %q", got.Content, "child body")
	}
	if got.Cursor != nil {
		t.Fatalf("Cursor = %+v, want nil", got.Cursor)
	}
}

// TestComposeView_ShiftsCursorByPrefixLineCount covers requirement (b): a
// non-nil child.Cursor must survive into the composed view, with its Y
// shifted down by the number of newlines composeView's prefix introduces —
// otherwise the cursor would visually land on the wrong on-screen row once
// the banner is stacked above the child's own content, exactly the failure
// mode the migration spec calls out tea.NewView(prefix+child.Content) for.
func TestComposeView_ShiftsCursorByPrefixLineCount(t *testing.T) {
	child := tea.NewView("child body")
	child.Cursor = tea.NewCursor(3, 2)

	got := composeView("banner\n\n", child)

	if got.Cursor == nil {
		t.Fatal("Cursor = nil, want non-nil")
	}
	if got.Cursor.X != 3 {
		t.Fatalf("Cursor.X = %d, want unchanged 3", got.Cursor.X)
	}
	// "banner\n\n" has two newlines, so the cursor's row shifts down by 2.
	if got.Cursor.Y != 4 {
		t.Fatalf("Cursor.Y = %d, want 2+2=4", got.Cursor.Y)
	}

	// The child's own Cursor must not be mutated by composeView (it
	// returns a shifted copy, not an in-place edit of the original).
	if child.Cursor.Y != 2 {
		t.Fatalf("child.Cursor.Y was mutated to %d, want unchanged 2", child.Cursor.Y)
	}
}

// TestComposeView_NilCursorStaysNil covers requirement (c): when child has
// no cursor (the common case — most of this package's screens never set
// one), composeView must not manufacture one.
func TestComposeView_NilCursorStaysNil(t *testing.T) {
	child := tea.NewView("child body")
	got := composeView("banner\n\n", child)
	if got.Cursor != nil {
		t.Fatalf("Cursor = %+v, want nil", got.Cursor)
	}
}

// TestComposeView_PreservesOtherViewMetadata covers the spec's "保留 child
// view 的所有 terminal metadata" requirement beyond just Cursor: composeView
// must not silently drop fields like WindowTitle that
// tea.NewView(prefix+child.Content) (the forbidden approach) would.
func TestComposeView_PreservesOtherViewMetadata(t *testing.T) {
	child := tea.NewView("child body")
	child.WindowTitle = "pilot edit"
	got := composeView("banner\n\n", child)
	if got.WindowTitle != "pilot edit" {
		t.Fatalf("WindowTitle = %q, want %q", got.WindowTitle, "pilot edit")
	}
}

// TestViewContent covers the "viewContent(view tea.View) string" helper the
// migration spec requires for every audit/recording call site that needs a
// screen's rendered content as a plain string.
func TestViewContent(t *testing.T) {
	view := tea.NewView("hello world")
	if got := viewContent(view); got != "hello world" {
		t.Fatalf("viewContent() = %q, want %q", got, "hello world")
	}
}

func TestViewContent_Empty(t *testing.T) {
	if got := viewContent(tea.View{}); got != "" {
		t.Fatalf("viewContent(zero value) = %q, want empty", got)
	}
}
