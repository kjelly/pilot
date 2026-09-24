package tui

import (
	"bytes"
	"strings"
	"testing"
)

// captureMenuDebug points menuDebugOut at a buffer for the rest of the test.
func captureMenuDebug(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := menuDebugOut
	menuDebugOut = &buf
	t.Cleanup(func() { menuDebugOut = orig })
	return &buf
}

func debugMenuSpec() SelectSpec {
	return SelectSpec{
		Title: "測試選單",
		Choices: []Choice{
			{ID: "a", Label: "item-a"},
			{ID: "b", Label: "item-b", Description: "second"},
			{ID: "c", Label: "item-a"},
		},
	}
}

// TestFactorySelect_DumpsRenderedRowsWhenDebugEnvSet builds the screen the
// way every router does, through the Huh factory, and checks the dump lists
// each row as rendered (description column, duplicate padding) with its
// 0-based index.
func TestFactorySelect_DumpsRenderedRowsWhenDebugEnvSet(t *testing.T) {
	t.Setenv(menuDebugEnv, "1")
	buf := captureMenuDebug(t)

	NewHuhFactory().Select(debugMenuSpec())

	want := strings.Join([]string{
		"[pilot:menu] 測試選單 (3 項，DOWN <n> 從 0 起算)",
		"[pilot:menu]   0: item-a",
		"[pilot:menu]   1: " + huhOptionKey("item-b", "second"),
		"[pilot:menu]   2: item-a ",
		"",
	}, "\n")
	if got := buf.String(); got != want {
		t.Fatalf("dump mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestFactorySelect_SilentWithoutDebugEnv(t *testing.T) {
	t.Setenv(menuDebugEnv, "")
	buf := captureMenuDebug(t)

	NewHuhFactory().Select(debugMenuSpec())

	if buf.Len() != 0 {
		t.Fatalf("dump printed with %s empty: %q", menuDebugEnv, buf.String())
	}
}
