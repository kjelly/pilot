package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestHuhKeyNameNormalization(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  tea.KeyPressMsg
		want string
	}{
		{"return", tea.KeyPressMsg{Code: tea.KeyEnter}, "enter"},
		{"ctrl+j is return on some ptys", tea.KeyPressMsg{Code: 'j', Mod: tea.ModCtrl}, "enter"},
		{"esc", tea.KeyPressMsg{Code: tea.KeyEsc}, "esc"},
		{"ctrl+c", tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}, "ctrl+c"},
		{"plain j stays j", runeKey('j'), "j"},
		{"space", tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}, "space"},
		{"slash", runeKey('/'), "/"},
		{"backspace", tea.KeyPressMsg{Code: tea.KeyBackspace}, "backspace"},
		{"tab", tea.KeyPressMsg{Code: tea.KeyTab}, "tab"},
		{"shift+tab", tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}, "shift+tab"},
	} {
		if got := huhKeyName(tc.msg); got != tc.want {
			t.Fatalf("%s: huhKeyName=%q want %q", tc.name, got, tc.want)
		}
	}
}

// Ctrl-J must reach huh as a real Return, never as the raw key: huh's
// Select keymap binds ctrl+j to "move down", so forwarding it verbatim
// would scroll the list instead of choosing the highlighted row.
func TestHuhSelectCtrlJActsAsReturn(t *testing.T) {
	s := NewHuhSelect(fruitSpec())
	s.Init()
	send(t, s, tea.KeyPressMsg{Code: 'j', Mod: tea.ModCtrl})
	if !s.Finished() || s.Canceled() {
		t.Fatalf("finished=%v canceled=%v", s.Finished(), s.Canceled())
	}
	if got := s.SelectedID(); got != "a" {
		t.Fatalf("SelectedID=%q want %q — ctrl+j moved the cursor instead of submitting", got, "a")
	}
}

func TestHuhOptionKeyFoldsDescription(t *testing.T) {
	if got := huhOptionKey("Docker", ""); got != "Docker" {
		t.Fatalf("no-description key=%q", got)
	}
	got := huhOptionKey("Docker", "container runtime")
	if !strings.HasPrefix(got, "Docker") || !strings.HasSuffix(got, "container runtime") {
		t.Fatalf("folded key=%q", got)
	}
	if strings.Contains(got, "Docker container") {
		t.Fatalf("label and description were not column-separated: %q", got)
	}
	// A label longer than the column still keeps at least one space.
	long := huhOptionKey(strings.Repeat("x", 40), "desc")
	if !strings.Contains(long, "x desc") {
		t.Fatalf("over-long label lost its separator: %q", long)
	}
}

func TestHuhUniqueKeysDisambiguatesDuplicates(t *testing.T) {
	got := huhUniqueKeys([]string{"web", "web", "db", "web"})
	seen := map[string]bool{}
	for _, k := range got {
		if seen[k] {
			t.Fatalf("duplicate key survived: %q in %q", k, got)
		}
		seen[k] = true
		if strings.TrimRight(k, " ") != "web" && strings.TrimRight(k, " ") != "db" {
			t.Fatalf("key %q is not a padded form of its original", k)
		}
	}
	if got[0] != "web" {
		t.Fatalf("first occurrence was padded: %q", got[0])
	}
}

func TestHuhListFilterMirrorsHuhPredicate(t *testing.T) {
	f := huhListFilter{keys: []string{"Alpha", "Beta", "Gamma"}}
	if got := f.matches(); len(got) != 3 {
		t.Fatalf("empty query matched %d want 3", len(got))
	}
	f.query = "a"
	// Case-insensitive substring, exactly what huh's filterFunc does.
	if got := f.matches(); len(got) != 3 {
		t.Fatalf("query %q matched %v want all three", f.query, got)
	}
	f.query = "MM"
	if got := f.matches(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("query %q matched %v want [2]", f.query, got)
	}
	f.query = "zzz"
	if got := f.matches(); len(got) != 0 {
		t.Fatalf("query %q matched %v want none", f.query, got)
	}
}

func TestHuhListFilterApplyKeyTracksQuery(t *testing.T) {
	f := huhListFilter{keys: []string{"Alpha", "Beta"}}

	// Not filtering: "/" only switches huh into capture mode.
	f.applyKey("/", runeKey('/'), false, false)
	if f.query != "" {
		t.Fatalf("query=%q after entering filter mode", f.query)
	}

	f.applyKey("B", runeKey('B'), true, false)
	f.applyKey("e", runeKey('e'), true, false)
	if f.query != "Be" {
		t.Fatalf("query=%q want %q", f.query, "Be")
	}

	f.applyKey("backspace", tea.KeyPressMsg{Code: tea.KeyBackspace}, true, false)
	if f.query != "B" {
		t.Fatalf("query=%q want %q", f.query, "B")
	}

	// Leaving capture mode with a query that still matches keeps it.
	f.applyKey("esc", keyEsc, true, false)
	if f.query != "B" {
		t.Fatalf("query=%q want the matching query preserved", f.query)
	}
	// A second esc (huh's ClearFilter) drops it.
	f.applyKey("esc", keyEsc, false, false)
	if f.query != "" {
		t.Fatalf("query=%q want empty after clear", f.query)
	}

	// A query matching nothing is dropped as soon as capture mode ends.
	f.query = "zzz"
	f.applyKey("esc", keyEsc, true, false)
	if f.query != "" {
		t.Fatalf("query=%q want empty; huh drops a zero-result query", f.query)
	}

	// huh's MultiSelect also binds Return to "set filter", and drops a
	// zero-result query the same way; its Select does not.
	f.query = "zzz"
	f.applyKey("enter", keyEnter, true, false)
	if f.query != "zzz" {
		t.Fatalf("query=%q want preserved for a Select-style field", f.query)
	}
	f.applyKey("enter", keyEnter, true, true)
	if f.query != "" {
		t.Fatalf("query=%q want empty for a MultiSelect-style field", f.query)
	}

	// ctrl+u clears the whole query in place.
	f.query = "abc"
	f.applyKey("ctrl+u", tea.KeyPressMsg{Code: 'u', Mod: tea.ModCtrl}, true, false)
	if f.query != "" {
		t.Fatalf("query=%q want empty after ctrl+u", f.query)
	}
}

func TestDropLastRuneHandlesMultibyte(t *testing.T) {
	if got := dropLastRune(""); got != "" {
		t.Fatalf("dropLastRune(\"\")=%q", got)
	}
	if got := dropLastRune("主機"); got != "主" {
		t.Fatalf("dropLastRune(主機)=%q want 主", got)
	}
	if got := dropLastRune("ab🖥"); got != "ab" {
		t.Fatalf("dropLastRune(ab🖥)=%q want ab", got)
	}
}

func TestPilotHuhThemeIsUsable(t *testing.T) {
	theme := PilotHuhTheme()
	if theme == nil {
		t.Fatalf("PilotHuhTheme returned nil")
	}
	for _, dark := range []bool{true, false} {
		if theme.Theme(dark) == nil {
			t.Fatalf("theme.Theme(%v) returned nil styles", dark)
		}
	}
}

func TestScreenIDOr(t *testing.T) {
	if got := screenIDOr("hosts.list", "select"); got != "hosts.list" {
		t.Fatalf("screenIDOr=%q", got)
	}
	if got := screenIDOr("", "select"); got != "select" {
		t.Fatalf("screenIDOr=%q", got)
	}
}
