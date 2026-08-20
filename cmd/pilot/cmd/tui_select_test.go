package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

func newManySelectItems(n int) []selectItem {
	items := make([]selectItem, n)
	for i := range items {
		items[i] = selectItem{Label: fmt.Sprintf("item-%02d", i)}
	}
	return items
}

// selectItems builds []selectItem from bare labels, for tests that
// construct a selectModel literal directly rather than through
// newSelectModel.
func selectItems(labels ...string) []selectItem {
	items := make([]selectItem, len(labels))
	for i, l := range labels {
		items[i] = selectItem{Label: l}
	}
	return items
}

func TestSelectModel_DownMovesCursor(t *testing.T) {
	m := selectModel{title: "t", items: selectItems("a", "b", "c")}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(selectModel)
	if m.cursor != 1 {
		t.Fatalf("cursor = %d, want 1", m.cursor)
	}
}

func TestSelectModel_CursorWrapsAtBounds(t *testing.T) {
	m := selectModel{title: "t", items: selectItems("a", "b", "c")}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = next.(selectModel)
	if m.cursor != 2 {
		t.Fatalf("cursor = %d, want 2 after wrapping up from first item", m.cursor)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(selectModel)
	if m.cursor != 0 {
		t.Fatalf("cursor = %d, want 0 after wrapping down from last item", m.cursor)
	}
}

func TestSelectModel_FuzzySearchPreservesOriginalSelection(t *testing.T) {
	m := newSelectModel("t", []string{"alpha", "FreeIPA Server", "freeipa-client", "beta"})
	for _, msg := range []tea.KeyMsg{
		{Type: tea.KeyRunes, Runes: []rune("/")},
		{Type: tea.KeyRunes, Runes: []rune("fas")},
		{Type: tea.KeyEnter}, // finish editing the search, keep its results
		{Type: tea.KeyEnter}, // select the sole match
	} {
		next, _ := m.Update(msg)
		m = next.(selectModel)
	}
	if !m.Finished() || m.Canceled() {
		t.Fatal("expected fuzzy-matched item to be selected")
	}
	if m.Selected() != 1 {
		t.Fatalf("Selected() = %d, want original index 1", m.Selected())
	}
	if view := m.View(); !strings.Contains(view, "搜尋：fas") || strings.Contains(view, "freeipa-client") {
		t.Fatalf("view did not retain only the fuzzy-matched item:\n%s", view)
	}
}

func TestSelectModel_SearchNoMatchesCanClearThenCancel(t *testing.T) {
	m := newSelectModel("t", []string{"alpha"})
	for _, msg := range []tea.KeyMsg{
		{Type: tea.KeyRunes, Runes: []rune("/")},
		{Type: tea.KeyRunes, Runes: []rune("zzz")},
	} {
		next, _ := m.Update(msg)
		m = next.(selectModel)
	}
	if m.Finished() {
		t.Fatal("searching with no matches must not finish the screen")
	}
	if view := m.View(); !strings.Contains(view, "沒有符合搜尋條件") {
		t.Fatalf("missing no-results feedback:\n%s", view)
	}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(selectModel)
	if m.Canceled() || m.query != "" || m.searching {
		t.Fatalf("first esc should clear search, got canceled=%v query=%q searching=%v", m.Canceled(), m.query, m.searching)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(selectModel)
	if !m.Canceled() {
		t.Fatal("second esc should cancel the list")
	}
}

func TestSelectModel_EnterConfirmsWithoutCanceling(t *testing.T) {
	m := selectModel{title: "t", items: selectItems("a", "b")}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(selectModel)
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(selectModel)
	if !m.Finished() || m.Canceled() {
		t.Fatalf("expected finished+not-canceled after enter, got finished=%v canceled=%v", m.Finished(), m.Canceled())
	}
	if m.Selected() != 1 {
		t.Fatalf("Selected() = %d, want 1", m.Selected())
	}
}

func TestSelectModel_LFEnterConfirmsWithoutCanceling(t *testing.T) {
	m := selectModel{title: "t", items: selectItems("a")}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlJ})
	m = next.(selectModel)
	if !m.Finished() || m.Canceled() {
		t.Fatal("expected LF/ctrl+j Return to confirm without canceling")
	}
}

func TestSelectModel_EnterOnEmptyListDoesNothing(t *testing.T) {
	m := selectModel{title: "t"}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(selectModel)
	if m.Finished() {
		t.Fatal("enter on an empty list should not finish the screen")
	}
}

func TestSelectModel_EscCancels(t *testing.T) {
	m := selectModel{title: "t", items: selectItems("a")}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(selectModel)
	if !m.Finished() || !m.Canceled() {
		t.Fatal("expected finished+canceled after esc")
	}
}

func TestSelectModel_ViewShowsTitleAndItems(t *testing.T) {
	m := selectModel{title: "選單標題", items: selectItems("alpha", "beta")}
	view := m.View()
	for _, want := range []string{"選單標題", "alpha", "beta", "▸"} {
		if !strings.Contains(view, want) {
			t.Fatalf("view missing %q:\n%s", want, view)
		}
	}
}

func TestSelectModel_ScrollIndicatorReflectsHiddenItems(t *testing.T) {
	m := selectModel{title: "t", items: newManySelectItems(20)}
	next, _ := m.Update(tea.WindowSizeMsg{Height: 10}) // rows = 4
	m = next.(selectModel)
	if !strings.Contains(m.View(), "還有 16 項在下面") {
		t.Fatalf("expected below-indicator for remaining 16 items:\n%s", m.View())
	}
}

func TestSelectModel_ScreenIDFallsBackWhenUnset(t *testing.T) {
	m := newSelectModel("t", []string{"a"})
	if got := m.automationScreenID(); got != "select" {
		t.Fatalf("automationScreenID() = %q, want legacy fallback %q", got, "select")
	}
}

func TestSelectModel_ScreenIDUsesExplicitID(t *testing.T) {
	m := newSelectModelWithScreenID("hosts.list", "t", []string{"a"})
	if got := m.automationScreenID(); got != "hosts.list" {
		t.Fatalf("automationScreenID() = %q, want %q", got, "hosts.list")
	}
}

func TestSelectModel_WithIDsPreservesLabelsAndIDs(t *testing.T) {
	items := []selectItem{{ID: "hosts.create", Label: "➕ 新增主機"}, {ID: "", Label: "web-01"}}
	m := newSelectModelWithIDs("hosts.list", "t", items)
	if got := m.automationItems(); len(got) != 2 || got[0] != "➕ 新增主機" || got[1] != "web-01" {
		t.Fatalf("automationItems() = %v, want labels from items", got)
	}
	idx, err := itemIndexByID(m.AutomationState().Items, "hosts.create")
	if err != nil || idx != 0 {
		t.Fatalf("itemIndexByID(hosts.create) = (%d, %v), want (0, nil)", idx, err)
	}
}

func TestNewSelectModel_DumpsMenuUnderDebugEnv(t *testing.T) {
	t.Setenv("PILOT_DEBUG_MENU", "1")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	_ = newSelectModel("dump 測試", []string{"only-item"})
	w.Close()
	os.Stderr = orig

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "only-item") {
		t.Fatalf("expected PILOT_DEBUG_MENU=1 to dump menu items to stderr, got:\n%s", out)
	}
}

func TestSelectModel_Teatest_HappyPath(t *testing.T) {
	m := screenTestHarness{s: selectModel{title: "t", items: selectItems("a", "b", "c")}}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Type("jj") // cursor -> index 2
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	got := final.(screenTestHarness).s.(selectModel)
	if got.Canceled() {
		t.Fatal("enter should not cancel")
	}
	if got.Selected() != 2 {
		t.Fatalf("Selected() = %d, want 2", got.Selected())
	}
}

func TestSelectModel_Teatest_FuzzySearchAndSelect(t *testing.T) {
	m := screenTestHarness{s: newSelectModel("t", []string{"alpha", "FreeIPA Server", "freeipa-client"})}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Type("/fas")
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return strings.Contains(string(b), "搜尋：fas")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	got := final.(screenTestHarness).s.(selectModel)
	if got.Selected() != 1 || got.Canceled() {
		t.Fatalf("fuzzy selection = %d, canceled=%v; want original index 1, false", got.Selected(), got.Canceled())
	}
	output, err := io.ReadAll(tm.FinalOutput(t, teatest.WithFinalTimeout(3*time.Second)))
	if err != nil {
		t.Fatalf("read program output: %v", err)
	}
	if !strings.Contains(string(output), "搜尋：fas") {
		t.Fatalf("program output did not show the search query:\n%s", output)
	}
}

func TestSelectModel_Teatest_EscCancels(t *testing.T) {
	m := screenTestHarness{s: selectModel{title: "t", items: selectItems("a", "b")}}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	got := final.(screenTestHarness).s.(selectModel)
	if !got.Canceled() {
		t.Fatal("expected canceled after esc")
	}
}
