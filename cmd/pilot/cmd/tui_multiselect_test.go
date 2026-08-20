package cmd

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"
)

func newTestMultiSelect() multiSelectModel {
	return multiSelectModel{
		title: "test",
		items: []multiSelectItem{
			{Label: "dns", Checked: false},
			{Label: "ntp", Checked: true},
			{Label: "docker", Checked: false},
		},
	}
}

func newManyItemMultiSelect(n int) multiSelectModel {
	items := make([]multiSelectItem, n)
	for i := range items {
		items[i] = multiSelectItem{Label: fmt.Sprintf("role-%02d", i)}
	}
	return multiSelectModel{title: "test", items: items}
}

func TestMultiSelect_SpaceTogglesItemUnderCursor(t *testing.T) {
	m := newTestMultiSelect()
	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeySpace})
	m = next.(multiSelectModel)
	if !m.items[0].Checked {
		t.Fatalf("expected items[0] to be checked after space, got %+v", m.items)
	}
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace})
	m = next.(multiSelectModel)
	if m.items[0].Checked {
		t.Fatalf("expected items[0] to be unchecked after a second space, got %+v", m.items)
	}
}

func TestMultiSelect_DownMovesCursorWithoutResettingOthers(t *testing.T) {
	m := newTestMultiSelect()
	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	m = next.(multiSelectModel)
	if m.cursor != 1 {
		t.Fatalf("cursor = %d, want 1", m.cursor)
	}
	if !m.items[1].Checked {
		t.Fatalf("expected seeded ntp-checked state to survive cursor movement, got %+v", m.items)
	}
}

func TestMultiSelect_CursorWrapsAtBounds(t *testing.T) {
	m := newTestMultiSelect()
	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyUp})
	m = next.(multiSelectModel)
	if m.cursor != len(m.items)-1 {
		t.Fatalf("cursor = %d, want %d after wrapping up from first item", m.cursor, len(m.items)-1)
	}
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	m = next.(multiSelectModel)
	if m.cursor != 0 {
		t.Fatalf("cursor = %d, want 0 after wrapping down from last item", m.cursor)
	}
}

func TestMultiSelect_FuzzySearchTogglesMatchedOriginalItem(t *testing.T) {
	m := newMultiSelectModel("t", []multiSelectItem{
		{Label: "dns", Description: "resolves hosts"},
		{Label: "ntp", Description: "time synchronization"},
		{Label: "restic", Description: "encrypted backups"},
	})
	for _, msg := range []tea.KeyPressMsg{
		{Text: "/", Code: '/'},
		{Text: "syn", Code: 's'},
		{Code: tea.KeyEnter}, // finish editing the search, keep its results
		{Code: tea.KeySpace}, // toggle the sole matched item
		{Code: tea.KeyEnter}, // finish the checklist
	} {
		next, _ := m.Update(msg)
		m = next.(multiSelectModel)
	}
	if !m.Finished() || !m.items[1].Checked || m.items[0].Checked || m.items[2].Checked {
		t.Fatalf("fuzzy toggle changed the wrong items: %+v", m.items)
	}
}

func TestMultiSelect_SearchNoMatchesDoesNotFinish(t *testing.T) {
	m := newMultiSelectModel("t", []multiSelectItem{{Label: "dns"}})
	for _, msg := range []tea.KeyPressMsg{
		{Text: "/", Code: '/'},
		{Text: "zzz", Code: 'z'},
		{Code: tea.KeyEnter}, // finish editing the search, keep the empty results
		{Code: tea.KeyEnter}, // must not submit a checklist with no result
	} {
		next, _ := m.Update(msg)
		m = next.(multiSelectModel)
	}
	if m.Finished() {
		t.Fatal("enter with no fuzzy-search results must not finish the checklist")
	}
	if view := viewContent(m.View()); !strings.Contains(view, "沒有符合搜尋條件") {
		t.Fatalf("missing no-results feedback:\n%s", view)
	}
}

func TestMultiSelect_EnterFinishesWithoutCanceling(t *testing.T) {
	m := newTestMultiSelect()
	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(multiSelectModel)
	if !m.Finished() || m.Canceled() {
		t.Fatal("expected finished+not-canceled after enter")
	}
	want := map[string]bool{"dns": false, "ntp": true, "docker": false}
	for _, label := range m.CheckedLabels() {
		if !want[label] {
			t.Fatalf("unexpected checked label %q (checked: %v)", label, m.CheckedLabels())
		}
	}
}

func TestMultiSelect_LFEnterFinishesWithoutCanceling(t *testing.T) {
	m := newTestMultiSelect()
	next, _ := m.Update(tea.KeyPressMsg{Code: 'j', Mod: tea.ModCtrl})
	m = next.(multiSelectModel)
	if !m.Finished() || m.Canceled() {
		t.Fatal("expected LF/ctrl+j Return to finish without canceling")
	}
}

func TestMultiSelect_EscCancels(t *testing.T) {
	m := newTestMultiSelect()
	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(multiSelectModel)
	if !m.Finished() || !m.Canceled() {
		t.Fatal("expected finished+canceled after esc")
	}
}

func TestMultiSelect_RawEscapeCancels(t *testing.T) {
	m := newTestMultiSelect()
	next, _ := m.Update(tea.KeyPressMsg{Code: 27, Text: "\x1b"})
	m = next.(multiSelectModel)
	if !m.Finished() || !m.Canceled() {
		t.Fatal("expected raw ESC to cancel")
	}
}

func TestMultiSelect_EmptyItemListDoesNotPanic(t *testing.T) {
	m := multiSelectModel{title: "empty"}
	for _, msg := range []tea.Msg{
		tea.KeyPressMsg{Code: tea.KeyDown},
		tea.KeyPressMsg{Code: tea.KeyUp},
		tea.KeyPressMsg{Code: tea.KeySpace},
		tea.WindowSizeMsg{Height: 24, Width: 80},
	} {
		next, _ := m.Update(msg)
		m = next.(multiSelectModel)
	}
	if m.cursor != 0 {
		t.Fatalf("cursor = %d, want 0 for an empty list", m.cursor)
	}
	if !strings.Contains(viewContent(m.View()), "empty") {
		t.Fatalf("expected title in view even with no items:\n%s", viewContent(m.View()))
	}
}

func TestMultiSelect_EmptyItemListEnterFinishes(t *testing.T) {
	m := multiSelectModel{title: "optional empty checklist"}
	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(multiSelectModel)
	if !m.Finished() || m.Canceled() {
		t.Fatalf("empty checklist should accept Enter as an empty selection: finished=%t canceled=%t", m.Finished(), m.Canceled())
	}
	if got := m.CheckedLabels(); len(got) != 0 {
		t.Fatalf("empty checklist selected unexpected items: %v", got)
	}
}

func TestMultiSelect_ViewShowsCheckboxMarks(t *testing.T) {
	m := newTestMultiSelect()
	view := viewContent(m.View())
	if !strings.Contains(view, "[x]") || !strings.Contains(view, "[ ]") {
		t.Fatalf("expected both checked and unchecked marks in view:\n%s", view)
	}
}

func TestMultiSelect_Teatest_HappyPath(t *testing.T) {
	m := screenTestHarness{s: newTestMultiSelect()}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Type("jj") // dns -> ntp -> docker
	tm.Type(" ")  // toggle docker on
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	got := final.(screenTestHarness).s.(multiSelectModel)
	if got.Canceled() {
		t.Fatal("enter should not cancel")
	}
	want := map[string]bool{"dns": false, "ntp": true, "docker": true}
	for _, label := range got.CheckedLabels() {
		if !want[label] {
			t.Fatalf("unexpected checked label %q", label)
		}
	}
}

func TestMultiSelect_Teatest_ResizeMidSessionUpdatesVisibleWindow(t *testing.T) {
	m := screenTestHarness{s: newManyItemMultiSelect(20)}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Send(tea.WindowSizeMsg{Height: 10, Width: 50}) // rows = 4
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return strings.Contains(string(b), "還有 16 項在下面")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc})
	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	if !final.(screenTestHarness).s.(multiSelectModel).Canceled() {
		t.Fatal("expected a clean cancel after resize")
	}
}

func TestMultiSelect_ScreenIDFallsBackWhenUnset(t *testing.T) {
	m := newMultiSelectModel("t", nil)
	if got := m.automationScreenID(); got != "multi-select" {
		t.Fatalf("automationScreenID() = %q, want legacy fallback %q", got, "multi-select")
	}
}

func TestMultiSelect_ScreenIDUsesExplicitID(t *testing.T) {
	m := newMultiSelectModelWithScreenID("hosts.roles_checklist", "t", nil)
	if got := m.automationScreenID(); got != "hosts.roles_checklist" {
		t.Fatalf("automationScreenID() = %q, want %q", got, "hosts.roles_checklist")
	}
}
