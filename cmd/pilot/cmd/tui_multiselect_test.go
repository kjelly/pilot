package cmd

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
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
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = next.(multiSelectModel)
	if !m.items[0].Checked {
		t.Fatalf("expected items[0] to be checked after space, got %+v", m.items)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = next.(multiSelectModel)
	if m.items[0].Checked {
		t.Fatalf("expected items[0] to be unchecked after a second space, got %+v", m.items)
	}
}

func TestMultiSelect_DownMovesCursorWithoutResettingOthers(t *testing.T) {
	m := newTestMultiSelect()
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(multiSelectModel)
	if m.cursor != 1 {
		t.Fatalf("cursor = %d, want 1", m.cursor)
	}
	if !m.items[1].Checked {
		t.Fatalf("expected seeded ntp-checked state to survive cursor movement, got %+v", m.items)
	}
}

func TestMultiSelect_CursorClampedAtBounds(t *testing.T) {
	m := newTestMultiSelect()
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = next.(multiSelectModel)
	if m.cursor != 0 {
		t.Fatalf("cursor = %d, want 0 (clamped)", m.cursor)
	}
	for i := 0; i < 10; i++ {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = next.(multiSelectModel)
	}
	if m.cursor != len(m.items)-1 {
		t.Fatalf("cursor = %d, want %d (clamped)", m.cursor, len(m.items)-1)
	}
}

func TestMultiSelect_EnterFinishesWithoutCanceling(t *testing.T) {
	m := newTestMultiSelect()
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
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

func TestMultiSelect_EscCancels(t *testing.T) {
	m := newTestMultiSelect()
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(multiSelectModel)
	if !m.Finished() || !m.Canceled() {
		t.Fatal("expected finished+canceled after esc")
	}
}

func TestMultiSelect_EmptyItemListDoesNotPanic(t *testing.T) {
	m := multiSelectModel{title: "empty"}
	for _, msg := range []tea.Msg{
		tea.KeyMsg{Type: tea.KeyDown},
		tea.KeyMsg{Type: tea.KeyUp},
		tea.KeyMsg{Type: tea.KeySpace},
		tea.WindowSizeMsg{Height: 24, Width: 80},
	} {
		next, _ := m.Update(msg)
		m = next.(multiSelectModel)
	}
	if m.cursor != 0 {
		t.Fatalf("cursor = %d, want 0 for an empty list", m.cursor)
	}
	if !strings.Contains(m.View(), "empty") {
		t.Fatalf("expected title in view even with no items:\n%s", m.View())
	}
}

func TestMultiSelect_ViewShowsCheckboxMarks(t *testing.T) {
	m := newTestMultiSelect()
	view := m.View()
	if !strings.Contains(view, "[x]") || !strings.Contains(view, "[ ]") {
		t.Fatalf("expected both checked and unchecked marks in view:\n%s", view)
	}
}

func TestMultiSelect_Teatest_HappyPath(t *testing.T) {
	m := screenTestHarness{s: newTestMultiSelect()}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Type("jj") // dns -> ntp -> docker
	tm.Type(" ")  // toggle docker on
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

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

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	if !final.(screenTestHarness).s.(multiSelectModel).Canceled() {
		t.Fatal("expected a clean cancel after resize")
	}
}
