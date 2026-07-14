package cmd

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func newTestChecklist() roleChecklistModel {
	return roleChecklistModel{
		title: "test",
		items: []roleChecklistItem{
			{Name: "dns", Checked: false},
			{Name: "ntp", Checked: true},
			{Name: "docker", Checked: false},
		},
	}
}

func newManyItemChecklist(n int) roleChecklistModel {
	items := make([]roleChecklistItem, n)
	for i := range items {
		items[i] = roleChecklistItem{Name: fmt.Sprintf("role-%02d", i)}
	}
	return roleChecklistModel{title: "test", items: items}
}

func TestRoleChecklist_VisibleRows_FallsBackWhenHeightUnknown(t *testing.T) {
	m := newManyItemChecklist(20)
	if got := m.visibleRows(); got != 15 {
		t.Fatalf("visibleRows() = %d, want 15 (fallback default, height unknown)", got)
	}
}

func TestRoleChecklist_VisibleRows_ComputedFromHeight(t *testing.T) {
	m := newManyItemChecklist(20)
	m.height = 10 // chromeLines=6 -> rows = 10-6 = 4
	if got := m.visibleRows(); got != 4 {
		t.Fatalf("visibleRows() = %d, want 4", got)
	}
}

func TestRoleChecklist_VisibleRows_NeverExceedsItemCount(t *testing.T) {
	m := newTestChecklist() // 3 items
	m.height = 100
	if got := m.visibleRows(); got != 3 {
		t.Fatalf("visibleRows() = %d, want 3 (can't exceed the item count)", got)
	}
}

func TestRoleChecklist_VisibleRows_HasAFloorOnTinyTerminals(t *testing.T) {
	m := newManyItemChecklist(20)
	m.height = 1 // 1-6 would be negative without the floor
	if got := m.visibleRows(); got != 3 {
		t.Fatalf("visibleRows() = %d, want the 3-row floor", got)
	}
}

func TestRoleChecklist_WindowFollowsCursorPastBottom(t *testing.T) {
	m := newManyItemChecklist(20)
	next, _ := m.Update(tea.WindowSizeMsg{Height: 10}) // rows = 4
	m = next.(roleChecklistModel)

	for i := 0; i < 6; i++ {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = next.(roleChecklistModel)
	}
	if m.cursor != 6 {
		t.Fatalf("cursor = %d, want 6", m.cursor)
	}
	if m.cursor < m.windowStart || m.cursor >= m.windowStart+m.visibleRows() {
		t.Fatalf("cursor %d fell outside the visible window [%d, %d)", m.cursor, m.windowStart, m.windowStart+m.visibleRows())
	}
	if m.windowStart == 0 {
		t.Fatal("expected the window to have scrolled down from the top")
	}
}

func TestRoleChecklist_WindowScrollsBackUp(t *testing.T) {
	m := newManyItemChecklist(20)
	next, _ := m.Update(tea.WindowSizeMsg{Height: 10}) // rows = 4
	m = next.(roleChecklistModel)
	for i := 0; i < 10; i++ {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = next.(roleChecklistModel)
	}
	for i := 0; i < 10; i++ {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
		m = next.(roleChecklistModel)
	}
	if m.cursor != 0 {
		t.Fatalf("cursor = %d, want 0", m.cursor)
	}
	if m.windowStart != 0 {
		t.Fatalf("windowStart = %d, want 0 after scrolling all the way back up", m.windowStart)
	}
}

func TestRoleChecklist_ViewShowsScrollIndicatorsOnlyWhenClipped(t *testing.T) {
	m := newManyItemChecklist(20)
	next, _ := m.Update(tea.WindowSizeMsg{Height: 10}) // rows = 4
	m = next.(roleChecklistModel)

	view := m.View()
	if strings.Contains(view, "還有") && m.windowStart == 0 {
		// at the top: no "more above" indicator expected, but "more below" is fine
		if strings.Count(view, "還有") != 1 {
			t.Fatalf("expected exactly one scroll indicator at the top of the list, got:\n%s", view)
		}
	}
	if !strings.Contains(view, "還有 16 項在下面") {
		t.Fatalf("expected a below-indicator reporting the remaining 16 items, got:\n%s", view)
	}

	for i := 0; i < 10; i++ {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = next.(roleChecklistModel)
	}
	view = m.View()
	if !strings.Contains(view, "還有") || !strings.Contains(view, "在上面") {
		t.Fatalf("expected an above-indicator after scrolling down, got:\n%s", view)
	}
}

func TestRoleChecklist_SpaceTogglesItemUnderCursor(t *testing.T) {
	m := newTestChecklist()

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = next.(roleChecklistModel)
	if !m.items[0].Checked {
		t.Fatalf("expected items[0] (cursor start) to be checked after space, got %+v", m.items)
	}

	next, _ = m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = next.(roleChecklistModel)
	if m.items[0].Checked {
		t.Fatalf("expected items[0] to be unchecked after a second space, got %+v", m.items)
	}
}

func TestRoleChecklist_DownMovesCursorWithoutResettingOthers(t *testing.T) {
	m := newTestChecklist()

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(roleChecklistModel)
	if m.cursor != 1 {
		t.Fatalf("cursor = %d, want 1", m.cursor)
	}
	// the seeded "ntp" checked state must survive cursor movement
	if !m.items[1].Checked {
		t.Fatalf("expected items[1] (ntp) to remain checked after moving, got %+v", m.items)
	}

	next, _ = m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = next.(roleChecklistModel)
	if m.items[1].Checked {
		t.Fatalf("expected space at cursor=1 to uncheck ntp, got %+v", m.items)
	}
}

func TestRoleChecklist_CursorClampedAtBounds(t *testing.T) {
	m := newTestChecklist()

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp}) // already at 0
	m = next.(roleChecklistModel)
	if m.cursor != 0 {
		t.Fatalf("cursor = %d, want 0 (clamped)", m.cursor)
	}

	for i := 0; i < 10; i++ {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = next.(roleChecklistModel)
	}
	if m.cursor != len(m.items)-1 {
		t.Fatalf("cursor = %d, want %d (clamped)", m.cursor, len(m.items)-1)
	}
}

func TestRoleChecklist_EnterQuitsWithoutCanceling(t *testing.T) {
	m := newTestChecklist()
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(roleChecklistModel)
	if m.canceled {
		t.Fatal("enter should not set canceled")
	}
	if cmd == nil {
		t.Fatal("expected enter to return tea.Quit")
	}
}

func TestRoleChecklist_EscCancels(t *testing.T) {
	m := newTestChecklist()
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(roleChecklistModel)
	if !m.canceled {
		t.Fatal("esc should set canceled")
	}
	if cmd == nil {
		t.Fatal("expected esc to return tea.Quit")
	}
}

func TestRoleChecklist_CtrlCCancels(t *testing.T) {
	m := newTestChecklist()
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	m = next.(roleChecklistModel)
	if !m.canceled {
		t.Fatal("ctrl+c should set canceled")
	}
	if cmd == nil {
		t.Fatal("expected ctrl+c to return tea.Quit")
	}
}

func TestRoleChecklist_InitialViewShowsTitleAndHelp(t *testing.T) {
	m := newTestChecklist()
	m.title = "主機 \"web-1\" 的角色"
	view := m.View()

	for _, want := range []string{
		"主機 \"web-1\" 的角色",
		"↑/↓ 移動",
		"space 勾選/取消",
		"enter 完成",
		"esc 取消",
		"dns",
		"ntp",
		"docker",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("view does not contain %q\nview:\n%s", want, view)
		}
	}
	if !strings.Contains(view, "[x]") || !strings.Contains(view, "[ ]") {
		t.Fatalf("expected both checked and unchecked marks in view:\n%s", view)
	}
}

func TestRoleChecklist_EmptyItemListDoesNotPanic(t *testing.T) {
	m := roleChecklistModel{title: "empty"}

	view := m.View()
	if !strings.Contains(view, "empty") {
		t.Fatalf("expected title in view even with no items, got:\n%s", view)
	}

	for _, msg := range []tea.Msg{
		tea.KeyMsg{Type: tea.KeyDown},
		tea.KeyMsg{Type: tea.KeyUp},
		tea.KeyMsg{Type: tea.KeySpace},
		tea.WindowSizeMsg{Height: 24, Width: 80},
	} {
		next, _ := m.Update(msg)
		m = next.(roleChecklistModel)
	}
	if m.cursor != 0 {
		t.Fatalf("cursor = %d, want 0 for an empty list", m.cursor)
	}
}

func TestRoleChecklist_NonKeyMsgIsIgnored(t *testing.T) {
	m := newTestChecklist()
	next, cmd := m.Update(struct{}{})
	if cmd != nil {
		t.Fatal("expected no command for a non-key message")
	}
	if got := next.(roleChecklistModel); got.cursor != m.cursor {
		t.Fatalf("state should be unchanged for a non-key message, got cursor=%d", got.cursor)
	}
}
