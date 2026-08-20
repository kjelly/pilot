package cmd

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kjelly/pilot/internal/tui"
)

// selectItem is one row of a selectModel list. ID is a stable
// automation target that survives Label text/emoji/ordering changes —
// see the "Stable Automation Identity" section of
// docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md.
// It is empty for the many call sites that don't need automation to
// target them by anything other than Label; automationDriver's
// label-based choose() keeps working regardless of whether ID is set.
type selectItem struct {
	ID    string
	Label string
}

// selectModel is an embedded single-select scrollable list screen —
// the router-based replacement for promptui.Select via
// promptSelectIndex. See tui_screen.go for why it never calls
// tea.Quit.
type selectModel struct {
	title       string
	items       []selectItem
	screenID    string
	cursor      int
	windowStart int
	height      int
	query       string
	searching   bool
	confirmed   bool
	canceled    bool
}

// newSelectModel builds a selectModel, dumping the live item list to
// stderr first when PILOT_DEBUG_MENU is set — see dumpMenuDebug
// (deploy.go): several menus' item counts are data-dependent, and this
// is the authoritative source a trec-driven script reads instead of
// recomputing from source or eyeballing the rendered screen.
func newSelectModel(title string, items []string) selectModel {
	return newSelectModelWithScreenID("", title, items)
}

// newSelectModelWithScreenID is newSelectModel plus a stable, contextual
// automationScreenID() — e.g. "hosts.list" instead of the generic
// "select" every selectModel would otherwise report regardless of what
// it's actually showing. screenID may be "" (same as newSelectModel).
func newSelectModelWithScreenID(screenID, title string, items []string) selectModel {
	labeled := make([]selectItem, len(items))
	for i, s := range items {
		labeled[i] = selectItem{Label: s}
	}
	return newSelectModelWithIDs(screenID, title, labeled)
}

// newSelectModelWithIDs is newSelectModelWithScreenID for call sites
// that also need per-item AutomationID targeting (see selectItem).
func newSelectModelWithIDs(screenID, title string, items []selectItem) selectModel {
	if os.Getenv("PILOT_DEBUG_MENU") != "" {
		labels := make([]string, len(items))
		for i, it := range items {
			labels[i] = it.Label
		}
		dumpMenuDebug(title, labels)
	}
	return selectModel{title: title, items: items, screenID: screenID}
}

func (m selectModel) Init() tea.Cmd { return nil }

func (m selectModel) Finished() bool { return m.confirmed || m.canceled }
func (m selectModel) Canceled() bool { return m.canceled }

func (m selectModel) automationScreenID() string {
	if m.screenID != "" {
		return m.screenID
	}
	return "select"
}

func (m selectModel) automationItems() []string {
	labels := make([]string, len(m.items))
	for i, it := range m.items {
		labels[i] = it.Label
	}
	return labels
}

// Selected is the original chosen item's index — valid once Finished() &&
// !Canceled(). The cursor itself is an index into the filtered result set.
func (m selectModel) Selected() int {
	matches := m.matchingIndices()
	if m.cursor < 0 || m.cursor >= len(matches) {
		return -1
	}
	return matches[m.cursor]
}

func (m selectModel) matchingIndices() []int {
	return listFilterIndices(m.automationItems(), m.query)
}

// AutomationState implements tui.Screen. Items reflects the current
// filtered view (Core Invariant 5: filter must not change item stable
// ID, but it does change which items are observable/navigable).
func (m selectModel) AutomationState() tui.AutomationState {
	matches := m.matchingIndices()
	items := make([]tui.AutomationItem, len(matches))
	for i, idx := range matches {
		items[i] = tui.AutomationItem{ID: m.items[idx].ID, Label: m.items[idx].Label}
	}
	focused := -1
	if m.cursor >= 0 && m.cursor < len(matches) {
		focused = m.cursor
	}
	return tui.AutomationState{
		ScreenID:     m.automationScreenID(),
		Kind:         tui.ScreenSelect,
		Title:        m.title,
		Items:        items,
		FocusedIndex: focused,
		FilterActive: m.searching || m.query != "",
	}
}

// SelectedID implements tui.SelectScreen.
func (m selectModel) SelectedID() string {
	idx := m.Selected()
	if idx < 0 || idx >= len(m.items) {
		return ""
	}
	return m.items[idx].ID
}

func (m *selectModel) resetFilterCursor() {
	m.cursor = 0
	m.windowStart = 0
}

func (m selectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.windowStart = listClampWindow(m.cursor, m.windowStart, len(m.matchingIndices()), m.height)
	case tea.KeyMsg:
		if query, searching, handled := updateListSearch(m.query, m.searching, msg); handled {
			if query != m.query {
				m.query = query
				m.resetFilterCursor()
			}
			m.searching = searching
			return m, nil
		}
		matches := m.matchingIndices()
		switch tuiKeyName(msg) {
		case "up", "k":
			m.cursor = listMoveCursor(m.cursor, len(matches), -1)
			m.windowStart = listClampWindow(m.cursor, m.windowStart, len(matches), m.height)
		case "down", "j":
			m.cursor = listMoveCursor(m.cursor, len(matches), 1)
			m.windowStart = listClampWindow(m.cursor, m.windowStart, len(matches), m.height)
		case "enter":
			if len(matches) > 0 {
				m.confirmed = true
			}
		case "esc", "ctrl+c":
			m.canceled = true
		}
	}
	return m, nil
}

func (m selectModel) View() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", m.title)
	b.WriteString("/ 搜尋　↑/↓ 循環移動　enter 選擇　esc 取消\n")
	b.WriteString(listSearchHint(m.query, m.searching) + "\n")

	matches := m.matchingIndices()
	if len(matches) == 0 {
		b.WriteString("\n   沒有符合搜尋條件的項目\n")
		return b.String()
	}

	rows := listVisibleRows(len(matches), m.height)
	end := min(m.windowStart+rows, len(matches))

	if m.windowStart > 0 {
		fmt.Fprintf(&b, "   ▲ 還有 %d 項在上面\n", m.windowStart)
	} else {
		b.WriteString("\n")
	}
	for i := m.windowStart; i < end; i++ {
		cursor := "  "
		if i == m.cursor {
			cursor = "▸ "
		}
		fmt.Fprintf(&b, "%s%s\n", cursor, m.items[matches[i]].Label)
	}
	if end < len(matches) {
		fmt.Fprintf(&b, "   ▼ 還有 %d 項在下面\n", len(matches)-end)
	} else {
		b.WriteString("\n")
	}
	return b.String()
}
