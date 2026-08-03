package cmd

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// multiSelectItem is one row of a multiSelectModel checklist.
type multiSelectItem struct {
	Label       string
	Description string
	Checked     bool
}

// multiSelectModel is an embedded multi-select (checkbox) scrollable
// list screen — the generic form of what edit_role_checklist.go's
// roleChecklistModel implemented one-off for the role checklist,
// reusable anywhere a "toggle several of these" screen is needed. See
// tui_screen.go for why it never calls tea.Quit.
type multiSelectModel struct {
	title       string
	items       []multiSelectItem
	cursor      int
	windowStart int
	height      int
	query       string
	searching   bool
	confirmed   bool
	canceled    bool
}

func newMultiSelectModel(title string, items []multiSelectItem) multiSelectModel {
	return multiSelectModel{title: title, items: items}
}

func (m multiSelectModel) Init() tea.Cmd { return nil }

func (m multiSelectModel) Finished() bool { return m.confirmed || m.canceled }
func (m multiSelectModel) Canceled() bool { return m.canceled }

func (m multiSelectModel) automationScreenID() string { return "multi-select" }

func (m multiSelectModel) automationItems() []string {
	items := make([]string, len(m.items))
	for i, item := range m.items {
		items[i] = item.Label
	}
	return items
}

// CheckedLabels returns the Label of every checked item, in item
// order — valid once Finished() && !Canceled().
func (m multiSelectModel) CheckedLabels() []string {
	var out []string
	for _, it := range m.items {
		if it.Checked {
			out = append(out, it.Label)
		}
	}
	return out
}

func (m multiSelectModel) matchingIndices() []int {
	items := make([]string, len(m.items))
	for i, item := range m.items {
		items[i] = item.Label + " " + item.Description
	}
	return listFilterIndices(items, m.query)
}

func (m *multiSelectModel) resetFilterCursor() {
	m.cursor = 0
	m.windowStart = 0
}

func (m multiSelectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
		case " ":
			if len(matches) > 0 {
				itemIndex := matches[m.cursor]
				m.items[itemIndex].Checked = !m.items[itemIndex].Checked
			}
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

func (m multiSelectModel) View() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", m.title)
	b.WriteString("/ 搜尋　↑/↓ 循環移動　space 勾選/取消　enter 完成　esc 取消\n")
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
		it := m.items[matches[i]]
		cursor := "  "
		if i == m.cursor {
			cursor = "▸ "
		}
		mark := "[ ]"
		if it.Checked {
			mark = "[x]"
		}
		fmt.Fprintf(&b, "%s%s %-24s %s\n", cursor, mark, it.Label, it.Description)
	}
	if end < len(matches) {
		fmt.Fprintf(&b, "   ▼ 還有 %d 項在下面\n", len(matches)-end)
	} else {
		b.WriteString("\n")
	}
	return b.String()
}
