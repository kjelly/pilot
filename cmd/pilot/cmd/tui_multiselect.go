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
	confirmed   bool
	canceled    bool
}

func newMultiSelectModel(title string, items []multiSelectItem) multiSelectModel {
	return multiSelectModel{title: title, items: items}
}

func (m multiSelectModel) Init() tea.Cmd { return nil }

func (m multiSelectModel) Finished() bool { return m.confirmed || m.canceled }
func (m multiSelectModel) Canceled() bool { return m.canceled }

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

func (m multiSelectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.windowStart = listClampWindow(m.cursor, m.windowStart, len(m.items), m.height)
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			m.windowStart = listClampWindow(m.cursor, m.windowStart, len(m.items), m.height)
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
			m.windowStart = listClampWindow(m.cursor, m.windowStart, len(m.items), m.height)
		case " ":
			if len(m.items) > 0 {
				m.items[m.cursor].Checked = !m.items[m.cursor].Checked
			}
		case "enter":
			m.confirmed = true
		case "esc", "ctrl+c":
			m.canceled = true
		}
	}
	return m, nil
}

func (m multiSelectModel) View() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", m.title)
	b.WriteString("↑/↓ 移動　space 勾選/取消　enter 完成　esc 取消\n\n")

	rows := listVisibleRows(len(m.items), m.height)
	end := min(m.windowStart+rows, len(m.items))

	if m.windowStart > 0 {
		fmt.Fprintf(&b, "   ▲ 還有 %d 項在上面\n", m.windowStart)
	} else {
		b.WriteString("\n")
	}
	for i := m.windowStart; i < end; i++ {
		it := m.items[i]
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
	if end < len(m.items) {
		fmt.Fprintf(&b, "   ▼ 還有 %d 項在下面\n", len(m.items)-end)
	} else {
		b.WriteString("\n")
	}
	return b.String()
}
