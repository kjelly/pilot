// edit_role_checklist.go implements a small, one-off Bubble Tea
// screen for editing a host's roles: arrow keys move, space toggles
// the role under the cursor, enter confirms. It replaces cycling
// through promptui.Select one role at a time — that approach reopens
// a brand new Select after every toggle, which always redraws with
// the cursor back at the first item, making it slow and disorienting
// once you've scrolled a few rows down. Bubble Tea keeps one
// continuous render loop instead, so the cursor stays exactly where
// the user left it between toggles.
package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type roleChecklistItem struct {
	Name        string
	Description string
	Checked     bool
}

// chromeLines is how many lines View() spends on the title, help
// text, and the two scroll-indicator rows (always reserved, even when
// blank, so the visible item count doesn't jump around as the window
// scrolls) — subtracted from the terminal height to size the
// scrollable item window.
const chromeLines = 6

type roleChecklistModel struct {
	title       string
	items       []roleChecklistItem
	cursor      int
	windowStart int
	height      int // terminal rows; 0 until the first tea.WindowSizeMsg arrives
	canceled    bool
}

func (m roleChecklistModel) Init() tea.Cmd { return nil }

// visibleRows is how many item rows fit on screen at once. Before the
// terminal size is known (height == 0, i.e. no WindowSizeMsg yet) it
// falls back to a reasonable default rather than aggressively
// clamping to a tiny window on the first frame.
func (m roleChecklistModel) visibleRows() int {
	if m.height == 0 {
		return min(len(m.items), 15)
	}
	return min(len(m.items), max(m.height-chromeLines, 3))
}

// clampWindow keeps the cursor inside [windowStart, windowStart+rows)
// and windowStart inside a valid range — called after every cursor
// move or resize so scrolling follows the cursor instead of leaving
// it to run off either edge of the visible window.
func (m *roleChecklistModel) clampWindow() {
	rows := m.visibleRows()
	if m.cursor < m.windowStart {
		m.windowStart = m.cursor
	}
	if m.cursor >= m.windowStart+rows {
		m.windowStart = m.cursor - rows + 1
	}
	m.windowStart = min(m.windowStart, max(len(m.items)-rows, 0))
	m.windowStart = max(m.windowStart, 0)
}

func (m roleChecklistModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.clampWindow()
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			m.clampWindow()
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
			m.clampWindow()
		case " ":
			if len(m.items) > 0 {
				m.items[m.cursor].Checked = !m.items[m.cursor].Checked
			}
		case "enter":
			return m, tea.Quit
		case "esc", "ctrl+c":
			m.canceled = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m roleChecklistModel) View() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", m.title)
	b.WriteString("↑/↓ 移動　space 勾選/取消　enter 完成　esc 取消\n\n")

	rows := m.visibleRows()
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
		fmt.Fprintf(&b, "%s%s %-24s %s\n", cursor, mark, it.Name, it.Description)
	}
	if end < len(m.items) {
		fmt.Fprintf(&b, "   ▼ 還有 %d 項在下面\n", len(m.items)-end)
	} else {
		b.WriteString("\n")
	}
	return b.String()
}

// promptRoleChecklist runs the checklist screen seeded with selected
// already checked, and returns the sorted list of checked role names.
// Returns errDeployAborted (the same sentinel promptSelectIndex/
// promptText use for Ctrl-C) if the user cancels with esc/Ctrl-C
// instead of confirming with enter — the caller should treat that as
// "no change", not a hard failure.
func promptRoleChecklist(title string, roles []struct{ Name, Description string }, selected []string) ([]string, error) {
	items := make([]roleChecklistItem, len(roles))
	for i, r := range roles {
		items[i] = roleChecklistItem{Name: r.Name, Description: r.Description, Checked: hasRole(selected, r.Name)}
	}
	m := roleChecklistModel{title: title, items: items}

	final, err := tea.NewProgram(m, tea.WithOutput(os.Stdout)).Run()
	if err != nil {
		return nil, fmt.Errorf("角色勾選畫面失敗: %w", err)
	}
	fm := final.(roleChecklistModel)
	if fm.canceled {
		return nil, errDeployAborted
	}

	var out []string
	for _, it := range fm.items {
		if it.Checked {
			out = append(out, it.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}
