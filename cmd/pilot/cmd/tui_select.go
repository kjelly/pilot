package cmd

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// selectModel is an embedded single-select scrollable list screen —
// the router-based replacement for promptui.Select via
// promptSelectIndex. See tui_screen.go for why it never calls
// tea.Quit.
type selectModel struct {
	title       string
	items       []string
	cursor      int
	windowStart int
	height      int
	confirmed   bool
	canceled    bool
}

// newSelectModel builds a selectModel, dumping the live item list to
// stderr first when PILOT_DEBUG_MENU is set — see dumpMenuDebug
// (deploy.go): several menus' item counts are data-dependent, and this
// is the authoritative source a trec-driven script reads instead of
// recomputing from source or eyeballing the rendered screen.
func newSelectModel(title string, items []string) selectModel {
	if os.Getenv("PILOT_DEBUG_MENU") != "" {
		dumpMenuDebug(title, items)
	}
	return selectModel{title: title, items: items}
}

func (m selectModel) Init() tea.Cmd { return nil }

func (m selectModel) Finished() bool { return m.confirmed || m.canceled }
func (m selectModel) Canceled() bool { return m.canceled }

func (m selectModel) automationScreenID() string { return "select" }

func (m selectModel) automationItems() []string { return append([]string(nil), m.items...) }

// Selected is the chosen item's index — valid once Finished() &&
// !Canceled().
func (m selectModel) Selected() int { return m.cursor }

func (m selectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
		case "enter":
			if len(m.items) > 0 {
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
	b.WriteString("↑/↓ 移動　enter 選擇　esc 取消\n\n")

	rows := listVisibleRows(len(m.items), m.height)
	end := min(m.windowStart+rows, len(m.items))

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
		fmt.Fprintf(&b, "%s%s\n", cursor, m.items[i])
	}
	if end < len(m.items) {
		fmt.Fprintf(&b, "   ▼ 還有 %d 項在下面\n", len(m.items)-end)
	} else {
		b.WriteString("\n")
	}
	return b.String()
}
