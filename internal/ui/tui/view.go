// Package tui: View function — renders the model to a string.
package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// View implements tea.Model. Returns the string the terminal will display.
func (m *Model) View() string {
	if m.quit {
		return ""
	}
	if m.width == 0 {
		// Not yet sized — render a minimal placeholder
		return "Initialising pilot TUI…"
	}

	switch m.mode {
	case ModeApproving:
		return m.viewApproveModal()
	case ModeAskUser:
		return m.viewAskUserModal()
	case ModeHelp:
		return m.viewHelp()
	case ModeHistory:
		return m.viewHistory()
	default:
		return m.viewMain()
	}
}

func (m *Model) viewMain() string {
	// Layout:
	//   +-----------------------+--------------------+
	//   | Chat (LLM stream)     |  Proposal pane     |
	//   |                       |  (last activity +  |
	//   |                       |   status)          |
	//   +-----------------------+--------------------+
	//   | status bar                                    |
	//   +-----------------------------------------------+
	//
	// Width split 60/40 minus borders.

	statusH := 1
	bodyH := m.height - statusH - 2 // borders
	if bodyH < 5 {
		bodyH = 5
	}
	leftW := m.width * 6 / 10
	if leftW < 30 {
		leftW = 30
	}
	rightW := m.width - leftW - 2 // borders
	if rightW < 24 {
		rightW = 24
	}
	leftInner := leftW - 4 // padding + border
	rightInner := rightW - 4

	chatView := m.renderChatPane(leftInner, bodyH-2)
	rightView := m.renderRightPane(rightInner, bodyH-2)
	statusView := m.renderStatusBar()

	row := lipgloss.JoinHorizontal(lipgloss.Top, chatView, rightView)
	return lipgloss.JoinVertical(lipgloss.Left, row, statusView)
}

func (m *Model) renderChatPane(width, height int) string {
	title := m.styles.PaneTitleChat.Render("💬 Chat / LLM stream")
	body := truncateToHeight(m.chat, height-2)
	if body == "" {
		body = lipgloss.NewStyle().Foreground(m.styles.Palette.Muted).Render("Waiting for first response…")
	}
	content := title + "\n" + body
	return m.styles.ChatPane.Width(width).Height(height).Render(content)
}

func (m *Model) renderRightPane(width, height int) string {
	var sb strings.Builder
	sb.WriteString(m.styles.PaneTitle.Render("📋 Activity"))
	sb.WriteString("\n\n")
	if len(m.activity) == 0 {
		sb.WriteString(lipgloss.NewStyle().Foreground(m.styles.Palette.Muted).Render("(no tool calls yet)"))
	} else {
		// Show last few activity entries that fit
		max := height - 4
		if max < 1 {
			max = 1
		}
		start := 0
		if len(m.activity) > max {
			start = len(m.activity) - max
		}
		for _, a := range m.activity[start:] {
			sb.WriteString(m.renderActivityEntry(a, width-4))
			sb.WriteString("\n")
		}
	}
	if m.pendingCount > 0 {
		sb.WriteString("\n")
		sb.WriteString(m.styles.PillPending.Render(fmt.Sprintf(" %d pending ", m.pendingCount)))
	}
	return m.styles.ProposalPane.Width(width).Height(height).Render(sb.String())
}

func (m *Model) renderActivityEntry(a activityEntry, width int) string {
	switch a.Kind {
	case "call":
		label := m.styles.ToolLabel.Render("▶ " + a.Tool)
		text := a.Text
		if len(text) > width-2 {
			text = truncateToHeight(text, 2)
		}
		return label + "\n" + m.styles.Diff.Render(text)
	case "result":
		marker := "✓"
		color := m.styles.Palette.ToolResult
		if a.IsErr {
			marker = "✗"
			color = m.styles.Palette.ToolError
		}
		label := lipgloss.NewStyle().Bold(true).Foreground(color).Render(marker + " " + a.Tool)
		text := a.Text
		if len(text) > width {
			text = truncateToHeight(text, 3)
		}
		return label + "\n" + m.styles.Diff.Render(text)
	}
	return a.Text
}

func (m *Model) renderStatusBar() string {
	parts := []string{
		fmt.Sprintf("iter %d/%d", m.iter, m.maxIter),
		fmt.Sprintf("proposals %d", m.proposalCount),
	}
	if m.pendingCount > 0 {
		parts = append(parts, m.styles.PillPending.Render(fmt.Sprintf(" %d pending ", m.pendingCount)))
	}
	if m.currentTool != "" {
		parts = append(parts, "tool: "+m.currentTool)
	}
	if m.currentHost != "" {
		parts = append(parts, "host: "+m.currentHost)
	}
	if m.docsModuleCount > 0 {
		docsLabel := fmt.Sprintf("📚 docs: %d", m.docsModuleCount)
		if m.docsPlaybookCount > 0 {
			docsLabel += fmt.Sprintf("+%d", m.docsPlaybookCount)
		}
		if m.docsStale {
			docsLabel += " (stale)"
		}
		parts = append(parts, docsLabel)
	}
	left := strings.Join(parts, "   ")
	right := HelpLine(m.keymap.KeysFor("main"))
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		gap = 1
	}
	return m.styles.StatusBar.Width(m.width).Render(left + strings.Repeat(" ", gap) + right)
}

// Modal views ---------------------------------------------------------------

func (m *Model) viewApproveModal() string {
	if m.approving == nil {
		return m.viewMain()
	}
	p := m.approving

	// Header
	title := m.styles.ModalTitle.Render("📋  AI 提案  #" + shortID(p.ID))

	// Metadata lines
	host := p.Host
	if host == "" {
		host = "(any host)"
	}
	hostLine := fmt.Sprintf("主機:    %s", host)
	toolLine := fmt.Sprintf("工具:    %s", p.Tool)
	riskLine := fmt.Sprintf("風險:    %s", m.styles.Risk(p.RiskLevel).Render(strings.ToUpper(p.RiskLevel)))
	cisLine := ""
	if p.CISControl != "" {
		cisLine = fmt.Sprintf("CIS:     %s", p.CISControl)
	}
	revLine := fmt.Sprintf("可逆:    %s", yesNo(p.Reversible))

	// Rationale
	rationaleLabel := m.styles.ModalTitle.Render("💭 理由:")
	rationale := m.styles.Rationale.Render(wordWrap(p.Rationale, 60))

	// Dry run output. Expanded view shows the full output without
	// truncation; collapsed view keeps the first 800 chars.
	dryRun := ""
	if p.DryRunOutput != "" {
		dryOut := p.DryRunOutput
		if !m.modalExpanded {
			dryOut = truncate(dryOut, 800)
		}
		dryRun = m.styles.ModalTitle.Render("🔍 預演輸出:") + "\n" +
			m.styles.Diff.Render(wordWrap(dryOut, 60))
	}

	// Args. Same pattern.
	argsText := string(p.Args)
	if !m.modalExpanded {
		argsText = truncate(argsText, 400)
	}
	args := m.styles.ModalTitle.Render("📦 參數:") + "\n" +
		m.styles.Diff.Render(argsText)

	// Options
	options := []string{"✓ 批准並執行 (y)", "✓ 批准後續所有提案 (Y)", "✗ 拒絕跳過 (n)", "🔧 顯示完整細節 (?)", "⛔ 中止整個 run (a)"}
	detailsLabel := "🔧 顯示完整細節 (?)"
	if m.modalExpanded {
		detailsLabel = "🔧 收合細節 (?)"
	}
	options[3] = detailsLabel
	var optLines []string
	for i, opt := range options {
		if i == m.modalSelectedIdx {
			optLines = append(optLines, m.styles.ModalActive.Render("▶ "+opt))
		} else {
			optLines = append(optLines, m.styles.ModalOption.Render("  "+opt))
		}
	}
	opts := strings.Join(optLines, "\n")

	content := strings.Join([]string{
		title,
		strings.Repeat("─", 60),
		hostLine,
		toolLine,
		riskLine,
		cisLine,
		revLine,
		"",
		rationaleLabel,
		rationale,
		"",
		dryRun,
		"",
		args,
		"",
		strings.Repeat("─", 60),
		opts,
		"",
		HelpLine(m.keymap.KeysFor("approve")),
	}, "\n")

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
		m.styles.Modal.Width(minInt(80, m.width-4)).Render(content))
}

func (m *Model) viewAskUserModal() string {
	title := m.styles.ModalTitle.Render("❓ " + m.askingQuestion)
	var body strings.Builder
	body.WriteString(title)
	body.WriteString("\n\n")
	if len(m.askingOptions) > 0 {
		for i, opt := range m.askingOptions {
			fmt.Fprintf(&body, "  %d) %s\n", i+1, opt)
		}
	} else {
		body.WriteString(lipgloss.NewStyle().Foreground(m.styles.Palette.Muted).Render("(type your answer, ENTER to submit, esc to cancel)"))
		// Show the in-progress buffer so the user sees what they're typing.
		if len(m.askingBuffer) > 0 {
			bufferLine := "> " + string(m.askingBuffer) + "▏"
			body.WriteString("\n\n")
			body.WriteString(m.styles.Rationale.Render(bufferLine))
		}
	}
	body.WriteString("\n")
	body.WriteString(HelpLine(m.keymap.KeysFor("ask")))
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
		m.styles.Modal.Width(minInt(60, m.width-4)).Render(body.String()))
}

func (m *Model) viewHelp() string {
	title := m.styles.ModalTitle.Render("pilot TUI — key bindings")
	lines := []string{
		"",
		"Global:  ? help  ·  t toggle thinking  ·  tab history  ·  ctrl+c quit",
		"",
		"Approval modal:",
		"  y approve   n reject   ? details   a abort",
		"  ↑/↓ navigate options, enter to apply",
		"",
		"Ask user:",
		"  1-9 select option, enter = first option",
		"  esc to cancel",
		"",
		"History mode:",
		"  ↑/↓ select run   ctrl+r refresh   tab/esc back",
		"",
		"(press any key to return)",
	}
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
		m.styles.Modal.Width(minInt(70, m.width-4)).Render(title+"\n"+strings.Join(lines, "\n")))
}

// Helpers -------------------------------------------------------------------

func shortID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}

func yesNo(b bool) string {
	if b {
		return "✓ yes"
	}
	return "✗ no"
}

func wordWrap(s string, w int) string {
	if s == "" {
		return ""
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		words := strings.Fields(line)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := words[0]
		for _, word := range words[1:] {
			if len(cur)+1+len(word) > w {
				out = append(out, cur)
				cur = word
			} else {
				cur += " " + word
			}
		}
		out = append(out, cur)
	}
	return strings.Join(out, "\n")
}

func truncateToHeight(s string, maxLines int) string {
	if s == "" || maxLines <= 0 {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= maxLines {
		return s
	}
	return strings.Join(lines[len(lines)-maxLines:], "\n")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m *Model) viewHistory() string {
	statusH := 1
	bodyH := m.height - statusH - 2 // borders
	if bodyH < 5 {
		bodyH = 5
	}
	leftW := m.width * 4 / 10
	if leftW < 30 {
		leftW = 30
	}
	rightW := m.width - leftW - 2
	if rightW < 24 {
		rightW = 24
	}
	leftInner := leftW - 4
	rightInner := rightW - 4

	leftView := m.renderHistoryRunsPane(leftInner, bodyH-2)
	rightView := m.renderHistoryDetailsPane(rightInner, bodyH-2)
	statusView := m.renderHistoryStatusBar()

	row := lipgloss.JoinHorizontal(lipgloss.Top, leftView, rightView)
	return lipgloss.JoinVertical(lipgloss.Left, row, statusView)
}

func (m *Model) renderHistoryRunsPane(width, height int) string {
	title := m.styles.PaneTitleChat.Render("歷史執行紀錄 (Runs)")
	var sb strings.Builder

	if m.historyLoading {
		sb.WriteString(lipgloss.NewStyle().Foreground(m.styles.Palette.Muted).Render("⏳ 載入中…"))
	} else if m.historyErr != nil {
		errStyle := lipgloss.NewStyle().Foreground(m.styles.Palette.ToolError)
		sb.WriteString(errStyle.Render(fmt.Sprintf("載入失敗: %v", m.historyErr)))
	} else if len(m.historyRuns) == 0 {
		sb.WriteString(lipgloss.NewStyle().Foreground(m.styles.Palette.Muted).Render("(無執行紀錄)"))
	} else {
		// Calculate visible window so the selected run is always on-screen.
		visibleLines := height - 4 // reserve for title + padding
		if visibleLines < 3 {
			visibleLines = 3
		}
		start := 0
		if m.selectedRunIdx >= visibleLines {
			start = m.selectedRunIdx - visibleLines + 1
		}
		end := start + visibleLines
		if end > len(m.historyRuns) {
			end = len(m.historyRuns)
			start = end - visibleLines
			if start < 0 {
				start = 0
			}
		}

		if start > 0 {
			sb.WriteString(lipgloss.NewStyle().Foreground(m.styles.Palette.Muted).Render(
				fmt.Sprintf("  ↑ %d more…", start)))
			sb.WriteString("\n")
		}

		for i := start; i < end; i++ {
			r := m.historyRuns[i]
			statusMarker := "▶"
			switch r.Status {
			case "finished", "success":
				statusMarker = "✓"
			case "failed":
				statusMarker = "✗"
			}

			playbookName := filepath.Base(r.Playbook)
			if playbookName == "." || playbookName == "" {
				playbookName = "unknown"
			}
			runLine := fmt.Sprintf("%s %s (%s)", statusMarker, shortID(r.ID), playbookName)

			if i == m.selectedRunIdx {
				sb.WriteString(m.styles.ModalActive.Render("▶ " + runLine))
			} else {
				sb.WriteString(m.styles.ModalOption.Render("  " + runLine))
			}
			sb.WriteString("\n")
		}

		if end < len(m.historyRuns) {
			sb.WriteString(lipgloss.NewStyle().Foreground(m.styles.Palette.Muted).Render(
				fmt.Sprintf("  ↓ %d more…", len(m.historyRuns)-end)))
			sb.WriteString("\n")
		}
	}
	content := title + "\n\n" + sb.String()
	return m.styles.ChatPane.Width(width).Height(height).Render(content)
}

func (m *Model) renderHistoryDetailsPane(width, height int) string {
	title := m.styles.PaneTitle.Render("📋 執行詳情 (Details)")
	var sb strings.Builder

	if len(m.historyRuns) == 0 || m.selectedRunIdx >= len(m.historyRuns) {
		sb.WriteString(lipgloss.NewStyle().Foreground(m.styles.Palette.Muted).Render("請選擇一個執行紀錄來查看詳情。"))
	} else {
		r := m.historyRuns[m.selectedRunIdx]
		// General Run Info
		fmt.Fprintf(&sb, "Run ID:   %s\n", r.ID)
		fmt.Fprintf(&sb, "開始時間: %s\n", r.StartedAt.Format("2006-01-02 15:04:05"))
		if r.FinishedAt != nil {
			fmt.Fprintf(&sb, "結束時間: %s\n", r.FinishedAt.Format("2006-01-02 15:04:05"))
		}
		fmt.Fprintf(&sb, "執行模式: %s\n", r.Mode)
		fmt.Fprintf(&sb, "Playbook: %s\n", r.Playbook)
		fmt.Fprintf(&sb, "Inventory:%s\n", r.Inventory)
		fmt.Fprintf(&sb, "狀態:     %s\n", r.Status)
		if r.Error != "" {
			errStyle := lipgloss.NewStyle().Foreground(m.styles.Palette.ToolError)
			sb.WriteString(errStyle.Render(fmt.Sprintf("錯誤:     %s\n", r.Error)))
		}

		sb.WriteString("\n" + m.styles.PaneTitle.Render("🔧 提案紀錄 (Proposals)") + "\n")
		if len(m.selectedProposals) == 0 {
			sb.WriteString(lipgloss.NewStyle().Foreground(m.styles.Palette.Muted).Render("(無提案)"))
		} else {
			for _, p := range m.selectedProposals {
				statusMarker := "⏳"
				switch p.Status {
				case "approved":
					statusMarker = "✓"
				case "rejected":
					statusMarker = "✗"
				}
				fmt.Fprintf(&sb, "  %s 主機:%s, 工具:%s, 風險:%s\n", statusMarker, p.Host, p.Tool, p.RiskLevel)
				if p.Rationale != "" {
					wrapped := wordWrap(p.Rationale, width-6)
					// Indent rationale
					lines := strings.Split(wrapped, "\n")
					for _, line := range lines {
						sb.WriteString("     " + m.styles.Diff.Render(line) + "\n")
					}
				}
			}
		}
	}
	body := truncateToHeightTop(sb.String(), height-2)
	content := title + "\n\n" + body
	return m.styles.ProposalPane.Width(width).Height(height).Render(content)
}

func (m *Model) renderHistoryStatusBar() string {
	left := m.styles.PaneTitle.Render("📜 HISTORY DASHBOARD")
	right := HelpLine(m.keymap.KeysFor("history"))
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		gap = 1
	}
	return m.styles.StatusBar.Width(m.width).Render(left + strings.Repeat(" ", gap) + right)
}

func truncateToHeightTop(s string, maxLines int) string {
	if s == "" || maxLines <= 0 {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= maxLines {
		return s
	}
	return strings.Join(lines[:maxLines], "\n")
}
