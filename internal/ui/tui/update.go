// Package tui: Update function — handles all messages and key events.
package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/anomalyco/pilot/internal/agent"
)

// Update implements tea.Model. It is the only place that mutates Model state.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case ThemeDetectedMsg:
		m.dark = msg.Dark
		m.styles = NewStyles(msg.Dark)
		return m, nil

	case RunStartedMsg:
		m.runID = msg.RunID
		m.goal = msg.Goal
		m.iter = 0
		m.proposalCount = 0
		m.pendingCount = 0
		m.chatLines = nil
		m.chatContentBuf.Reset()
		m.chatThinkingBuf.Reset()
		m.chat = ""
		m.activity = nil
		m.appendChat(fmt.Sprintf("▶ Run %s started\n%s\n\n", shortID(msg.RunID), msg.Goal))
		return m, nil

	case RunFinishedMsg:
		m.appendChat(fmt.Sprintf("\n✓ Run %s finished (%s)\n", shortID(msg.RunID), msg.Status))
		m.iter = 0
		m.currentTool = ""
		m.currentHost = ""
		return m, nil

	case StatusUpdateMsg:
		m.iter = msg.Iter
		m.maxIter = msg.MaxIter
		m.proposalCount = msg.ProposalCount
		m.pendingCount = msg.PendingCount
		m.currentTool = msg.CurrentTool
		m.currentHost = msg.CurrentHost
		return m, nil

	case DocsIndexStatusMsg:
		m.docsModuleCount = msg.ModuleCount
		m.docsPlaybookCount = msg.PlaybookCount
		m.docsStale = msg.Stale
		m.docsAnsibleVer = msg.AnsibleVersion
		return m, nil

	case LLMChunkMsg:
		if msg.Thinking != "" {
			m.appendThinking(msg.Thinking)
		}
		if msg.Content != "" {
			m.appendChat(msg.Content)
		}
		if msg.Done {
			m.endStream()
		}
		return m, nil

	case ToolCallMsg:
		m.activity = append(m.activity, activityEntry{Kind: "call", Tool: msg.Tool, Text: msg.Args})
		m.currentTool = msg.Tool
		return m, nil

	case ToolResultMsg:
		m.activity = append(m.activity, activityEntry{Kind: "result", Tool: msg.Tool, Text: msg.Summary, IsErr: msg.IsError})
		return m, nil

	case ProposalRequestMsg:
		m.mode = ModeApproving
		m.approving = msg.Proposal
		m.approvingReply = msg.Reply
		m.modalSelectedIdx = 0
		m.modalExpanded = false
		m.proposalCount++
		m.pendingCount++
		return m, nil

	case AskUserMsg:
		m.mode = ModeAskUser
		m.askingQuestion = msg.Question
		m.askingOptions = msg.Options
		m.askingReply = msg.Reply
		m.askingBuffer = m.askingBuffer[:0]
		return m, nil

	case QuitMsg:
		m.quit = true
		return m, tea.Quit

	case HistoryLoadedMsg:
		m.historyLoading = false
		m.historyErr = msg.Err
		if msg.Err != nil {
			m.historyRuns = nil
			m.selectedProposals = nil
			return m, nil
		}
		m.historyRuns = msg.Runs
		if len(msg.Runs) > 0 {
			if m.selectedRunIdx >= len(msg.Runs) {
				m.selectedRunIdx = len(msg.Runs) - 1
			}
			if m.selectedRunIdx < 0 {
				m.selectedRunIdx = 0
			}
			return m, m.loadProposalsCmd()
		}
		m.selectedProposals = nil
		return m, nil

	case HistoryProposalsLoadedMsg:
		if msg.Err != nil {
			m.selectedProposals = nil
			return m, nil
		}
		// Only apply if the run ID still matches the selected run
		if len(m.historyRuns) > 0 && m.selectedRunIdx < len(m.historyRuns) &&
			m.historyRuns[m.selectedRunIdx].ID == msg.RunID {
			m.selectedProposals = msg.Proposals
		}
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if isQuit(msg) {
		m.quit = true
		return m, tea.Quit
	}

	switch m.mode {
	case ModeApproving:
		return m.handleApproveKey(msg)
	case ModeAskUser:
		return m.handleAskUserKey(msg)
	case ModeHelp:
		// any key dismisses help
		m.mode = ModeRunning
		return m, nil
	case ModeHistory:
		return m.handleHistoryKey(msg)
	default:
		return m.handleMainKey(msg)
	}
}

func (m *Model) handleMainKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if keyMatches(msg, "tab") {
		m.mode = ModeHistory
		m.historyLoading = true
		return m, m.loadHistoryCmd()
	}
	if keyMatches(msg, "t") {
		m.showThinking = !m.showThinking
		m.rebuildChat()
		return m, nil
	}
	if keyMatches(msg, "?") {
		m.mode = ModeHelp
		return m, nil
	}
	return m, nil
}

func (m *Model) handleHistoryKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if keyMatches(msg, "tab") || keyMatches(msg, "esc") {
		m.mode = ModeRunning
		return m, nil
	}
	if keyMatches(msg, "ctrl+r") {
		m.historyLoading = true
		return m, m.loadHistoryCmd()
	}
	if keyMatches(msg, "up") {
		if len(m.historyRuns) > 0 {
			m.selectedRunIdx--
			if m.selectedRunIdx < 0 {
				m.selectedRunIdx = len(m.historyRuns) - 1
			}
			return m, m.loadProposalsCmd()
		}
		return m, nil
	}
	if keyMatches(msg, "down") {
		if len(m.historyRuns) > 0 {
			m.selectedRunIdx++
			if m.selectedRunIdx >= len(m.historyRuns) {
				m.selectedRunIdx = 0
			}
			return m, m.loadProposalsCmd()
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) handleApproveKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Y / N / A directly apply
	if keyMatches(msg, "y") {
		return m, m.sendDecision(agent.DecisionApproved)
	}
	if keyMatches(msg, "Y") {
		return m, m.sendDecision(agent.DecisionApprovedAll)
	}
	if keyMatches(msg, "n") {
		return m, m.sendDecision(agent.DecisionRejected)
	}
	if keyMatches(msg, "a") {
		return m, m.sendDecision(agent.DecisionAbort)
	}
	// ? toggles the expanded details view (full args + dry-run output
	// without truncation).
	if keyMatches(msg, "?") {
		m.modalExpanded = !m.modalExpanded
		return m, nil
	}
	// Arrow keys change selected option for visual feedback
	if keyMatches(msg, "up") || keyMatches(msg, "down") {
		if keyMatches(msg, "up") {
			m.modalSelectedIdx--
		} else {
			m.modalSelectedIdx++
		}
		if m.modalSelectedIdx < 0 {
			m.modalSelectedIdx = 4
		}
		if m.modalSelectedIdx > 4 {
			m.modalSelectedIdx = 0
		}
		return m, nil
	}
	// Enter applies the highlighted option
	if keyMatches(msg, "enter") {
		switch m.modalSelectedIdx {
		case 0:
			return m, m.sendDecision(agent.DecisionApproved)
		case 1:
			return m, m.sendDecision(agent.DecisionApprovedAll)
		case 2:
			return m, m.sendDecision(agent.DecisionRejected)
		case 3:
			return m, nil
		case 4:
			return m, m.sendDecision(agent.DecisionAbort)
		}
	}
	return m, nil
}

func (m *Model) handleAskUserKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// ESC cancels.
	if keyMatches(msg, "esc") {
		return m, m.sendAnswer("(cancelled)")
	}
	// Numbered option selection always wins, regardless of buffer
	// contents. This lets users quickly pick an option even if they
	// started typing.
	if msg.Type == tea.KeyRunes {
		for _, r := range msg.Runes {
			if r >= '1' && r <= '9' {
				idx := int(r - '1')
				if idx < len(m.askingOptions) {
					return m, m.sendAnswer(m.askingOptions[idx])
				}
			}
		}
	}
	// ENTER submits. If options are present, ENTER picks the first
	// (matches the original MVP behaviour). Otherwise ENTER submits
	// whatever is in the free-text buffer.
	if keyMatches(msg, "enter") {
		if len(m.askingOptions) > 0 {
			return m, m.sendAnswer(m.askingOptions[0])
		}
		return m, m.sendAnswer(string(m.askingBuffer))
	}
	// Backspace removes the last rune from the buffer.
	if msg.Type == tea.KeyBackspace {
		if n := len(m.askingBuffer); n > 0 {
			m.askingBuffer = m.askingBuffer[:n-1]
		}
		return m, nil
	}
	// Otherwise: append printable runes to the buffer. Multi-rune keys
	// (e.g. pasted text) are inserted atomically.
	if msg.Type == tea.KeyRunes && len(msg.Runes) > 0 {
		// Drop control characters; keep printable + space + basic
		// punctuation.
		for _, r := range msg.Runes {
			if r == 0 || r == '\n' || r == '\r' || r == '\t' {
				continue
			}
			m.askingBuffer = append(m.askingBuffer, r)
		}
		return m, nil
	}
	return m, nil
}

// sendDecision is a tea.Cmd that sends the chosen decision on the
// proposal's reply channel and returns the model to running mode.
func (m *Model) sendDecision(d agent.Decision) tea.Cmd {
	reply := m.approvingReply
	propID := ""
	if m.approving != nil {
		propID = m.approving.ID
	}
	m.mode = ModeRunning
	m.approving = nil
	m.approvingReply = nil
	m.pendingCount = maxInt(m.pendingCount-1, 0)
	m.modalSelectedIdx = 0
	return func() tea.Msg {
		if reply != nil {
			reply <- d
		}
		// Echo the decision in the activity log via a synthetic message
		_ = propID
		return nil
	}
}

func (m *Model) sendAnswer(ans string) tea.Cmd {
	reply := m.askingReply
	question := m.askingQuestion
	m.mode = ModeRunning
	m.askingReply = nil
	m.askingOptions = nil
	m.askingQuestion = ""
	return func() tea.Msg {
		if reply != nil {
			reply <- ans
		}
		return LLMChunkMsg{Content: fmt.Sprintf("[ask_user] %s → %s\n", truncate(question, 60), ans), Done: true}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n]) + "…"
}
