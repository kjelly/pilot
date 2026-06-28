// Package tui: bubbletea Model — the state machine root.
package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/anomalyco/pilot/internal/agent"
	"github.com/anomalyco/pilot/internal/store"
)

// Mode enumerates the high-level states of the TUI.
type Mode int

const (
	ModeRunning Mode = iota
	ModeApproving
	ModeAskUser
	ModeHelp
	ModeHistory
)

// Model is the bubbletea model for the pilot TUI.
type Model struct {
	// Configuration
	width  int
	height int
	styles *Styles
	keymap Keymap

	// State
	mode   Mode
	dark   bool
	quit   bool
	showThinking bool

	// Run metadata
	runID   string
	goal    string

	// Counters for status bar
	iter          int
	maxIter       int
	proposalCount int
	pendingCount  int
	currentTool   string
	currentHost   string

	// Docs index status
	docsModuleCount   int
	docsPlaybookCount int
	docsStale         bool
	docsAnsibleVer    string

	// Chat pane — accumulating LLM stream
	chatLines       []string
	chatThinkingBuf strings.Builder
	chatContentBuf  strings.Builder
	chat            string // rendered text

	// Activity log: tool calls and results
	activity []activityEntry

	// Approval modal
	approving        *agent.Proposal
	approvingReply   chan agent.Decision
	modalSelectedIdx int // for the option list (0=approve,1=reject,2=details,3=abort)
	modalExpanded bool  // true when the user has pressed '?' to view full details

	// Ask user modal
	askingQuestion string
	askingOptions  []string
	askingReply    chan string
	askingBuffer   []rune // accumulates the user's typed answer for free-text questions

	// Last error
	lastErr string

	// History state
	store             *store.Store
	historyRuns       []*store.Run
	historyErr        error
	historyLoading    bool
	selectedRunIdx    int
	selectedProposals []*store.Proposal
}

type activityEntry struct {
	Kind   string // "call" or "result" or "error"
	Tool   string
	Text   string
	IsErr  bool
}

func newModel(st *store.Store) *Model {
	dark := DetectTheme()
	return &Model{
		styles:        NewStyles(dark),
		keymap:        defaultKeymap,
		mode:          ModeRunning,
		dark:          dark,
		showThinking:  false,
		maxIter:       20,
		modalSelectedIdx: 0,
		store:         st,
	}
}

// Init implements tea.Model. We send a ThemeDetectedMsg so styles can
// update on first run if we ever want to allow live theme switching.
func (m *Model) Init() tea.Cmd {
	return func() tea.Msg {
		return ThemeDetectedMsg{Dark: DetectTheme()}
	}
}

// SetSize is called by the Program on window resize.
func (m *Model) SetSize(w, h int) {
	m.width = w
	m.height = h
}

func (m *Model) appendChat(s string) {
	m.chatContentBuf.WriteString(s)
	m.rebuildChat()
}

func (m *Model) appendThinking(s string) {
	m.chatThinkingBuf.WriteString(s)
	m.rebuildChat()
}

func (m *Model) endStream() {
	// When the model finishes a turn we want to keep a clean separator
	// between turns. Just append a blank line; the renderer is plain text.
	if m.chatContentBuf.Len() > 0 {
		m.chatContentBuf.WriteString("\n")
	}
	m.chatThinkingBuf.Reset()
	m.rebuildChat()
}

func (m *Model) rebuildChat() {
	var sb strings.Builder
	if m.showThinking {
		if t := m.chatThinkingBuf.String(); t != "" {
			sb.WriteString(m.styles.Thinking.Render("💭 " + t))
			sb.WriteString("\n")
		}
	}
	sb.WriteString(m.chatContentBuf.String())
	m.chat = sb.String()
}

// loadHistoryCmd returns a tea.Cmd that asynchronously queries the
// store for recent runs. The result arrives as a HistoryLoadedMsg.
func (m *Model) loadHistoryCmd() tea.Cmd {
	if m.store == nil {
		return func() tea.Msg {
			return HistoryLoadedMsg{Err: fmt.Errorf("no database store available")}
		}
	}
	st := m.store
	return func() tea.Msg {
		runs, err := st.ListRuns("", 50)
		return HistoryLoadedMsg{Runs: runs, Err: err}
	}
}

// loadProposalsCmd returns a tea.Cmd that asynchronously queries the
// store for proposals of the currently selected run.
func (m *Model) loadProposalsCmd() tea.Cmd {
	if m.store == nil || len(m.historyRuns) == 0 {
		return nil
	}
	st := m.store
	run := m.historyRuns[m.selectedRunIdx]
	runID := run.ID
	return func() tea.Msg {
		props, err := st.ListProposals(runID)
		return HistoryProposalsLoadedMsg{RunID: runID, Proposals: props, Err: err}
	}
}
