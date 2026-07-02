// Package tui implements the Bubble Tea TUI for pilot.
//
// It runs as a single tea.Program in its own goroutine. The agent loop and
// other components communicate with the TUI by sending messages via
// program.Send(msg). When a human decision is required (approve/reject a
// proposal, answer a question), the sender blocks on a reply channel
// included in the request message.
package tui

import (
	"github.com/anomalyco/pilot/internal/agent"
	"github.com/anomalyco/pilot/internal/store"
)

// ProposalRequestMsg asks the TUI to display a proposal and wait for a
// decision from the user. The Reply channel is buffered with capacity 1;
// the TUI sends exactly one Decision on it and then the model returns to
// the running state.
type ProposalRequestMsg struct {
	Proposal *agent.Proposal
	Reply    chan agent.Decision
}

// AskUserMsg asks the TUI to display a question to the user and return
// their answer. Used by the ask_user tool.
type AskUserMsg struct {
	Question string
	Options  []string
	Reply    chan string
}

// LLMChunkMsg streams a chunk of LLM output into the chat pane.
type LLMChunkMsg struct {
	Content  string
	Thinking string
	Done     bool
}

// RunStartedMsg marks the start of a new agent run.
type RunStartedMsg struct {
	RunID string
	Goal  string
}

// RunFinishedMsg marks the end of a run.
type RunFinishedMsg struct {
	RunID  string
	Status string
}

// StatusUpdateMsg refreshes the status bar with current counters.
type StatusUpdateMsg struct {
	Iter          int
	MaxIter       int
	ProposalCount int
	PendingCount  int
	CurrentTool   string
	CurrentHost   string
}

// ToolCallMsg records that the LLM is about to call a tool (for the
// activity log in the chat pane).
type ToolCallMsg struct {
	Tool string
	Args string
}

// ToolResultMsg records the result of a tool call.
type ToolResultMsg struct {
	Tool    string
	Summary string
	IsError bool
}

// QuitMsg is sent to the program to make it exit cleanly.
type QuitMsg struct{}

// ThemeDetectedMsg tells the model the user's terminal background so it
// can pick a palette. Auto-detected at startup.
type ThemeDetectedMsg struct {
	Dark bool
}

// DocsIndexStatusMsg updates the docs-index indicator in the status bar.
type DocsIndexStatusMsg struct {
	ModuleCount    int
	PlaybookCount  int
	Stale          bool
	AnsibleVersion string
}

// HistoryLoadedMsg is sent after the async DB query for runs completes.
type HistoryLoadedMsg struct {
	Runs []*store.Run
	Err  error
}

// HistoryProposalsLoadedMsg is sent after the async DB query for
// proposals of a selected run completes.
type HistoryProposalsLoadedMsg struct {
	RunID     string
	Proposals []*store.Proposal
	Err       error
}
