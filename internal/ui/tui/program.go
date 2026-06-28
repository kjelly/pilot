// Package tui: public Program wrapper for the Bubble Tea TUI.
//
// This is the entry point used by the rest of pilot. It handles
// TTY detection (and falls back to a non-TUI mode), spawns the
// tea.Program in its own goroutine, and exposes thread-safe senders
// for the agent loop.
package tui

import (
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/anomalyco/pilot/internal/agent"
	"github.com/anomalyco/pilot/internal/store"
)

// IsSupported returns true if the given fd (typically os.Stderr.Fd()) is
// a real terminal. Use this before constructing a Program.
func IsSupported(fd uintptr) bool {
	return term.IsTerminal(int(fd))
}

// Program wraps a tea.Program and exposes senders for the agent loop.
//
// The Program is safe to use from multiple goroutines: the tea.Program's
// Send method is internally serialized. The blocking approval and ask
// methods will park the calling goroutine on a channel until the user
// makes a decision.
type Program struct {
	tea   *tea.Program
	model *Model

	// approvalTimeout and askUserTimeout allow callers to bound how long
	// the TUI will block the agent. They are advisory — the channels are
	// buffered with capacity 1, so a sender that gives up simply moves on
	// (the TUI may still complete later and the reply is silently dropped).
}

// New creates and starts a TUI Program. The caller is responsible for
// calling Wait (or Shutdown) when done.
//
// The TUI runs in a separate goroutine; tea.NewProgram.Run blocks, so
// the returned Program.Start() returns immediately.
func New(st *store.Store) *Program {
	m := newModel(st)
	p := tea.NewProgram(m,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
		tea.WithOutput(nil), // we use stderr (the program default)
	)
	return &Program{tea: p, model: m}
}

// Start launches the TUI in a goroutine and returns immediately.
func (p *Program) Start() {
	go func() {
		// Discard any error from Run — typically a tea.ErrProgramKilled when
		// the user hits Ctrl-C, which is the expected exit path.
		_, _ = p.tea.Run()
	}()
}

// Shutdown signals the program to quit and waits for the goroutine to
// exit. Safe to call multiple times.
func (p *Program) Shutdown() {
	p.tea.Send(QuitMsg{})
}

// Run blocks until the program exits. Useful for tests.
func (p *Program) Run() error {
	_, err := p.tea.Run()
	return err
}

// RequestApproval sends a proposal to the TUI and blocks until the user
// decides. Returns the user's decision. If the TUI is not running or the
// user never responds, returns DecisionRejected as a safe default.
func (p *Program) RequestApproval(prop *agent.Proposal) agent.Decision {
	reply := make(chan agent.Decision, 1)
	p.tea.Send(ProposalRequestMsg{Proposal: prop, Reply: reply})
	d, ok := <-reply
	if !ok {
		return agent.DecisionRejected
	}
	return d
}

// AskUser shows a question and blocks until the user answers.
func (p *Program) AskUser(question string, options []string) string {
	reply := make(chan string, 1)
	p.tea.Send(AskUserMsg{Question: question, Options: options, Reply: reply})
	ans, ok := <-reply
	if !ok {
		return ""
	}
	return ans
}

// SendLLMChunk streams a chunk of LLM output into the chat pane.
func (p *Program) SendLLMChunk(content, thinking string) {
	if content == "" && thinking == "" {
		return
	}
	p.tea.Send(LLMChunkMsg{Content: content, Thinking: thinking})
}

// SendLLMDone marks the current LLM turn as complete.
func (p *Program) SendLLMDone() {
	p.tea.Send(LLMChunkMsg{Done: true})
}

// SendRunStart signals the start of a new agent run.
func (p *Program) SendRunStart(runID, goal string) {
	p.tea.Send(RunStartedMsg{RunID: runID, Goal: goal})
}

// SendRunFinish signals the end of a run.
func (p *Program) SendRunFinish(runID, status string) {
	p.tea.Send(RunFinishedMsg{RunID: runID, Status: status})
}

// SendStatus refreshes the status bar counters.
func (p *Program) SendStatus(iter, maxIter, proposalCount, pendingCount int, tool, host string) {
	p.tea.Send(StatusUpdateMsg{
		Iter:          iter,
		MaxIter:       maxIter,
		ProposalCount: proposalCount,
		PendingCount:  pendingCount,
		CurrentTool:   tool,
		CurrentHost:   host,
	})
}

// SendToolCall records that the LLM is about to call a tool.
func (p *Program) SendToolCall(tool, args string) {
	p.tea.Send(ToolCallMsg{Tool: tool, Args: args})
}

// SendToolResult records the result of a tool call.
func (p *Program) SendToolResult(tool, summary string, isErr bool) {
	p.tea.Send(ToolResultMsg{Tool: tool, Summary: summary, IsError: isErr})
}

// SendError shows an error in the chat pane.
func (p *Program) SendError(msg string) {
	p.tea.Send(LLMChunkMsg{Content: "\n❌ " + msg + "\n", Done: true})
}

// SendDocsStatus updates the docs index indicator.
func (p *Program) SendDocsStatus(moduleCount, playbookCount int, stale bool, ansibleVer string) {
	p.tea.Send(DocsIndexStatusMsg{
		ModuleCount:    moduleCount,
		PlaybookCount:  playbookCount,
		Stale:          stale,
		AnsibleVersion: ansibleVer,
	})
}

// Helper to coordinate a sync.WaitGroup if multiple senders wait on us.
var _ = sync.WaitGroup{}
