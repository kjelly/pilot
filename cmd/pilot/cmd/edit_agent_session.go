// edit_agent_session.go is pilot edit automation's session boundary,
// isolated from CLI package globals (contrast runAutomatedEditWorkflow
// before this file existed, which read the editDir global directly
// inside the function that built the router/driver). A future caller —
// an MCP server (docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md),
// or a test — can build an editAgentSession against any workspace
// directory the same way --dir drives editDir for the CLI today,
// without needing a *cobra.Command or any other CLI-only value.
package cmd

import (
	"io"
	"time"
)

// editAgentSessionOptions configures the automationDriver behind an
// editAgentSession, without exposing automationDriver's CLI-flag-shaped
// fields (trace file, TREC marker fd, presentation pacing) to a caller
// that only needs a subset — e.g. a future MCP caller building one with
// just a Recorder.
type editAgentSessionOptions struct {
	Out               io.Writer
	Presentation      bool
	Trace             func(automationTraceEvent)
	Marker            io.Writer
	PausePresentation func(time.Duration)
	Recorder          AuditRecorder
}

// editAgentSession is a single pilot-edit automation run against dir.
// runAutomatedEditWorkflow reads the editDir CLI global exactly once —
// at its call to newEditAgentSession — and nowhere else; every method
// here takes dir as a plain value instead.
type editAgentSession struct {
	dir    string
	router editRouterModel
	driver automationDriver
}

func newEditAgentSession(dir string, opts editAgentSessionOptions) *editAgentSession {
	return &editAgentSession{
		dir:    dir,
		router: newEditRouterModel(dir),
		driver: automationDriver{
			trace:             opts.Trace,
			presentation:      opts.Presentation,
			out:               opts.Out,
			dir:               dir,
			marker:            opts.Marker,
			pausePresentation: opts.PausePresentation,
			recorder:          opts.Recorder,
		},
	}
}

// View is the session's current router frame — read before Run to show
// the starting screen (the presentation preamble
// runAutomatedEditWorkflow already printed before this file existed) or
// after a failed Run to inspect where the router stopped.
func (s *editAgentSession) View() string { return s.router.View() }

// Run drives scenario's steps against the session's router, exactly as
// calling automationDriver.run directly would — this indirection exists
// solely so a caller never needs to know automationDriver exists.
func (s *editAgentSession) Run(scenario editScenario) error {
	return s.driver.run(&s.router, scenario)
}
