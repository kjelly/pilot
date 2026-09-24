package cmd

import "time"

// Upper bounds on how long a TUI test waits for a screen, a final model, or
// a PTY child to exit. Every wait polls and returns as soon as its condition
// holds, so a passing test never sleeps for the full bound; the bound only
// decides how long a failing test hangs before it reports. The old 2s/3s/5s
// bounds were close enough to the render time under -race on a loaded
// machine that a correct screen could miss the window.
const (
	teatestWaitTimeout  = 15 * time.Second
	teatestFinalTimeout = 15 * time.Second
	ptyOutputTimeout    = 20 * time.Second
	ptyExitTimeout      = 20 * time.Second
)
