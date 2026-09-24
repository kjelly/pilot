package tui

import (
	"fmt"
	"io"
	"os"
)

// menuDebugEnv names the environment variable that makes every select
// screen print its live item list. Scripted and trec-driven runs use it:
// several wizard menus (group_vars keys, vault keys, host lists) have an
// item count that depends on file contents rather than source order, so a
// script computing `DOWN <n>` from source, or from a remembered session,
// can silently miscount. See .agents/skills/pilot-trec-verification.
const menuDebugEnv = "PILOT_DEBUG_MENU"

// menuDebugOut is where dumpMenuDebug writes. Tests swap it; in a real run
// stderr shares the PTY that trec records.
var menuDebugOut io.Writer = os.Stderr

// dumpMenuDebug prints title's items, one line each with its 0-based
// DOWN-arrow index, when menuDebugEnv is set to a non-empty value. The
// items are the rows exactly as the screen renders them, built by this
// package from the caller's SelectSpec — never read back from Huh's
// private state (Huh migration spec, "Logging and Debugging").
func dumpMenuDebug(title string, items []string) {
	if os.Getenv(menuDebugEnv) == "" {
		return
	}
	fmt.Fprintf(menuDebugOut, "[pilot:menu] %s (%d 項，DOWN <n> 從 0 起算)\n", title, len(items))
	for i, item := range items {
		fmt.Fprintf(menuDebugOut, "[pilot:menu]   %d: %s\n", i, item)
	}
}
