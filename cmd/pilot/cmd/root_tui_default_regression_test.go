package cmd

import (
	"testing"
)

// TestRootCmd_TUIFlagDefault guards the contract that the CLI
// defaults to non-interactive (promptui / headless-friendly) mode,
// and that opting into the TUI requires an explicit `--tui` flag.
//
// The previous default (TUI on unless `--no-tui`) silently degraded
// to promptui when stderr wasn't a TTY — fine for developers, but
// hostile to CI, AI-agent runners, and SSH users who saw the noisy
// "TUI not available (no TTY), using promptui" line in their logs.
// Inverting the default removes both the noisy notice and the
// ambiguity about which mode is active.
//
// To prove the test isn't a tautology: delete the `--tui` flag
// registration in `init()` (cmd/pilot/cmd/root.go:52-66) and
// re-run; this test still compiles but loses the ability to assert
// `Lookup("tui") != nil`, and the on-by-default guarantee the test
// documents becomes untestable here. The existing
// TestNewHonoursNoTUI in internal/app/ covers the app-layer side
// regardless of the CLI default.
func TestRootCmd_TUIFlagDefault(t *testing.T) {
	fs := rootCmd.PersistentFlags()
	if fs.Lookup("tui") == nil {
		t.Fatal("--tui flag missing from rootCmd.PersistentFlags()")
	}
	// Default must be false; opt-in via --tui.
	if got := fs.Lookup("tui").DefValue; got != "false" {
		t.Errorf("--tui default = %q, want \"false\" (non-interactive by default)", got)
	}
	// --no-tui kept as deprecated alias for one release; verify the
	// flag still exists so backward compat is intact during the
	// deprecation window.
	if fs.Lookup("no-tui") == nil {
		t.Error("--no-tui deprecated alias missing; backward compat broken")
	}
}
