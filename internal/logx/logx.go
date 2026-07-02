// Package logx configures pilot's structured DIAGNOSTIC logging on top of
// the standard library's log/slog.
//
// pilot has three distinct output channels; keep them separate:
//
//  1. Returned errors — the primary control-flow signal. Wrap with %w and
//     return up the stack. Do NOT also log an error you return (log XOR
//     return); the top-level caller decides how to surface it.
//
//  2. User-facing UX — the agent's LLM stream, proposals, progress, and
//     results. These are the product surface and go to the CLI writers
//     (os.Stdout / a command's Out/Err) or the TUI. They are NOT logs and
//     must NOT go through this package.
//
//  3. Diagnostics — recovered-error warnings ("index not found, continuing")
//     and internal debug traces. These go through slog (this package): they
//     are leveled (default WARN), structured (key/value attrs), silenceable,
//     and — under the TUI — redirectable to a file so they don't smear the
//     interface.
//
// Usage from anywhere: slog.Warn("msg", "key", val) / slog.Debug(...) — the
// default logger is configured by Init below.
package logx

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// remembered so Redirect can re-apply the same level/format to a new writer.
var (
	curLevel  string
	curFormat string
)

// ParseLevel maps a name to an slog.Level. Unknown/empty → WARN (pilot's
// default: recovered-error warnings are visible, debug traces are not).
func ParseLevel(name string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "error":
		return slog.LevelError
	default:
		return slog.LevelWarn
	}
}

// Init installs the process-wide slog default logger. level is one of
// debug|info|warn|error (case-insensitive). format "json" selects the JSON
// handler; anything else is human-readable text with the timestamp elided
// (CLI diagnostics read cleaner as `level=WARN msg=... key=val`). w defaults
// to os.Stderr when nil.
func Init(level, format string, w io.Writer) {
	curLevel, curFormat = level, format
	if w == nil {
		w = os.Stderr
	}
	opts := &slog.HandlerOptions{Level: ParseLevel(level)}
	var h slog.Handler
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		h = slog.NewJSONHandler(w, opts)
	} else {
		// Drop the time attr: CLI diagnostics are read live, not archived,
		// and a leading timestamp is noise next to the message.
		opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}
		h = slog.NewTextHandler(w, opts)
	}
	slog.SetDefault(slog.New(h))
}

// Redirect re-installs the default logger writing to w, preserving the level
// and format last passed to Init. The TUI uses this to send diagnostics to a
// log file instead of stderr (where they would corrupt the rendered UI).
func Redirect(w io.Writer) {
	Init(curLevel, curFormat, w)
}
