// Package sessionrecording is the opt-in PTY terminal recorder for the
// Gateway -> Target hop (docs/tmp/now/spec.md §23-§27). It is completely
// inert in the default "metadata" recording mode — nothing in this
// package is even constructed unless an operator has explicitly opted
// into "terminal_output" or "terminal_io" (D8).
//
// This package NEVER shares a transport with internal/sessionaudit (D9):
// terminal I/O is a different sensitivity class from small structured
// lifecycle metadata, and the two must stay on separate sinks. The three
// recording lifecycle events this package DOES emit through the shared
// internal/sessionaudit.Emitter (recording_started/recording_gap/
// recording_failed) carry no terminal bytes — only counts/status.
package sessionrecording

// TerminalEvent is one PTY byte-stream record (spec.md §25.3). Seq must be
// strictly monotonic per session. DataBase64 is omitted (empty) for a
// redacted tty_input chunk (see redaction.go) and for every "resize"
// event, which carries Rows/Cols instead.
type TerminalEvent struct {
	SchemaVersion int    `json:"schema_version"`
	SessionID     string `json:"session_id"`
	Seq           uint64 `json:"seq"`
	OffsetNanos   int64  `json:"offset_nanos"`
	Stream        string `json:"stream"` // "tty_input" | "tty_output" | "resize"

	DataBase64 string `json:"data_base64,omitempty"`
	Rows       int    `json:"rows,omitempty"`
	Cols       int    `json:"cols,omitempty"`

	RedactedBytes int `json:"redacted_bytes,omitempty"`
}

// SchemaVersion1 is the only schema version this package currently emits.
const SchemaVersion1 = 1

// Stream values (spec.md §25.2 — PTY mode merges stdout/stderr, so these
// are the only three streams that exist; never pretend to distinguish
// stdout from stderr).
const (
	StreamTTYInput  = "tty_input"
	StreamTTYOutput = "tty_output"
	StreamResize    = "resize"
)

// Recording modes (spec.md §23). "metadata" is the unconditional default
// everywhere in this codebase — a caller must never construct a Recorder
// for it; these two are the only modes that do.
const (
	ModeMetadata       = "metadata"
	ModeTerminalOutput = "terminal_output"
	ModeTerminalIO     = "terminal_io"
)

// Failure policies (spec.md §27).
const (
	FailurePolicyBestEffort = "best_effort"
	FailurePolicyFailClosed = "fail_closed"
)
