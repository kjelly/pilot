package sessionaudit

import (
	"encoding/json"
	"io"
	"log/slog"
	"log/syslog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Emitter writes SessionAuditEvent records as single-line JSON to syslog
// facility LOCAL6 (spec.md §22: "使用 syslog: facility=local6"). It never
// writes terminal recording payload (D9) — only these small structured
// records.
//
// Emit never returns an error and never blocks/fails the connect/authorize
// flow it describes: metadata audit here is best-effort observability, not
// a gate (unlike Phase 7/8's later terminal-recording integrity concerns).
// This mirrors the annotations half of internal/accessportal.hostMetadataCache ("enrichment,
// never authorization" principle and internal/freeipaaccess.Client's lazy,
// fail-soft credential loading (see that package's NewClient doc comment
// for the incident that shaped this house style) — a Directory/Gateway
// process must never crash-loop, refuse to start, or slow down a real
// connect just because local syslog is unreachable.
type Emitter struct {
	tag string
	seq atomic.Uint64

	// w is the underlying sink. Normally a *syslog.Writer; swappable for
	// tests via newEmitterWithWriter. Never nil after construction.
	w writer

	// fallback receives events (and Emit's own internal failures) when w
	// could not be established or a write to it fails — never left silent.
	fallback *slog.Logger
}

// writer is the minimal surface this package needs from *syslog.Writer,
// factored out so tests can inject a fake without a real syslog daemon.
type writer interface {
	Write([]byte) (int, error)
}

// NewEmitter builds an Emitter tagged as tag (e.g. "pilot-access-directory"
// or "pilot-access-gateway" — becomes the syslog program tag other tools
// like `journalctl -t` or an audit-log-forwarding rule key off). If the
// local syslog daemon is unreachable, NewEmitter still succeeds: Emit
// falls back to slog.Default() instead of failing the caller's startup
// (see the fail-soft rationale on Emitter above). NewEmitter therefore
// never returns a non-nil error today, but keeps the error return so a
// future stricter mode (or a caller that wants to know) has somewhere to
// look without an API break.
func NewEmitter(tag string) (*Emitter, error) {
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_LOCAL6, tag)
	fallback := slog.Default()
	if err != nil {
		fallback.Warn("sessionaudit: local syslog unavailable, falling back to default logger", "tag", tag, "error", err)
		return &Emitter{tag: tag, w: nil, fallback: fallback}, nil
	}
	return &Emitter{tag: tag, w: w, fallback: fallback}, nil
}

// NewEmitterWithWriter returns an Emitter that writes one JSON line per
// event to w instead of local syslog — for callers (and other packages'
// tests) that need to capture or redirect the audit stream. w must be safe
// for the caller's own concurrency; Emit itself does not serialize writes.
func NewEmitterWithWriter(tag string, w io.Writer) *Emitter {
	return newEmitterWithWriter(tag, newlineWriter{w: w})
}

// newlineWriter terminates each Emit's single Write with '\n' — syslog
// frames each message itself, but a plain stream needs a line delimiter.
type newlineWriter struct{ w io.Writer }

func (n newlineWriter) Write(p []byte) (int, error) {
	if _, err := n.w.Write(append(append([]byte(nil), p...), '\n')); err != nil {
		return 0, err
	}
	return len(p), nil
}

// newEmitterWithWriter is NewEmitter for tests: injects w directly instead
// of dialing a real syslog daemon.
func newEmitterWithWriter(tag string, w writer) *Emitter {
	return &Emitter{tag: tag, w: w, fallback: slog.Default()}
}

// NewWriterEmitter returns an Emitter that writes one JSON line per event
// to w instead of syslog — for other packages' tests that need to observe
// the exact audit events a component emits. w must be safe for concurrent
// use when events are emitted from several goroutines.
func NewWriterEmitter(tag string, w io.Writer) *Emitter {
	return newEmitterWithWriter(tag, w)
}

// Emit fills in SchemaVersion/EventID/Seq/Timestamp (callers never set
// these) and writes one JSON line. Never returns an error; a marshal or
// write failure logs via the fallback logger instead, so a broken sink
// never blocks or fails the real connect/authorize flow it is describing.
func (e *Emitter) Emit(ev SessionAuditEvent) {
	ev.SchemaVersion = SchemaVersion1
	ev.EventID = uuid.NewString()
	ev.Seq = e.seq.Add(1)
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	line, err := json.Marshal(ev)
	if err != nil {
		e.fallback.Warn("sessionaudit: failed to marshal event", "kind", ev.Kind, "session_id", ev.SessionID, "error", err)
		return
	}

	if e.w == nil {
		e.fallback.Info("sessionaudit", "line", string(line))
		return
	}
	if _, err := e.w.Write(line); err != nil {
		e.fallback.Warn("sessionaudit: failed to write event to syslog", "kind", ev.Kind, "session_id", ev.SessionID, "error", err)
	}
}
