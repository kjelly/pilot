package sessionrecording

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"

	"github.com/kjelly/pilot/internal/sessionaudit"
)

// gapEmitInterval rate-limits recording_gap events under sustained
// backpressure — one dropped-chunk gap per interval is enough signal for
// an operator; emitting one per dropped chunk would itself flood the
// (unrelated, small, structured) metadata channel this shares with every
// other session-lifecycle event.
const gapEmitInterval = 2 * time.Second

// copyBufSize bounds how much of one Read gets queued as a single
// TerminalEvent — matches a conventional pty relay chunk size.
const copyBufSize = 4096

// Recorder relays bytes between an outer terminal and a child PTY,
// recording them to sink as TerminalEvents (spec.md §25.1), for a session
// already known to be in "terminal_output" or "terminal_io" mode — a
// caller in "metadata" mode never constructs one of these at all (see
// cmd/pilot/cmd/portal_session_connect.go's fork point).
type Recorder struct {
	mode          string
	sessionID     string
	sink          Sink
	emitter       *sessionaudit.Emitter
	failurePolicy string
	queueSize     int
	flushGrace    time.Duration

	seq   atomic.Uint64
	start time.Time

	mu            sync.Mutex
	dropped       int
	lastGapEmit   time.Time
	lastGoodWrite time.Time
}

// New builds a Recorder for one session. mode must be ModeTerminalOutput
// or ModeTerminalIO — New panics on ModeMetadata/anything else, since
// that is a caller bug (the whole point of the mode fork at the call site
// is that a metadata-only session never reaches here).
func New(mode, sessionID string, sink Sink, emitter *sessionaudit.Emitter, failurePolicy string, queueSize int, flushGrace time.Duration) *Recorder {
	if mode != ModeTerminalOutput && mode != ModeTerminalIO {
		panic("sessionrecording.New called with mode " + mode + ", want terminal_output or terminal_io")
	}
	if queueSize <= 0 {
		queueSize = 1024
	}
	if flushGrace <= 0 {
		flushGrace = 500 * time.Millisecond
	}
	if failurePolicy == "" {
		failurePolicy = FailurePolicyBestEffort
	}
	now := time.Now()
	return &Recorder{
		mode: mode, sessionID: sessionID, sink: sink, emitter: emitter,
		failurePolicy: failurePolicy, queueSize: queueSize, flushGrace: flushGrace,
		start: now, lastGoodWrite: now,
	}
}

// ErrRecordingFailedClosed is returned by Run when failurePolicy is
// fail_closed and the sink has been failing for longer than flushGrace —
// the caller (runPortalOneShotConnect) must treat this as "terminate the
// target session", never "continue unrecorded" (spec.md §27 fail_closed:
// "不允許開始 recorded session，或 active session 在 grace period 後終止").
var ErrRecordingFailedClosed = errors.New("sessionrecording: sink failing, fail_closed policy terminating session")

// Run puts the outer terminal into raw mode (when it is a real TTY —
// best-effort no-op otherwise, e.g. under test), relays bytes both
// directions between it and ptyFile, forwards SIGWINCH as pty resizes,
// restores the outer terminal's original mode unconditionally on return
// (spec.md §25.1 point 8 — a sink failure must never leave the terminal
// stuck in raw mode), and returns when ptyFile reports EOF (the child
// process exited) or, in fail_closed mode, when the sink has been failing
// for longer than flushGrace.
//
// Run never starts, waits for, or kills the child process itself — that
// stays the caller's job, exactly like portal_ssh.go's existing
// buildConnectSSHCmd/sshLauncher split separates "build the command" from
// "run it".
func (r *Recorder) Run(ctx context.Context, ptyFile *os.File, outerIn io.Reader, outerOut io.Writer) error {
	events := make(chan TerminalEvent, r.queueSize)
	writerDone := make(chan struct{})
	stopWriter := make(chan struct{})
	// Buffered so runWriter's non-blocking send (it must never block on
	// Run's main select being ready — that select can't be listening yet
	// during the brief window before this function reaches it) can never
	// silently drop the one signal that matters.
	failClosed := make(chan struct{}, 1)

	go r.runWriter(ctx, events, stopWriter, writerDone, failClosed)

	restore := r.enterRawMode(outerIn)
	defer restore()

	stopResize := r.watchResize(outerOut, ptyFile, events)
	defer stopResize()

	// events is intentionally NEVER closed: enqueue's producers (the two
	// relay goroutines below, and watchResize's own goroutine) are not
	// guaranteed to have stopped calling it by the time this function
	// decides the session is over — relay's outerIn side in particular can
	// still be blocked in a Read with nothing more coming, for as long as
	// the caller keeps the real outer terminal open after the child pty
	// has already gone away. Closing a channel a still-live producer might
	// send on is a send-on-closed-channel panic waiting to happen, not
	// just a benign data race (found by this package's own race-enabled
	// tests). stopWriter (below) is the actual shutdown signal instead —
	// a channel only Run ever closes, that no producer ever touches; a
	// stray enqueue after that point just becomes an ordinary
	// non-blocking send into a channel nobody drains anymore, which
	// enqueue's existing backpressure/drop path already handles safely.
	copyDone := make(chan error, 2)
	go func() {
		copyDone <- r.relay(outerIn, ptyFile, StreamTTYInput, ptyFile, events)
	}()
	go func() {
		copyDone <- r.relay(ptyFile, outerOut, StreamTTYOutput, ptyFile, events)
	}()

	var runErr error
	select {
	case <-copyDone:
		// Either direction returning means the pty (child side) or the
		// outer terminal closed — either way the session is over. Give
		// the other direction a moment to drain, then move on.
	case <-failClosed:
		runErr = ErrRecordingFailedClosed
	case <-ctx.Done():
		runErr = ctx.Err()
	}

	close(stopWriter)
	<-writerDone
	return runErr
}

// enterRawMode puts in's fd into raw mode when it is a real terminal.
// Returns a restore func that is always safe to call (a no-op when raw
// mode was never entered).
func (r *Recorder) enterRawMode(in io.Reader) func() {
	f, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return func() {}
	}
	oldState, err := term.MakeRaw(int(f.Fd()))
	if err != nil {
		return func() {}
	}
	return func() { _ = term.Restore(int(f.Fd()), oldState) }
}

// watchResize forwards SIGWINCH (read from out's fd, when it's a real
// terminal) to ptyFile's window size, recording a "resize" event each
// time. Returns a stop func.
func (r *Recorder) watchResize(out io.Writer, ptyFile *os.File, events chan<- TerminalEvent) func() {
	f, ok := out.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return func() {}
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				w, h, err := term.GetSize(int(f.Fd()))
				if err != nil {
					continue
				}
				_ = pty.Setsize(ptyFile, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)})
				r.enqueue(events, TerminalEvent{Stream: StreamResize, Rows: h, Cols: w})
			case <-done:
				signal.Stop(ch)
				return
			}
		}
	}()
	return func() { close(done) }
}

// relay copies from src to dst in copyBufSize chunks, queueing a
// TerminalEvent per chunk on the given stream — except tty_input in
// ModeTerminalOutput, which is dropped without even reading it into the
// events pipeline (spec.md §23.2: "terminal_output 只保存 output"; not
// "records input then discards" — never captured in the first place).
// echoFile is the fd isEchoOff checks for tty_input redaction (always the
// child pty, per redaction.go's doc comment on why the master side is
// the right read point).
func (r *Recorder) relay(src io.Reader, dst io.Writer, stream string, echoFile *os.File, events chan<- TerminalEvent) error {
	buf := make([]byte, copyBufSize)
	recordInput := stream == StreamTTYInput && r.mode == ModeTerminalIO
	recordOutput := stream == StreamTTYOutput
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
			if recordInput {
				r.enqueueInput(events, echoFile, buf[:n])
			} else if recordOutput {
				r.enqueue(events, TerminalEvent{Stream: StreamTTYOutput, DataBase64: base64.StdEncoding.EncodeToString(buf[:n])})
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// enqueueInput applies echo-off redaction (spec.md §26) before queueing a
// tty_input chunk. See isEchoOff's doc comment for a verified, important
// caveat: against the ssh-client child this recorder actually wraps, this
// check evaluates true for virtually the whole session, not specifically
// during a remote password prompt — today this makes terminal_io mode
// safe (never under-redacts) but not able to capture real typed command
// text via this path.
func (r *Recorder) enqueueInput(events chan<- TerminalEvent, ptyFile *os.File, chunk []byte) {
	off, err := isEchoOff(ptyFile.Fd())
	if err == nil && off {
		r.enqueue(events, TerminalEvent{Stream: StreamTTYInput, RedactedBytes: len(chunk)})
		return
	}
	r.enqueue(events, TerminalEvent{Stream: StreamTTYInput, DataBase64: base64.StdEncoding.EncodeToString(chunk)})
}

// enqueue fills in the fields the writer goroutine/sink never sets
// itself and does a non-blocking send — a full queue means the sink
// cannot keep up (spec.md §27 backpressure), handled here as a drop, not
// a block: the actual relay to the user's real terminal must never stall
// because recording fell behind.
func (r *Recorder) enqueue(events chan<- TerminalEvent, ev TerminalEvent) {
	ev.SchemaVersion = SchemaVersion1
	ev.SessionID = r.sessionID
	ev.Seq = r.seq.Add(1)
	ev.OffsetNanos = time.Since(r.start).Nanoseconds()
	select {
	case events <- ev:
	default:
		r.recordDrop()
	}
}

func (r *Recorder) recordDrop() {
	r.mu.Lock()
	r.dropped++
	droppedSinceLastGap := r.dropped
	shouldEmit := time.Since(r.lastGapEmit) >= gapEmitInterval
	if shouldEmit {
		r.dropped = 0
		r.lastGapEmit = time.Now()
	}
	r.mu.Unlock()
	if shouldEmit {
		r.emitter.Emit(sessionaudit.SessionAuditEvent{
			SessionID: r.sessionID, Kind: sessionaudit.KindRecordingGap,
			Result:        fmt.Sprintf("queue full, dropped %d event(s) in the last %s", droppedSinceLastGap, gapEmitInterval),
			RecordingMode: r.mode,
		})
	}
}

// runWriter drains events to r.sink until stopWriter is closed (Run
// returning, after which it does one final non-blocking drain of
// whatever is already buffered) or, in fail_closed mode, until the sink
// has been failing for longer than r.flushGrace, at which point it
// signals failClosed so Run aborts the session rather than continuing
// silently unrecorded.
//
// The fail_closed check runs on its own ticker, independent of event
// traffic — checking only opportunistically on each Write attempt would
// miss a sustained failure during a quiet stretch (e.g. a single input
// chunk then silence): time.Since(lastGoodWrite) would never be
// re-evaluated until the NEXT event happens to arrive, which might be
// long after flushGrace has actually elapsed. A background ticker
// guarantees the grace period is enforced in wall-clock time, not
// "however often the user happens to type something" (found by this
// package's own TestRecorderFailClosedTerminatesSession, which failed
// against the first, event-driven-only version of this function).
func (r *Recorder) runWriter(ctx context.Context, events <-chan TerminalEvent, stopWriter <-chan struct{}, done chan<- struct{}, failClosed chan<- struct{}) {
	defer close(done)
	defer func() { _ = r.sink.Close() }()

	tickInterval := r.flushGrace / 4
	if tickInterval < time.Millisecond {
		tickInterval = time.Millisecond
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	failing := false
	for {
		select {
		case ev := <-events:
			err := r.sink.Write(ctx, ev)
			r.mu.Lock()
			if err == nil {
				r.lastGoodWrite = time.Now()
				failing = false
			}
			r.mu.Unlock()
		case <-ticker.C:
			if r.failurePolicy != FailurePolicyFailClosed || failing {
				continue
			}
			r.mu.Lock()
			sustained := time.Since(r.lastGoodWrite) >= r.flushGrace
			r.mu.Unlock()
			if sustained {
				failing = true
				r.emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: r.sessionID, Kind: sessionaudit.KindRecordingFailed, Result: fmt.Sprintf("sink failing for >= %s", r.flushGrace), RecordingMode: r.mode})
				select {
				case failClosed <- struct{}{}:
				default:
				}
			}
		case <-stopWriter:
			// Best-effort final drain of whatever is already buffered —
			// events is never closed (see Run's doc comment on why), so
			// this is a bounded, non-blocking sweep, not a real
			// channel-close drain loop.
			for {
				select {
				case ev := <-events:
					_ = r.sink.Write(ctx, ev)
				default:
					return
				}
			}
		}
	}
}
