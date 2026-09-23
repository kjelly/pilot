package sessionrecording

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

// gapEmitInterval rate-limits recording_gap audit events so a sustained
// drop/sink-error storm produces one event per interval, not one per event.
const gapEmitInterval = 2 * time.Second

// copyBufSize is each relay direction's read buffer — large enough that
// normal interactive traffic is one read per keystroke/output burst.
const copyBufSize = 4096

// defaultFailureGrace is how long pending events may go unacknowledged
// before fail_closed terminates the session (per-host recording spec
// §19.2), when the caller does not set Options.FailureGrace.
const defaultFailureGrace = 10 * time.Second

// finishTimeout bounds the final Sink.Finish call.
const finishTimeout = 5 * time.Second

// writerStopGrace bounds how long Run waits for the writer to exit after
// the drain window, even if a sink ignores context cancellation.
const writerStopGrace = 5 * time.Second

// Batching (per-host recording spec §19.4): the writer ships a batch as
// soon as it holds maxBatchEvents events, its encoded events reach
// maxBatchBytes, or its oldest event has waited FlushInterval.
const (
	maxBatchEvents       = 128
	maxBatchBytes        = 64 << 10
	defaultFlushInterval = 500 * time.Millisecond
)

// Winsize is a terminal size in character cells.
type Winsize struct {
	Rows int
	Cols int
}

// AuditIdentity is the session identity copied into every audit event the
// recorder itself emits (recording_gap, recording_failed).
type AuditIdentity struct {
	User         string
	TargetFQDN   string
	GatewayID    string
	GatewayScope string
	// RecordingPolicySource is where the effective mode came from (host |
	// gateway_default | built_in_default), when known.
	RecordingPolicySource string
}

// Options configures one Recorder (per-host recording spec §19.1).
type Options struct {
	Mode          string // terminal_output | terminal_io
	SessionID     string
	FailurePolicy string // best_effort | fail_closed (default best_effort)
	QueueEvents   int    // default 1024
	// FlushInterval is the longest an event waits in a batch before being
	// written; 0 means defaultFlushInterval. New caps it at half of
	// FailureGrace so batching alone can never trip the fail_closed
	// watchdog.
	FlushInterval time.Duration
	// FailureGrace is how long pending events may go unacknowledged before
	// fail_closed terminates the session; 0 means defaultFailureGrace.
	FailureGrace time.Duration
	// InitialSize, when non-zero, is recorded as the session's first event
	// (seq=1, a resize) before any relay starts.
	InitialSize Winsize
	// Terminal is the outer terminal used for raw mode, size and SIGWINCH.
	// It is separate from Run's outer reader so a cancelable input reader
	// can wrap stdin without losing raw mode. nil falls back to
	// type-asserting Run's outerIn/outerOut to *os.File.
	Terminal *os.File
	Identity AuditIdentity
}

// Recorder wraps one recorded PTY session: it relays bytes between the
// outer terminal and the child pty unchanged and, alongside, ships
// TerminalEvents to a Sink through a bounded queue.
//
// Failure semantics (per-host recording spec §19):
//   - best_effort: a full queue drops the event; a sink error drops it too.
//     Either marks the recording incomplete and emits a rate-limited
//     recording_gap. The session continues.
//   - fail_closed: nothing is dropped while the writer is alive — a full
//     queue applies backpressure to the relay. Any sink error, or pending
//     events staying unacknowledged for FailureGrace, terminates the
//     session (ErrRecordingFailedClosed). An idle session with nothing
//     pending never trips the watchdog.
type Recorder struct {
	opts    Options
	sink    Sink
	emitter *sessionaudit.Emitter

	seq   atomic.Uint64
	start time.Time

	// writerCtx scopes every sink call; cancelWriter aborts an in-flight
	// or retrying sink call (fail closed, drain timeout, Run exit).
	writerCtx    context.Context
	cancelWriter context.CancelFunc

	writerStopped chan struct{} // closed when the writer goroutine exits
	failClosedCh  chan struct{} // closed once fail_closed triggers
	failOnce      sync.Once
	inputDone     chan struct{} // closed when the input relay exits

	mu          sync.Mutex
	pending     int64
	progressAt  time.Time
	dropped     int // since the last recording_gap emission
	lastGapEmit time.Time
	lost        bool   // any event dropped or not acknowledged by the sink
	lossReason  string // "dropped" or "sink_error": the first loss seen
	failed      bool   // fail_closed triggered
	drainTimed  bool   // the end-of-session drain hit its deadline
}

// New builds a Recorder. It panics on a non-recording mode: a caller must
// never construct one for metadata sessions.
func New(opts Options, sink Sink, emitter *sessionaudit.Emitter) *Recorder {
	if opts.Mode != ModeTerminalOutput && opts.Mode != ModeTerminalIO {
		panic("sessionrecording.New called with mode " + opts.Mode + ", want terminal_output or terminal_io")
	}
	if opts.QueueEvents <= 0 {
		opts.QueueEvents = 1024
	}
	if opts.FailureGrace <= 0 {
		opts.FailureGrace = defaultFailureGrace
	}
	if opts.FailurePolicy == "" {
		opts.FailurePolicy = FailurePolicyBestEffort
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = defaultFlushInterval
	}
	if limit := opts.FailureGrace / 2; opts.FlushInterval > limit {
		opts.FlushInterval = limit
	}
	return &Recorder{
		opts: opts, sink: sink, emitter: emitter, start: time.Now(),
		writerStopped: make(chan struct{}),
		failClosedCh:  make(chan struct{}),
		inputDone:     make(chan struct{}),
	}
}

// ErrRecordingFailedClosed is returned by Run when fail_closed terminated
// the session; the caller must kill the target session, never continue it
// unrecorded.
var ErrRecordingFailedClosed = errors.New("sessionrecording: sink failing, fail_closed policy terminating session")

// LastSeq is the last seq this recorder has assigned (0 before any event).
func (r *Recorder) LastSeq() uint64 { return r.seq.Load() }

// InputDone is closed once the input relay goroutine has returned. A caller
// that keeps using the outer terminal after Run (the interactive Portal)
// cancels its input reader and waits on this before reading stdin again.
func (r *Recorder) InputDone() <-chan struct{} { return r.inputDone }

// Run relays between the outer terminal and ptyFile until the child side
// closes, the context ends, or fail_closed triggers; then drains, calls
// Sink.Finish exactly once, and returns. It restores the outer terminal
// mode unconditionally and never starts, waits for, or kills the child.
func (r *Recorder) Run(ctx context.Context, ptyFile *os.File, outerIn io.Reader, outerOut io.Writer) error {
	r.writerCtx, r.cancelWriter = context.WithCancel(ctx)
	defer r.cancelWriter()

	events := make(chan TerminalEvent, r.opts.QueueEvents)
	stopWriter := make(chan struct{})

	go r.runWriter(events, stopWriter)
	stopWatchdog := r.startWatchdog()
	defer stopWatchdog()

	restore := r.enterRawMode(outerIn)
	defer restore()

	if r.opts.InitialSize.Rows > 0 && r.opts.InitialSize.Cols > 0 {
		r.enqueue(events, TerminalEvent{Stream: StreamResize, Rows: r.opts.InitialSize.Rows, Cols: r.opts.InitialSize.Cols})
	}

	stopResize := r.watchResize(outerOut, ptyFile, events)
	defer stopResize()

	// events is intentionally never closed: the relay goroutines (the
	// input side can stay blocked in a Read on the outer terminal after the
	// child is gone) may still call enqueue. enqueue returns immediately
	// once the writer has stopped, so a late producer never blocks.
	copyDone := make(chan error, 2)
	go func() {
		defer close(r.inputDone)
		copyDone <- r.relay(outerIn, ptyFile, StreamTTYInput, ptyFile, events)
	}()
	go func() {
		copyDone <- r.relay(ptyFile, outerOut, StreamTTYOutput, ptyFile, events)
	}()

	var runErr error
	select {
	case <-copyDone:
	case <-r.failClosedCh:
		runErr = ErrRecordingFailedClosed
	case <-ctx.Done():
		runErr = ctx.Err()
	}

	// Drain: the writer flushes what is queued, bounded by FailureGrace.
	drainTimer := time.AfterFunc(r.opts.FailureGrace, func() {
		select {
		case <-r.writerStopped:
			return // the drain already finished; nothing timed out
		default:
		}
		r.mu.Lock()
		r.drainTimed = true
		r.mu.Unlock()
		r.cancelWriter()
	})
	close(stopWriter)
	select {
	case <-r.writerStopped:
	case <-time.After(r.opts.FailureGrace + writerStopGrace):
		r.mu.Lock()
		r.drainTimed = true
		r.mu.Unlock()
		r.cancelWriter()
	}
	drainTimer.Stop()

	// A fail_closed trip during the drain (the session already ended)
	// only marks the recording incomplete; it does not change runErr.
	r.finish(runErr)
	return runErr
}

// finish reports the recording's completeness to the sink (per-host
// recording spec §19.6).
func (r *Recorder) finish(runErr error) {
	r.mu.Lock()
	info := FinishInfo{LastSeq: r.seq.Load()}
	switch {
	case r.failed:
		info.Reason = "fail_closed"
	case r.drainTimed:
		info.Reason = "drain_timeout"
	case r.lost:
		info.Reason = r.lossReason
	case runErr != nil:
		info.Reason = "aborted"
	default:
		info.Complete = true
	}
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), finishTimeout)
	defer cancel()
	if err := r.sink.Finish(ctx, info); err != nil {
		r.emit(sessionaudit.KindRecordingFailed, "finish: "+err.Error())
	}
}

// enterRawMode puts the outer terminal into raw mode when it is a real
// terminal. Returns a restore func that is always safe to call.
func (r *Recorder) enterRawMode(in io.Reader) func() {
	f := r.opts.Terminal
	if f == nil {
		ff, ok := in.(*os.File)
		if !ok {
			return func() {}
		}
		f = ff
	}
	if !term.IsTerminal(int(f.Fd())) {
		return func() {}
	}
	oldState, err := term.MakeRaw(int(f.Fd()))
	if err != nil {
		return func() {}
	}
	return func() { _ = term.Restore(int(f.Fd()), oldState) }
}

// watchResize forwards SIGWINCH on the outer terminal to ptyFile's window
// size, recording a resize event each time. Returns a stop func.
func (r *Recorder) watchResize(out io.Writer, ptyFile *os.File, events chan<- TerminalEvent) func() {
	f := r.opts.Terminal
	if f == nil {
		ff, ok := out.(*os.File)
		if !ok {
			return func() {}
		}
		f = ff
	}
	if !term.IsTerminal(int(f.Fd())) {
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

// relay copies src to dst, recording what it copies. The relay is
// byte-for-byte transparent: recording is a side channel.
//
// Each chunk is queued before it is forwarded, and once fail_closed has
// tripped nothing more is forwarded in either direction: the session must
// not keep exchanging unrecorded bytes while Run drains and finishes.
func (r *Recorder) relay(src io.Reader, dst io.Writer, stream string, echoFile *os.File, events chan<- TerminalEvent) error {
	buf := make([]byte, copyBufSize)
	recordInput := stream == StreamTTYInput && r.opts.Mode == ModeTerminalIO
	recordOutput := stream == StreamTTYOutput
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if recordInput {
				r.enqueueInput(events, echoFile, buf[:n])
			} else if recordOutput {
				r.enqueue(events, TerminalEvent{Stream: StreamTTYOutput, DataBase64: base64.StdEncoding.EncodeToString(buf[:n])})
			}
			if r.failedClosed() {
				return ErrRecordingFailedClosed
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
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

// enqueueInput records one chunk of typed input, redacted to a byte count
// while the child terminal has echo off (see redaction.go for why this is
// effectively always true on the SSH relay path).
func (r *Recorder) enqueueInput(events chan<- TerminalEvent, ptyFile *os.File, chunk []byte) {
	off, err := isEchoOff(ptyFile.Fd())
	if err == nil && off {
		r.enqueue(events, TerminalEvent{Stream: StreamTTYInput, RedactedBytes: len(chunk)})
		return
	}
	r.enqueue(events, TerminalEvent{Stream: StreamTTYInput, DataBase64: base64.StdEncoding.EncodeToString(chunk)})
}

// enqueue stamps ev and hands it to the writer. The seq is assigned first,
// so a dropped event leaves a gap the store can see.
func (r *Recorder) enqueue(events chan<- TerminalEvent, ev TerminalEvent) {
	ev.SchemaVersion = SchemaVersion1
	ev.SessionID = r.opts.SessionID
	ev.Seq = r.seq.Add(1)
	ev.OffsetNanos = time.Since(r.start).Nanoseconds()

	r.addPending(1)
	if r.opts.FailurePolicy == FailurePolicyFailClosed {
		// Backpressure: block the relay rather than drop, bounded by the
		// watchdog (which closes failClosedCh) and the writer's lifetime.
		select {
		case events <- ev:
			return
		case <-r.failClosedCh:
		case <-r.writerStopped:
		}
		r.addPending(-1)
		r.recordLoss("writer stopped", 1)
		return
	}
	select {
	case events <- ev:
	default:
		r.addPending(-1)
		r.recordLoss("queue full", 1)
	}
}

func (r *Recorder) addPending(delta int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == 0 && delta > 0 {
		r.progressAt = time.Now()
	}
	r.pending += delta
}

// recordLoss marks n lost events, the recording incomplete, and emits a
// rate-limited recording_gap.
func (r *Recorder) recordLoss(why string, n int) {
	r.mu.Lock()
	r.markLostLocked("dropped")
	r.dropped += n
	count := r.dropped
	shouldEmit := time.Since(r.lastGapEmit) >= gapEmitInterval
	if shouldEmit {
		r.dropped = 0
		r.lastGapEmit = time.Now()
	}
	r.mu.Unlock()
	if shouldEmit {
		r.emit(sessionaudit.KindRecordingGap, fmt.Sprintf("%s: lost %d event(s) in the last %s", why, count, gapEmitInterval))
	}
}

func (r *Recorder) emit(kind, result string) {
	id := r.opts.Identity
	r.emitter.Emit(sessionaudit.SessionAuditEvent{
		SessionID: r.opts.SessionID, Kind: kind, Result: result,
		User: id.User, TargetFQDN: id.TargetFQDN, GatewayID: id.GatewayID, GatewayScope: id.GatewayScope,
		RecordingMode: r.opts.Mode, RecordingPolicySource: id.RecordingPolicySource,
	})
}

// markLostLocked records that an event was lost; r.mu must be held.
func (r *Recorder) markLostLocked(reason string) {
	r.lost = true
	if r.lossReason == "" {
		r.lossReason = reason
	}
}

// triggerFailClosed ends the session under fail_closed exactly once.
func (r *Recorder) triggerFailClosed(reason string) {
	r.failOnce.Do(func() {
		r.mu.Lock()
		r.failed = true
		r.markLostLocked("sink_error")
		r.mu.Unlock()
		r.emit(sessionaudit.KindRecordingFailed, reason)
		close(r.failClosedCh)
		r.cancelWriter()
	})
}

// failedClosed reports whether fail_closed has tripped.
func (r *Recorder) failedClosed() bool {
	select {
	case <-r.failClosedCh:
		return true
	default:
		return false
	}
}

// startWatchdog enforces FailureGrace in wall-clock time, independently of
// the writer (which may be blocked inside a retrying sink call).
func (r *Recorder) startWatchdog() func() {
	if r.opts.FailurePolicy != FailurePolicyFailClosed {
		return func() {}
	}
	tick := r.opts.FailureGrace / 4
	if tick < 50*time.Millisecond {
		tick = 50 * time.Millisecond
	}
	ticker := time.NewTicker(tick)
	done := make(chan struct{})
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.mu.Lock()
				stuck := r.pending > 0 && time.Since(r.progressAt) >= r.opts.FailureGrace
				r.mu.Unlock()
				if stuck {
					r.triggerFailClosed(fmt.Sprintf("sink made no progress for >= %s", r.opts.FailureGrace))
					return
				}
			case <-done:
				return
			case <-r.failClosedCh:
				return
			}
		}
	}()
	return func() { close(done) }
}

// runWriter batches queued events and ships them to the sink until
// stopWriter, then drains and flushes what is still queued (bounded by the
// drain timer cancelling writerCtx).
func (r *Recorder) runWriter(events <-chan TerminalEvent, stopWriter <-chan struct{}) {
	defer close(r.writerStopped)
	var batch []TerminalEvent
	batchBytes := 0
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	var flushDue <-chan time.Time

	flush := func() {
		timer.Stop()
		flushDue = nil
		if len(batch) == 0 {
			return
		}
		r.writeBatch(batch)
		batch, batchBytes = nil, 0
	}
	add := func(ev TerminalEvent) {
		if len(batch) == 0 {
			timer.Reset(r.opts.FlushInterval)
			flushDue = timer.C
		}
		batch = append(batch, ev)
		batchBytes += encodedEventSize(ev)
		if len(batch) >= maxBatchEvents || batchBytes >= maxBatchBytes {
			flush()
		}
	}

	for {
		select {
		case ev := <-events:
			add(ev)
		case <-flushDue:
			flush()
		case <-stopWriter:
			for {
				select {
				case ev := <-events:
					add(ev)
				default:
					flush()
					return
				}
			}
		}
	}
}

// encodedEventSize is ev's JSON size, what the batch byte threshold counts.
func encodedEventSize(ev TerminalEvent) int {
	b, err := json.Marshal(ev)
	if err != nil {
		return len(ev.DataBase64)
	}
	return len(b)
}

// writeBatch ships one batch and settles its pending count. Once writerCtx
// is cancelled (fail closed, drain timeout, Run exit) the batch is counted
// as lost without calling the sink.
func (r *Recorder) writeBatch(batch []TerminalEvent) {
	n := int64(len(batch))
	if r.writerCtx.Err() != nil {
		r.addPending(-n)
		r.recordLoss("drain cancelled", len(batch))
		return
	}
	err := r.sink.WriteBatch(r.writerCtx, batch)
	if err == nil {
		r.mu.Lock()
		r.pending -= n
		r.progressAt = time.Now()
		r.mu.Unlock()
		return
	}
	r.addPending(-n)
	r.mu.Lock()
	r.markLostLocked("sink_error")
	r.mu.Unlock()
	if r.opts.FailurePolicy == FailurePolicyFailClosed {
		// The batch is lost: under fail_closed that alone ends the session.
		r.triggerFailClosed("sink error: " + err.Error())
		return
	}
	r.recordLoss("sink error", len(batch))
}
