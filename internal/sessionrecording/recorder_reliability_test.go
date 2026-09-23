package sessionrecording

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/sessionaudit"
)

// auditBuffer captures the JSON lines a writer-backed Emitter produces.
type auditBuffer struct {
	mu    sync.Mutex
	lines [][]byte
}

func (b *auditBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = append(b.lines, append([]byte(nil), p...))
	return len(p), nil
}

func (b *auditBuffer) events(kind string) []sessionaudit.SessionAuditEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []sessionaudit.SessionAuditEvent
	for _, l := range b.lines {
		var ev sessionaudit.SessionAuditEvent
		if json.Unmarshal(l, &ev) == nil && ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

// slowSink acknowledges every batch after delay.
type slowSink struct {
	memSink
	delay time.Duration
}

func (s *slowSink) WriteBatch(ctx context.Context, events []TerminalEvent) error {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return ctx.Err()
	}
	return s.memSink.WriteBatch(ctx, events)
}

type runResult struct {
	err error
	at  time.Time
}

func startRun(t *testing.T, rec *Recorder) (chan runResult, func(string)) {
	t.Helper()
	childPtm, cmd := startCatChild(t)
	outerPtm, outerPts := openOuterPty(t)
	done := make(chan runResult, 1)
	go func() {
		err := rec.Run(context.Background(), childPtm, outerPtm, outerPtm)
		done <- runResult{err: err, at: time.Now()}
	}()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	write := func(s string) {
		if _, err := outerPts.Write([]byte(s)); err != nil {
			t.Fatalf("write outer: %v", err)
		}
	}
	return done, write
}

func killAndWait(t *testing.T, done chan runResult, within time.Duration) runResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(within):
		t.Fatalf("Run did not return within %s", within)
		return runResult{}
	}
}

// TestRecorderFailClosedIdleSessionSurvives is the F7 regression: a healthy
// session with nothing pending must never be killed for being quiet.
func TestRecorderFailClosedIdleSessionSurvives(t *testing.T) {
	sink := &memSink{}
	grace := 100 * time.Millisecond
	rec := New(Options{Mode: ModeTerminalOutput, SessionID: "sess-idle", FailurePolicy: FailurePolicyFailClosed, QueueEvents: 64, FlushInterval: 10 * time.Millisecond, FailureGrace: grace}, sink, testEmitter(t))
	childPtm, cmd := startCatChild(t)
	outerPtm, outerPts := openOuterPty(t)
	done := make(chan error, 1)
	go func() { done <- rec.Run(context.Background(), childPtm, outerPtm, outerPtm) }()

	if _, err := outerPts.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	waitForEvent(t, sink, func(ev TerminalEvent) bool { return ev.Stream == StreamTTYOutput }, 2*time.Second)

	select {
	case err := <-done:
		t.Fatalf("idle healthy session ended after %v of silence: %v", 6*grace, err)
	case <-time.After(6 * grace):
	}

	_ = cmd.Process.Kill()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v after a normal end, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after the child exited")
	}
	if f := sink.finishes(); len(f) != 1 || !f[0].Complete {
		t.Fatalf("finish = %+v, want exactly one complete finish", f)
	}
}

// TestRecorderFailClosedSustainedFailureTerminates: a hung sink (Write
// never returns on its own) still trips the wall-clock watchdog, and Run
// returns within FailureGrace plus the bounded stop window.
func TestRecorderFailClosedSustainedFailureTerminates(t *testing.T) {
	sink := &memSink{block: true}
	grace := 150 * time.Millisecond
	rec := New(Options{Mode: ModeTerminalOutput, SessionID: "sess-hung", FailurePolicy: FailurePolicyFailClosed, QueueEvents: 64, FailureGrace: grace}, sink, testEmitter(t))
	done, write := startRun(t, rec)
	start := time.Now()
	write("trigger\n")

	r := killAndWait(t, done, 3*time.Second)
	if !errors.Is(r.err, ErrRecordingFailedClosed) {
		t.Fatalf("Run = %v, want ErrRecordingFailedClosed", r.err)
	}
	if elapsed := r.at.Sub(start); elapsed > 2*time.Second {
		t.Fatalf("Run took %v against a hung sink, want roughly FailureGrace", elapsed)
	}
	if f := sink.finishes(); len(f) != 1 || f[0].Complete || f[0].Reason != "fail_closed" {
		t.Fatalf("finish = %+v, want one incomplete fail_closed finish", f)
	}
}

// TestRecorderFailClosedPermanentErrorImmediate: a sink error means the
// event is lost, so fail_closed ends the session without waiting out a
// long grace.
func TestRecorderFailClosedPermanentErrorImmediate(t *testing.T) {
	sink := &memSink{fail: true}
	rec := New(Options{Mode: ModeTerminalOutput, SessionID: "sess-perm", FailurePolicy: FailurePolicyFailClosed, QueueEvents: 64, FailureGrace: time.Minute}, sink, testEmitter(t))
	done, write := startRun(t, rec)
	write("x\n")
	r := killAndWait(t, done, 5*time.Second)
	if !errors.Is(r.err, ErrRecordingFailedClosed) {
		t.Fatalf("Run = %v, want ErrRecordingFailedClosed", r.err)
	}
}

// TestRecorderFailClosedBackpressureNoDrops: with a one-slot queue and a
// slow sink, fail_closed blocks the relay instead of dropping, so every
// assigned seq reaches the sink.
func TestRecorderFailClosedBackpressureNoDrops(t *testing.T) {
	sink := &slowSink{delay: 5 * time.Millisecond}
	rec := New(Options{Mode: ModeTerminalIO, SessionID: "sess-bp", FailurePolicy: FailurePolicyFailClosed, QueueEvents: 1, FailureGrace: 5 * time.Second}, sink, testEmitter(t))
	childPtm, cmd := startCatChild(t)
	outerPtm, outerPts := openOuterPty(t)
	done := make(chan error, 1)
	go func() { done <- rec.Run(context.Background(), childPtm, outerPtm, outerPtm) }()
	for i := 0; i < 20; i++ {
		if _, err := outerPts.Write([]byte("line\n")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	_ = cmd.Process.Kill()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	events := sink.snapshot()
	seen := map[uint64]bool{}
	for _, ev := range events {
		seen[ev.Seq] = true
	}
	f := sink.finishes()
	if len(f) != 1 {
		t.Fatalf("finishes = %+v", f)
	}
	for seq := uint64(1); seq <= f[0].LastSeq; seq++ {
		if !seen[seq] {
			t.Fatalf("seq %d never reached the sink under fail_closed backpressure (last_seq %d)", seq, f[0].LastSeq)
		}
	}
	if !f[0].Complete {
		t.Fatalf("finish = %+v, want complete", f[0])
	}
}

func TestRecorderBestEffortSinkErrorEmitsGap(t *testing.T) {
	sink := &memSink{fail: true}
	audit := &auditBuffer{}
	rec := New(Options{
		Mode: ModeTerminalOutput, SessionID: "sess-be-err", FailurePolicy: FailurePolicyBestEffort, QueueEvents: 64,
		FailureGrace: 200 * time.Millisecond,
		Identity:     AuditIdentity{User: "alice", TargetFQDN: "db.example.test", GatewayID: "gw01", GatewayScope: "gpu"},
	}, sink, sessionaudit.NewWriterEmitter("test", audit))
	childPtm, cmd := startCatChild(t)
	outerPtm, outerPts := openOuterPty(t)
	done := make(chan error, 1)
	go func() { done <- rec.Run(context.Background(), childPtm, outerPtm, outerPtm) }()
	if _, err := outerPts.Write([]byte("x\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("best_effort session ended on a sink error: %v", err)
	default:
	}
	_ = cmd.Process.Kill()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v", err)
	}
	gaps := audit.events(sessionaudit.KindRecordingGap)
	if len(gaps) == 0 || !strings.Contains(gaps[0].Result, "sink error") {
		t.Fatalf("recording_gap events = %+v, want one for the sink error", gaps)
	}
	if f := sink.finishes(); len(f) != 1 || f[0].Complete || f[0].Reason != "sink_error" {
		t.Fatalf("finish = %+v, want incomplete sink_error", f)
	}
}

func TestRecorderBestEffortQueueFullDropsAndIncomplete(t *testing.T) {
	sink := &slowSink{delay: 50 * time.Millisecond}
	// A 1ms flush keeps the writer inside slow WriteBatch calls, so the
	// one-slot queue overflows.
	rec := New(Options{Mode: ModeTerminalIO, SessionID: "sess-be-drop", FailurePolicy: FailurePolicyBestEffort, QueueEvents: 1, FlushInterval: time.Millisecond, FailureGrace: 5 * time.Second}, sink, testEmitter(t))
	childPtm, cmd := startCatChild(t)
	outerPtm, outerPts := openOuterPty(t)
	done := make(chan error, 1)
	go func() { done <- rec.Run(context.Background(), childPtm, outerPtm, outerPtm) }()
	// Paced writes arrive as separate chunks while the sink is busy for
	// 50ms, so the one-slot queue must overflow.
	for i := 0; i < 40; i++ {
		_, _ = outerPts.Write([]byte("burst\n"))
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	f := sink.finishes()
	if len(f) != 1 || f[0].Complete || f[0].Reason != "dropped" {
		t.Fatalf("finish = %+v, want incomplete dropped", f)
	}
	if got := uint64(len(sink.snapshot())); got >= f[0].LastSeq {
		t.Fatalf("sink got %d events for last_seq %d; the test did not overflow the queue", got, f[0].LastSeq)
	}
}

func TestRecorderFinishCompleteOnlyWhenClean(t *testing.T) {
	sink := &memSink{}
	rec := New(Options{Mode: ModeTerminalIO, SessionID: "sess-clean", FailurePolicy: FailurePolicyBestEffort, QueueEvents: 64}, sink, testEmitter(t))
	childPtm, cmd := startCatChild(t)
	outerPtm, outerPts := openOuterPty(t)
	done := make(chan error, 1)
	go func() { done <- rec.Run(context.Background(), childPtm, outerPtm, outerPtm) }()
	_, _ = outerPts.Write([]byte("ok\n"))
	waitForEvent(t, sink, func(ev TerminalEvent) bool { return ev.Stream == StreamTTYOutput }, 2*time.Second)
	_ = cmd.Process.Kill()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	f := sink.finishes()
	if len(f) != 1 || !f[0].Complete || f[0].Reason != "" {
		t.Fatalf("finish = %+v, want one complete finish", f)
	}
	if got := uint64(len(sink.snapshot())); got != f[0].LastSeq {
		t.Fatalf("last_seq %d but the sink holds %d events", f[0].LastSeq, got)
	}
}

// TestRecorderAbortedContextIsIncomplete: a caller-cancelled session is not
// a clean end.
func TestRecorderAbortedContextIsIncomplete(t *testing.T) {
	sink := &memSink{}
	rec := New(Options{Mode: ModeTerminalOutput, SessionID: "sess-abort", QueueEvents: 64, FailureGrace: 200 * time.Millisecond}, sink, testEmitter(t))
	childPtm, _ := startCatChild(t)
	outerPtm, _ := openOuterPty(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, childPtm, outerPtm, outerPtm) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	if f := sink.finishes(); len(f) != 1 || f[0].Complete || f[0].Reason != "aborted" {
		t.Fatalf("finish = %+v, want incomplete aborted", f)
	}
}

func TestRecorderDrainTimeoutCancelsWriter(t *testing.T) {
	sink := &memSink{block: true}
	grace := 150 * time.Millisecond
	rec := New(Options{Mode: ModeTerminalOutput, SessionID: "sess-drain", FailurePolicy: FailurePolicyBestEffort, QueueEvents: 64, FailureGrace: grace}, sink, testEmitter(t))
	childPtm, cmd := startCatChild(t)
	outerPtm, outerPts := openOuterPty(t)
	done := make(chan error, 1)
	go func() { done <- rec.Run(context.Background(), childPtm, outerPtm, outerPtm) }()
	_, _ = outerPts.Write([]byte("pending\n"))
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return: the drain was not bounded")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("drain took %v, want about FailureGrace", elapsed)
	}
	if f := sink.finishes(); len(f) != 1 || f[0].Complete || f[0].Reason != "drain_timeout" {
		t.Fatalf("finish = %+v, want incomplete drain_timeout", f)
	}
}

func TestRecorderEnqueueReturnsAfterWriterStops(t *testing.T) {
	rec := New(Options{Mode: ModeTerminalOutput, SessionID: "sess-late", FailurePolicy: FailurePolicyFailClosed, QueueEvents: 1}, &memSink{}, testEmitter(t))
	events := make(chan TerminalEvent, 1)
	events <- TerminalEvent{} // full
	close(rec.writerStopped)
	returned := make(chan struct{})
	go func() {
		rec.enqueue(events, TerminalEvent{Stream: StreamTTYOutput})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("enqueue blocked forever on a full queue after the writer stopped")
	}
}

func TestRecorderDefaultFailureGrace(t *testing.T) {
	rec := New(Options{Mode: ModeTerminalOutput, SessionID: "sess-default"}, &memSink{}, testEmitter(t))
	if rec.opts.FailureGrace != defaultFailureGrace || defaultFailureGrace != 10*time.Second {
		t.Fatalf("default FailureGrace = %v", rec.opts.FailureGrace)
	}
	if rec.opts.FailurePolicy != FailurePolicyBestEffort || rec.opts.QueueEvents != 1024 {
		t.Fatalf("defaults = %+v", rec.opts)
	}
}

func TestRecorderAuditEventsCarryIdentity(t *testing.T) {
	audit := &auditBuffer{}
	id := AuditIdentity{User: "alice", TargetFQDN: "db.example.test", GatewayID: "gw01", GatewayScope: "gpu"}
	rec := New(Options{Mode: ModeTerminalOutput, SessionID: "sess-id", FailurePolicy: FailurePolicyFailClosed, QueueEvents: 8, FailureGrace: time.Minute, Identity: id},
		&memSink{fail: true}, sessionaudit.NewWriterEmitter("test", audit))
	done, write := startRun(t, rec)
	write("x\n")
	killAndWait(t, done, 5*time.Second)
	failed := audit.events(sessionaudit.KindRecordingFailed)
	if len(failed) == 0 {
		t.Fatalf("no recording_failed event; audit = %s", bytes.Join(audit.lines, []byte("\n")))
	}
	ev := failed[0]
	if ev.User != id.User || ev.TargetFQDN != id.TargetFQDN || ev.GatewayID != id.GatewayID || ev.GatewayScope != id.GatewayScope || ev.SessionID != "sess-id" || ev.RecordingMode != ModeTerminalOutput {
		t.Fatalf("recording_failed = %+v, want the session identity", ev)
	}
}

func TestRecorderInputDoneClosesWhenInputRelayEnds(t *testing.T) {
	sink := &memSink{}
	rec := New(Options{Mode: ModeTerminalOutput, SessionID: "sess-input-done", QueueEvents: 8}, sink, testEmitter(t))
	childPtm, cmd := startCatChild(t)
	in := &closingReader{ch: make(chan struct{})}
	outerPtm, _ := openOuterPty(t)
	done := make(chan error, 1)
	go func() { done <- rec.Run(context.Background(), childPtm, in, outerPtm) }()
	select {
	case <-rec.InputDone():
		t.Fatal("InputDone closed while the input relay was still reading")
	case <-time.After(50 * time.Millisecond):
	}
	close(in.ch) // the reader returns EOF, like a cancelled cancelreader
	select {
	case <-rec.InputDone():
	case <-time.After(2 * time.Second):
		t.Fatal("InputDone never closed after the input reader ended")
	}
	_ = cmd.Process.Kill()
	<-done
}

// closingReader blocks in Read until ch is closed, then reports EOF.
type closingReader struct{ ch chan struct{} }

func (r *closingReader) Read([]byte) (int, error) {
	<-r.ch
	return 0, io.EOF
}

// TestRecorderFailClosedStopsRelaying: once fail_closed trips, nothing more
// crosses the relay in either direction, even while Run is still draining
// and finishing (found live, per-host recording spec L13: output kept
// flowing, unrecorded, for the length of the finish attempt).
func TestRecorderFailClosedStopsRelaying(t *testing.T) {
	sink := &memSink{block: true}
	rec := New(Options{Mode: ModeTerminalOutput, SessionID: "sess-stop", FailurePolicy: FailurePolicyFailClosed, QueueEvents: 64, FlushInterval: 10 * time.Millisecond, FailureGrace: 150 * time.Millisecond}, sink, testEmitter(t))
	childPtm, cmd := startCatChild(t)
	outerPtm, outerPts := openOuterPty(t)
	done := make(chan error, 1)
	go func() { done <- rec.Run(context.Background(), childPtm, outerPtm, outerPtm) }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	if _, err := outerPts.Write([]byte("before\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rec.failClosedCh:
	case <-time.After(3 * time.Second):
		t.Fatal("fail_closed never tripped against a hung sink")
	}

	var seen bytes.Buffer
	var mu sync.Mutex
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := outerPts.Read(buf)
			mu.Lock()
			seen.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	if _, err := outerPts.Write([]byte("AFTER_TRIP_MARKER\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	leaked := strings.Contains(seen.String(), "AFTER_TRIP_MARKER")
	mu.Unlock()
	if leaked {
		t.Fatal("input typed after fail_closed reached the child and its echo came back unrecorded")
	}
	_ = cmd.Process.Kill()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRecordingFailedClosed) {
			t.Fatalf("Run = %v, want ErrRecordingFailedClosed", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Run did not return")
	}
}
