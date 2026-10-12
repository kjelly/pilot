package sessionrecording

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"

	"github.com/kjelly/pilot/internal/sessionaudit"
)

// unixIsTerminalRaw reports whether f's termios currently has ICANON
// cleared — the defining characteristic term.MakeRaw toggles off and
// term.Restore toggles back on. Used to prove Run's raw-mode
// enter/restore actually round-trips even when the sink is failing
// throughout the session.
func unixIsTerminalRaw(f *os.File) (bool, error) {
	t, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if err != nil {
		return false, err
	}
	return t.Lflag&unix.ICANON == 0, nil
}

// memSink is a fake Sink that records every event it receives for
// assertions, and can be told to fail every WriteBatch for fail_closed
// testing.
type memSink struct {
	mu       sync.Mutex
	events   []TerminalEvent
	fail     bool
	finished []FinishInfo
	// block, when set, makes WriteBatch wait until ctx ends (a hung sink).
	block bool
	// batches records the size of every successful WriteBatch.
	batches []int
}

func (s *memSink) WriteBatch(ctx context.Context, events []TerminalEvent) error {
	s.mu.Lock()
	block := s.block
	s.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return context_DeadlineExceededLike{}
	}
	s.events = append(s.events, events...)
	s.batches = append(s.batches, len(events))
	return nil
}

func (s *memSink) Finish(_ context.Context, info FinishInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finished = append(s.finished, info)
	return nil
}

func (s *memSink) finishes() []FinishInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]FinishInfo(nil), s.finished...)
}

func (s *memSink) snapshot() []TerminalEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TerminalEvent, len(s.events))
	copy(out, s.events)
	return out
}

// context_DeadlineExceededLike is just a distinct error type for the
// fail-injection path above, named oddly on purpose to avoid colliding
// with anything real — it carries no meaning beyond "the sink failed".
type context_DeadlineExceededLike struct{}

func (context_DeadlineExceededLike) Error() string { return "injected sink failure" }

func testEmitter(t *testing.T) *sessionaudit.Emitter {
	t.Helper()
	e, err := sessionaudit.NewEmitter("sessionrecording-test")
	if err != nil {
		t.Fatalf("sessionaudit.NewEmitter: %v", err)
	}
	return e
}

// startCatChild starts a real "cat" child process attached to a real
// pty, returning the master *os.File (what a real ssh child's pty master
// would be) and the process for cleanup. cat echoes whatever it reads on
// stdin back out on stdout — both visible on the same master fd, exactly
// like PTY mode merges stdout/stderr in a real target session.
func startCatChild(t *testing.T) (*os.File, *exec.Cmd) {
	t.Helper()
	cmd := exec.Command("cat")
	ptm, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("pty.Start(cat): %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = ptm.Close()
	})
	return ptm, cmd
}

// openOuterPty opens a real pty pair standing in for the local SSH
// client's controlling terminal: the master (returned) is what Recorder
// treats as outerIn/outerOut, and the test drives/observes it through the
// slave, exactly as a real terminal emulator would from the other side of
// a real tty.
func openOuterPty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	ptm, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("pty.Open (outer): %v", err)
	}
	t.Cleanup(func() {
		_ = ptm.Close()
		_ = pts.Close()
	})
	return ptm, pts
}

func waitForEvent(t *testing.T, sink *memSink, pred func(TerminalEvent) bool, timeout time.Duration) TerminalEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, ev := range sink.snapshot() {
			if pred(ev) {
				return ev
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for matching event; got %+v", sink.snapshot())
	return TerminalEvent{}
}

func TestRecorderTerminalIOCapturesBothDirections(t *testing.T) {
	childPtm, cmd := startCatChild(t)
	outerPtm, outerPts := openOuterPty(t)

	sink := &memSink{}
	rec := New(Options{Mode: ModeTerminalIO, SessionID: "sess-io", FailurePolicy: FailurePolicyBestEffort, QueueEvents: 64, FailureGrace: 500 * time.Millisecond}, sink, testEmitter(t))

	runDone := make(chan error, 1)
	go func() { runDone <- rec.Run(context.Background(), childPtm, outerPtm, outerPtm) }()

	// Simulate the user typing "hello\n" — write on the slave side, which
	// is what a real terminal emulator delivers to whatever reads the
	// master (Recorder's outerIn).
	if _, err := outerPts.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write to outer pty slave: %v", err)
	}

	waitForEvent(t, sink, func(ev TerminalEvent) bool {
		return ev.Stream == StreamTTYInput && ev.DataBase64 != "" && ev.RedactedBytes == 0
	}, 2*time.Second)
	waitForEvent(t, sink, func(ev TerminalEvent) bool {
		return ev.Stream == StreamTTYOutput && ev.DataBase64 != ""
	}, 2*time.Second)

	_ = cmd.Process.Kill()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned error after child exit: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Run did not return after killing the child")
	}
}

func TestRecorderTerminalOutputNeverRecordsInput(t *testing.T) {
	childPtm, cmd := startCatChild(t)
	outerPtm, outerPts := openOuterPty(t)

	sink := &memSink{}
	rec := New(Options{Mode: ModeTerminalOutput, SessionID: "sess-out", FailurePolicy: FailurePolicyBestEffort, QueueEvents: 64, FailureGrace: 500 * time.Millisecond}, sink, testEmitter(t))

	runDone := make(chan error, 1)
	go func() { runDone <- rec.Run(context.Background(), childPtm, outerPtm, outerPtm) }()

	if _, err := outerPts.Write([]byte("secret-command\n")); err != nil {
		t.Fatalf("write to outer pty slave: %v", err)
	}
	// Give the relay time to process the write and produce at least the
	// output-side echo before asserting the negative.
	waitForEvent(t, sink, func(ev TerminalEvent) bool { return ev.Stream == StreamTTYOutput }, 2*time.Second)

	for _, ev := range sink.snapshot() {
		if ev.Stream == StreamTTYInput {
			t.Fatalf("terminal_output mode recorded a tty_input event: %+v", ev)
		}
	}

	_ = cmd.Process.Kill()
	select {
	case <-runDone:
	case <-time.After(3 * time.Second):
		t.Fatalf("Run did not return after killing the child")
	}
}

// TestRecorderFailClosedTerminatesSession proves spec.md §27's fail_closed
// policy actually does what it promises: after the sink has been failing
// for longer than flushGrace, Run returns ErrRecordingFailedClosed —
// proving the caller (runPortalOneShotConnect) gets a real, unmissable
// signal to terminate the target session rather than silently continuing
// unrecorded. A tiny flushGrace keeps this test fast without touching
// Run's real logic.
func TestRecorderFailClosedTerminatesSession(t *testing.T) {
	childPtm, cmd := startCatChild(t)
	outerPtm, outerPts := openOuterPty(t)

	sink := &memSink{fail: true}
	rec := New(Options{Mode: ModeTerminalIO, SessionID: "sess-failclosed", FailurePolicy: FailurePolicyFailClosed, QueueEvents: 8, FailureGrace: 50 * time.Millisecond}, sink, testEmitter(t))

	runDone := make(chan error, 1)
	go func() { runDone <- rec.Run(context.Background(), childPtm, outerPtm, outerPtm) }()

	if _, err := outerPts.Write([]byte("trigger\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case err := <-runDone:
		if !errors.Is(err, ErrRecordingFailedClosed) {
			t.Fatalf("Run returned %v, want ErrRecordingFailedClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Run did not return within 3s of a permanently failing sink under fail_closed")
	}

	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func TestRecorderResizeProducesEvent(t *testing.T) {
	childPtm, cmd := startCatChild(t)
	outerPtm, _ := openOuterPty(t)

	sink := &memSink{}
	rec := New(Options{Mode: ModeTerminalIO, SessionID: "sess-resize", FailurePolicy: FailurePolicyBestEffort, QueueEvents: 64, FailureGrace: 500 * time.Millisecond}, sink, testEmitter(t))

	runDone := make(chan error, 1)
	go func() { runDone <- rec.Run(context.Background(), childPtm, outerPtm, outerPtm) }()

	// Give watchResize's goroutine a moment to install its signal handler
	// before the window actually changes and SIGWINCH is raised.
	time.Sleep(100 * time.Millisecond)
	if err := pty.Setsize(outerPtm, &pty.Winsize{Rows: 55, Cols: 199}); err != nil {
		t.Fatalf("pty.Setsize(outer): %v", err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatalf("self-signal SIGWINCH: %v", err)
	}

	ev := waitForEvent(t, sink, func(ev TerminalEvent) bool { return ev.Stream == StreamResize }, 2*time.Second)
	if ev.Rows != 55 || ev.Cols != 199 {
		t.Fatalf("resize event = rows=%d cols=%d, want rows=55 cols=199", ev.Rows, ev.Cols)
	}
	if ev.DataBase64 != "" {
		t.Fatalf("resize event carried DataBase64 = %q, want empty", ev.DataBase64)
	}

	_ = cmd.Process.Kill()
	select {
	case <-runDone:
	case <-time.After(3 * time.Second):
		t.Fatalf("Run did not return after killing the child")
	}
}

func TestRecorderRestoresTerminalOnSinkFailure(t *testing.T) {
	childPtm, cmd := startCatChild(t)
	outerPtm, outerPts := openOuterPty(t)

	sink := &memSink{fail: true}
	rec := New(Options{Mode: ModeTerminalIO, SessionID: "sess-fail", FailurePolicy: FailurePolicyBestEffort, QueueEvents: 8, FailureGrace: 200 * time.Millisecond}, sink, testEmitter(t))

	before, err := unixIsTerminalRaw(outerPts)
	if err != nil {
		t.Fatalf("read initial termios: %v", err)
	}

	runDone := make(chan error, 1)
	go func() { runDone <- rec.Run(context.Background(), childPtm, outerPtm, outerPtm) }()

	if _, err := outerPts.Write([]byte(bytes.Repeat([]byte("x"), 4096))); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // let backpressure/drops happen

	_ = cmd.Process.Kill()
	select {
	case <-runDone:
	case <-time.After(3 * time.Second):
		t.Fatalf("Run did not return")
	}

	after, err := unixIsTerminalRaw(outerPts)
	if err != nil {
		t.Fatalf("read termios after Run: %v", err)
	}
	if before != after {
		t.Fatalf("outer terminal raw-mode state changed across a failing sink (before raw=%v after raw=%v) — terminal left in a different mode than it started", before, after)
	}
}

// TestRecorderInitialResizeIsFirstEvent locks per-host recording spec
// §18.3 step 7: the caller's InitialSize is recorded as seq=1, a resize,
// before any relayed output.
func TestRecorderInitialResizeIsFirstEvent(t *testing.T) {
	childPtm, cmd := startCatChild(t)
	outerPtm, outerPts := openOuterPty(t)
	sink := &memSink{}
	rec := New(Options{Mode: ModeTerminalOutput, SessionID: "sess-initial", QueueEvents: 64, FlushInterval: 10 * time.Millisecond, InitialSize: Winsize{Rows: 42, Cols: 133}}, sink, testEmitter(t))
	runDone := make(chan error, 1)
	go func() { runDone <- rec.Run(context.Background(), childPtm, outerPtm, outerPtm) }()
	if _, err := outerPts.Write([]byte("hi\n")); err != nil {
		t.Fatal(err)
	}
	waitForEvent(t, sink, func(ev TerminalEvent) bool { return ev.Stream == StreamTTYOutput }, 2*time.Second)
	_ = cmd.Process.Kill()
	select {
	case <-runDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after killing the child")
	}
	events := sink.snapshot()
	if len(events) == 0 || events[0].Seq != 1 || events[0].Stream != StreamResize || events[0].Rows != 42 || events[0].Cols != 133 {
		t.Fatalf("first event = %+v, want seq 1 resize 42x133", events)
	}
}
