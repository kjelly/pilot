//go:build linux || darwin || freebsd

// L4 integration tests: build the real test binary for this package
// (which embeds the production promptRoleChecklist/roleChecklistModel
// code, not a reimplementation) and drive it inside a real PTY —
// covering raw-mode key delivery, resize, scroll, cancel and terminal
// cursor restore on exit. TestRoleChecklistHelperProcess below is the
// re-exec'd subprocess entrypoint; it is a no-op under a normal
// `go test` run.
//
// Keystrokes are sent one at a time with a short pause (see
// checklistPTY.press) rather than blasted in a single write. Writing
// several keys (e.g. "jj") in one call was observed to reliably drop
// all but one of them before the model ever saw them — this repro'd
// 100% of the time across repeated runs, independent of load, so it's
// pacing the input like a real keypress stream, not papering over a
// flaky race with a blind sleep.
package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
)

// ---- helper subprocess entrypoint ------------------------------------------

// TestRoleChecklistHelperProcess is not itself a PTY test. When the
// compiled test binary is re-invoked with
// PILOT_ROLE_CHECKLIST_HELPER=1 (see startChecklistPTY), it runs the
// real promptRoleChecklist screen against the process's real stdio —
// the PTY slave — and reports the outcome on stdout before exiting.
// Under a plain `go test ./...` run the env var is unset, so this is
// a one-line skip.
func TestRoleChecklistHelperProcess(t *testing.T) {
	if os.Getenv("PILOT_ROLE_CHECKLIST_HELPER") != "1" {
		t.Skip("only runs as a PTY E2E helper subprocess")
	}

	n := 3
	if v := os.Getenv("PILOT_ROLE_CHECKLIST_ITEM_COUNT"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			n = parsed
		}
	}
	roles := make([]struct{ Name, Description string }, n)
	for i := range roles {
		roles[i] = struct{ Name, Description string }{
			Name:        fmt.Sprintf("role-%02d", i),
			Description: fmt.Sprintf("desc-%02d", i),
		}
	}
	var selected []string
	if v := os.Getenv("PILOT_ROLE_CHECKLIST_SELECTED"); v != "" {
		selected = strings.Split(v, ",")
	}

	out, err := promptRoleChecklist("PTY E2E", roles, selected)
	switch {
	case errors.Is(err, errDeployAborted):
		fmt.Println("HELPER_CANCELED")
		os.Exit(3)
	case err != nil:
		fmt.Println("HELPER_ERROR:" + err.Error())
		os.Exit(1)
	default:
		fmt.Println("HELPER_RESULT:" + strings.Join(out, ","))
		os.Exit(0)
	}
}

// ---- shared binary build ----------------------------------------------------

var (
	checklistBinaryOnce sync.Once
	checklistBinaryPath string
	checklistBinaryErr  error
	checklistBinaryDir  string
)

// buildRoleChecklistTestBinary compiles this package's test binary
// once and reuses it across all PTY tests below (it embeds
// TestRoleChecklistHelperProcess, so it's a real compiled binary
// containing the production code, not a mock).
func buildRoleChecklistTestBinary(t *testing.T) string {
	t.Helper()
	checklistBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "pilot-role-checklist-pty")
		if err != nil {
			checklistBinaryErr = err
			return
		}
		checklistBinaryDir = dir
		out := filepath.Join(dir, "role_checklist_helper.test")
		cmd := exec.Command("go", "test", "-c", "-o", out, ".")
		combined, err := cmd.CombinedOutput()
		if err != nil {
			checklistBinaryErr = fmt.Errorf("build helper test binary: %w\n%s", err, combined)
			return
		}
		checklistBinaryPath = out
	})
	if checklistBinaryErr != nil {
		t.Fatalf("%v", checklistBinaryErr)
	}
	return checklistBinaryPath
}

func TestMain(m *testing.M) {
	code := m.Run()
	if checklistBinaryDir != "" {
		_ = os.RemoveAll(checklistBinaryDir)
	}
	os.Exit(code)
}

// ---- PTY driver --------------------------------------------------------------

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

type checklistPTY struct {
	f       *os.File
	cmd     *exec.Cmd
	out     *safeBuffer
	doneCh  chan struct{}
	waitErr error
}

func startChecklistPTY(t *testing.T, env []string, rows, cols uint16) *checklistPTY {
	t.Helper()
	bin := buildRoleChecklistTestBinary(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	cmd := exec.CommandContext(ctx, bin, "-test.run=^TestRoleChecklistHelperProcess$", "-test.v")
	cmd.Env = append(append([]string{}, os.Environ()...), env...)
	// CI=1 makes termenv's isTTY() check false (see
	// github.com/muesli/termenv Output.isTTY), which skips the OSC
	// background-color query that github.com/charmbracelet/bubbletea's
	// package init() triggers unconditionally via
	// lipgloss.HasDarkBackground() — without it the helper blocks for
	// termenv.OSCTimeout (5s) waiting for a reply nothing in this PTY
	// setup will ever send.
	cmd.Env = append(cmd.Env, "PILOT_ROLE_CHECKLIST_HELPER=1", "TERM=xterm-256color", "CI=1")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: rows, Cols: cols})
	if err != nil {
		t.Fatalf("start PTY: %v", err)
	}

	proc := &checklistPTY{f: ptmx, cmd: cmd, out: &safeBuffer{}, doneCh: make(chan struct{})}
	go func() { _, _ = io.Copy(proc.out, ptmx) }()
	go func() {
		proc.waitErr = cmd.Wait()
		close(proc.doneCh)
	}()

	t.Cleanup(func() {
		_ = ptmx.Close()
		select {
		case <-proc.doneCh:
		case <-time.After(2 * time.Second):
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			<-proc.doneCh
		}
	})
	return proc
}

func (p *checklistPTY) write(t *testing.T, s string) {
	t.Helper()
	if _, err := io.WriteString(p.f, s); err != nil {
		t.Fatalf("write PTY input: %v", err)
	}
}

// keyPressSettle is a short pause between individual keystrokes.
// Blasting several keys into the PTY in one write with no pacing at
// all is not representative of a real keypress stream and was
// observed to drop messages (see the file-level comment); this pause
// is deliberate pacing for input delivery, not a wait for an
// assertion to become true.
const keyPressSettle = 30 * time.Millisecond

// press writes a single keystroke and pauses briefly, mimicking a
// real user typing rather than blasting the whole input in one write.
func (p *checklistPTY) press(t *testing.T, s string) {
	t.Helper()
	p.write(t, s)
	time.Sleep(keyPressSettle)
}

func (p *checklistPTY) resize(t *testing.T, rows, cols uint16) {
	t.Helper()
	if err := pty.Setsize(p.f, &pty.Winsize{Rows: rows, Cols: cols}); err != nil {
		t.Fatalf("resize PTY: %v", err)
	}
}

// waitExit blocks until the subprocess exits (or timeout) and returns
// its exit code.
func (p *checklistPTY) waitExit(t *testing.T, timeout time.Duration) int {
	t.Helper()
	select {
	case <-p.doneCh:
	case <-time.After(timeout):
		t.Fatalf("process did not exit within %s; output so far:\n%s", timeout, p.out.String())
	}
	if p.waitErr == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(p.waitErr, &exitErr) {
		return exitErr.ExitCode()
	}
	t.Fatalf("process wait error: %v", p.waitErr)
	return -1
}

func waitForOutput(t *testing.T, buf *safeBuffer, timeout time.Duration, want string) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cur := buf.String()
		if strings.Contains(cur, want) {
			return cur
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %q in output:\n%s", timeout, want, buf.String())
	return ""
}

// ---- tests -------------------------------------------------------------------

func TestRoleChecklistPTY_HappyPath(t *testing.T) {
	proc := startChecklistPTY(t, []string{"PILOT_ROLE_CHECKLIST_ITEM_COUNT=3"}, 30, 100)

	waitForOutput(t, proc.out, 3*time.Second, "role-00")

	proc.press(t, "j")
	proc.press(t, "j")  // move cursor to role-02
	proc.press(t, " ")  // toggle it on
	proc.press(t, "\r") // enter -> confirm

	code := proc.waitExit(t, 5*time.Second)
	final := proc.out.String()
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, final)
	}
	if !strings.Contains(final, "HELPER_RESULT:role-02") {
		t.Fatalf("expected HELPER_RESULT:role-02 in output, got:\n%s", final)
	}
	if !strings.Contains(final, "\x1b[?25h") {
		t.Fatalf("expected the cursor-restore sequence after exit, got:\n%s", final)
	}
}

func TestRoleChecklistPTY_PreselectedRoleSurvivesUntouched(t *testing.T) {
	proc := startChecklistPTY(t, []string{
		"PILOT_ROLE_CHECKLIST_ITEM_COUNT=3",
		"PILOT_ROLE_CHECKLIST_SELECTED=role-01",
	}, 30, 100)

	waitForOutput(t, proc.out, 3*time.Second, "role-00")
	proc.press(t, "\r") // confirm immediately, no toggles

	code := proc.waitExit(t, 5*time.Second)
	final := proc.out.String()
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, final)
	}
	if !strings.Contains(final, "HELPER_RESULT:role-01") {
		t.Fatalf("expected the pre-selected role-01 unchanged, got:\n%s", final)
	}
}

func TestRoleChecklistPTY_EscCancels(t *testing.T) {
	proc := startChecklistPTY(t, []string{"PILOT_ROLE_CHECKLIST_ITEM_COUNT=3"}, 30, 100)

	waitForOutput(t, proc.out, 3*time.Second, "role-00")
	proc.press(t, " ")    // toggle something — must not survive a cancel
	proc.press(t, "\x1b") // esc

	code := proc.waitExit(t, 5*time.Second)
	final := proc.out.String()
	if code != 3 {
		t.Fatalf("exit code = %d, want 3 (canceled)\noutput:\n%s", code, final)
	}
	if !strings.Contains(final, "HELPER_CANCELED") {
		t.Fatalf("expected HELPER_CANCELED in output, got:\n%s", final)
	}
}

func TestRoleChecklistPTY_RealCtrlCKeystrokeCancels(t *testing.T) {
	proc := startChecklistPTY(t, []string{"PILOT_ROLE_CHECKLIST_ITEM_COUNT=3"}, 30, 100)

	waitForOutput(t, proc.out, 3*time.Second, "role-00")
	proc.press(t, "\x03") // real ctrl+c byte, delivered as a keystroke under raw mode

	code := proc.waitExit(t, 5*time.Second)
	final := proc.out.String()
	if code != 3 {
		t.Fatalf("exit code = %d, want 3 (canceled)\noutput:\n%s", code, final)
	}
	if !strings.Contains(final, "HELPER_CANCELED") {
		t.Fatalf("expected HELPER_CANCELED in output, got:\n%s", final)
	}
}

func TestRoleChecklistPTY_ResizeUpdatesScrollWindowThenExits(t *testing.T) {
	proc := startChecklistPTY(t, []string{"PILOT_ROLE_CHECKLIST_ITEM_COUNT=20"}, 12, 50)

	waitForOutput(t, proc.out, 3*time.Second, "還有")

	proc.resize(t, 30, 100)
	for i := 0; i < 6; i++ {
		proc.press(t, "j")
	}
	waitForOutput(t, proc.out, 3*time.Second, "role-06")

	proc.press(t, "\r")
	code := proc.waitExit(t, 5*time.Second)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, proc.out.String())
	}
}
