//go:build linux || darwin || freebsd

// L4 integration test: build the real `pilot` binary (not a
// reimplementation, not a go-test helper-process shim) and drive
// `pilot edit --dir <scratch>` inside a real PTY — the same way
// .agents/skills/pilot-trec-verification actually exercises this
// command via trec. This is the router-level equivalent of
// edit_role_checklist_pty_test.go's harness (which tested only the
// role checklist sub-screen before this rewrite folded it into the
// router as one screen among many).
//
// CI=1 is set exactly as the pilot-trec-verification skill documents:
// every `pilot edit` invocation now touches Bubble Tea (the whole
// wizard, not just the role checklist as before this rewrite), so
// every driven invocation needs it to avoid bubbletea's package-init
// OSC background-color query blocking for termenv.OSCTimeout (5s)
// under a PTY with nothing to answer it.
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/anomalyco/pilot/internal/inventory"
)

var (
	pilotBinaryOnce sync.Once
	pilotBinaryPath string
	pilotBinaryErr  error
	pilotBinaryDir  string
)

// buildPilotBinary compiles the real cmd/pilot binary once and reuses
// it across every PTY test in this file.
func buildPilotBinary(t *testing.T) string {
	t.Helper()
	pilotBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "pilot-edit-pty")
		if err != nil {
			pilotBinaryErr = err
			return
		}
		pilotBinaryDir = dir
		out := filepath.Join(dir, "pilot")
		repoRoot := repoRootForPTYTest(t)
		cmd := exec.Command("go", "build", "-o", out, "./cmd/pilot")
		cmd.Dir = repoRoot
		combined, err := cmd.CombinedOutput()
		if err != nil {
			pilotBinaryErr = fmt.Errorf("build pilot binary: %w\n%s", err, combined)
			return
		}
		pilotBinaryPath = out
	})
	if pilotBinaryErr != nil {
		t.Fatalf("%v", pilotBinaryErr)
	}
	return pilotBinaryPath
}

func repoRootForPTYTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod) above " + dir)
		}
		dir = parent
	}
}

type ptyProc struct {
	f       *os.File
	cmd     *exec.Cmd
	out     *ptySafeBuffer
	doneCh  chan struct{}
	waitErr error
}

type ptySafeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *ptySafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *ptySafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func startEditPTY(t *testing.T, dir string, rows, cols uint16) *ptyProc {
	t.Helper()
	bin := buildPilotBinary(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	cmd := exec.CommandContext(ctx, bin, "edit", "--dir", dir)
	cmd.Env = append(append([]string{}, os.Environ()...), "TERM=xterm-256color", "CI=1")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: rows, Cols: cols})
	if err != nil {
		t.Fatalf("start PTY: %v", err)
	}

	proc := &ptyProc{f: ptmx, cmd: cmd, out: &ptySafeBuffer{}, doneCh: make(chan struct{})}
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

// keyPressSettle mirrors edit_role_checklist_pty_test.go's finding:
// blasting several keys in one write reliably drops all but one under
// a real PTY, so keystrokes are paced individually.
const keyPressSettle = 30 * time.Millisecond

func (p *ptyProc) press(t *testing.T, s string) {
	t.Helper()
	if _, err := io.WriteString(p.f, s); err != nil {
		t.Fatalf("write PTY input: %v", err)
	}
	time.Sleep(keyPressSettle)
}

func (p *ptyProc) typeText(t *testing.T, s string) {
	t.Helper()
	for _, r := range s {
		p.press(t, string(r))
	}
}

func (p *ptyProc) waitExit(t *testing.T, timeout time.Duration) int {
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

func waitForPTYOutput(t *testing.T, buf *ptySafeBuffer, timeout time.Duration, want string) string {
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

func TestPilotEditPTY_AddHostToggleRoleSaveAndQuit(t *testing.T) {
	dir := t.TempDir()
	proc := startEditPTY(t, dir, 40, 100)

	waitForPTYOutput(t, proc.out, 5*time.Second, "要編輯什麼")
	proc.press(t, "\r") // top menu -> hosts.yml
	waitForPTYOutput(t, proc.out, 5*time.Second, "hosts.yml 路徑")
	proc.press(t, "\r") // accept default path
	waitForPTYOutput(t, proc.out, 5*time.Second, "不存在")
	proc.press(t, "\r") // confirm start blank (default yes)
	waitForPTYOutput(t, proc.out, 5*time.Second, "新增主機")
	proc.press(t, "\r") // host list -> "新增主機"
	waitForPTYOutput(t, proc.out, 5*time.Second, "新主機名稱")
	proc.typeText(t, "web-1")
	proc.press(t, "\r")
	waitForPTYOutput(t, proc.out, 5*time.Second, "ansible_host")
	proc.press(t, "\r") // host menu -> ansible_host field
	waitForPTYOutput(t, proc.out, 5*time.Second, "可路由的 IP")
	proc.typeText(t, "10.0.0.9")
	proc.press(t, "\r")

	waitForPTYOutput(t, proc.out, 5*time.Second, "選要編輯的項目")
	for i := 0; i < 4; i++ {
		proc.press(t, "j")
	}
	proc.press(t, "\r") // -> roles menu
	waitForPTYOutput(t, proc.out, 5*time.Second, "逐項勾選角色")
	proc.press(t, "\r") // -> role checklist (the one Bubble Tea screen requiring CI=1)
	waitForPTYOutput(t, proc.out, 5*time.Second, inventory.Roles()[0].Name)
	proc.press(t, " ")  // toggle first role on
	proc.press(t, "\r") // confirm checklist -> back to roles menu

	waitForPTYOutput(t, proc.out, 5*time.Second, "完成")
	for i := 0; i < 3; i++ {
		proc.press(t, "j")
	}
	proc.press(t, "\r") // "✅ 完成" -> back to host menu

	waitForPTYOutput(t, proc.out, 5*time.Second, "選要編輯的項目")
	for i := 0; i < 7; i++ {
		proc.press(t, "j")
	}
	proc.press(t, "\r") // "↩ 返回主機清單"

	waitForPTYOutput(t, proc.out, 5*time.Second, "存檔並離開")
	proc.press(t, "j")
	proc.press(t, "j")
	proc.press(t, "\r") // save and return to top menu

	waitForPTYOutput(t, proc.out, 5*time.Second, "✅ 已存檔")
	waitForPTYOutput(t, proc.out, 5*time.Second, "要編輯什麼")
	for i := 0; i < 3; i++ {
		proc.press(t, "j")
	}
	proc.press(t, "\r") // "離開"

	code := proc.waitExit(t, 10*time.Second)
	final := proc.out.String()
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", code, final)
	}
	if !strings.Contains(final, "\x1b[?25h") {
		t.Fatalf("expected the terminal cursor-restore sequence after exit, got:\n%s", final)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("expected hosts.yml to be written: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("written hosts.yml did not parse: %v\n%s", err, data)
	}
	if len(hf.Hosts) != 1 || hf.Hosts[0].Name != "web-1" || hf.Hosts[0].AnsibleHost != "10.0.0.9" {
		t.Fatalf("unexpected hosts.yml contents: %+v\n%s", hf, data)
	}
	if !hasRole(hf.Hosts[0].Roles, inventory.Roles()[0].Name) {
		t.Fatalf("expected role %q to be set, got %v", inventory.Roles()[0].Name, hf.Hosts[0].Roles)
	}
}

func TestPilotEditPTY_EscOnTopMenuQuitsCleanly(t *testing.T) {
	dir := t.TempDir()
	proc := startEditPTY(t, dir, 40, 100)

	waitForPTYOutput(t, proc.out, 5*time.Second, "要編輯什麼")
	proc.press(t, "\x1b") // esc

	code := proc.waitExit(t, 5*time.Second)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (clean cancel), output:\n%s", code, proc.out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); err == nil {
		t.Fatal("expected no hosts.yml to be written after an immediate cancel")
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if pilotBinaryDir != "" {
		_ = os.RemoveAll(pilotBinaryDir)
	}
	os.Exit(code)
}
