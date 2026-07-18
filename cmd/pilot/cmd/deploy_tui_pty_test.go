//go:build linux || darwin || freebsd

// L4 integration test for `pilot deploy`'s prompt flow, using the same
// real-binary-under-a-real-PTY harness as edit_tui_pty_test.go
// (buildPilotBinary/ptyProc/etc., defined there and reused here since
// both live in the same package). It drives every new Bubble Tea
// prompt wrapper (deploy_tui.go's runSelectProgram/runTextProgram/
// runConfirmProgram) through a real terminal, declining at the final
// "確定要執行以上指令嗎？" gate so it never actually invokes
// ansible-playbook — this test is about proving the prompt flow itself
// works under a real PTY (raw-mode key delivery, CI=1, exit cleanup),
// not about exercising ansible.Runner, which this rewrite doesn't
// touch.
package cmd

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

// startDeployPTY mirrors startEditPTY (edit_tui_pty_test.go) but runs
// `pilot deploy` with dir as the process's working directory (deploy's
// playbook paths, e.g. "playbooks/site.yml", and its --inventory
// default are both CWD-relative, unlike edit's --dir flag).
func startDeployPTY(t *testing.T, dir string, rows, cols uint16) *ptyProc {
	t.Helper()
	bin := buildPilotBinary(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	cmd := exec.CommandContext(ctx, bin, "deploy")
	cmd.Dir = dir
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

// newProgramSettle is a pause after a new screen's first output before
// sending it any keys. Unlike pilot edit (one continuous tea.Program
// for the whole session), pilot deploy launches a brand-new
// tea.Program per prompt (see deploy_tui.go's package doc comment) —
// each transition briefly returns the PTY to cooked/echo mode between
// one Program exiting and the next re-entering raw mode. Keys sent
// into that gap get swallowed into the kernel's line-buffered input
// instead of delivered to the new Program, and surface much later as
// garbled echoed text once some later reader finally consumes them.
// Confirmed live: without this pause, "jj" meant for the preflight
// select arrived after the next prompt had already defaulted, then
// echoed out verbatim once a subprocess with no active raw-mode
// reader let cooked-mode echo take over again. This mirrors the
// dropped-keystroke gotchas already documented for promptui in
// .agents/skills/pilot-trec-verification/SKILL.md — the same
// generous-settle-delay discipline applies here, for the same reason.
const newProgramSettle = 150 * time.Millisecond

func waitForNewDeployScreen(t *testing.T, proc *ptyProc, want string) {
	t.Helper()
	waitForPTYOutput(t, proc.out, 5*time.Second, want)
	time.Sleep(newProgramSettle)
}

func TestPilotDeployPTY_DeclineAtFinalConfirmNeverRunsAnsible(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	t.Setenv("PILOT_DATA_DIR", filepath.Join(dir, "data"))
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "ansible"), []byte("#!/bin/sh\nif [ \"$1\" = docker ]; then printf '%s\\n' '  hosts (1):' '    host-a'; else printf '%s\\n' '  hosts (0):'; fi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := os.WriteFile(filepath.Join(dir, "inventory.yml"), []byte("all:\n  children:\n    docker:\n      hosts:\n        host-a:\n          ansible_connection: local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	proc := startDeployPTY(t, dir, 40, 100)

	waitForNewDeployScreen(t, proc, "Inventory 檔路徑")
	proc.press(t, "\r") // accept default "inventory.yml" (resolves via cmd.Dir)

	waitForNewDeployScreen(t, proc, "ansible-inventory --graph")
	proc.press(t, "n") // decline inventory graph preview — confirmModel finalizes on y/n alone, no Enter needed

	waitForNewDeployScreen(t, proc, "前置檢查")
	proc.press(t, "j")
	proc.press(t, "j")
	proc.press(t, "\r") // "跳過前置檢查"

	waitForNewDeployScreen(t, proc, "要佈署什麼")
	proc.press(t, "\r") // "全站部署(site.yml)"

	waitForNewDeployScreen(t, proc, "要套用到哪個 stage")
	proc.press(t, "\r") // sandbox (no extra confirm needed)

	waitForNewDeployScreen(t, proc, "--limit")
	proc.press(t, "\r") // leave --limit blank

	waitForNewDeployScreen(t, proc, "--tags")
	proc.press(t, "\r") // leave --tags blank

	waitForNewDeployScreen(t, proc, "需要密碼變數嗎")
	proc.press(t, "\r") // "不需要"

	waitForNewDeployScreen(t, proc, "還有其他 -e 變數")
	proc.press(t, "\r") // leave extra -e vars blank

	waitForNewDeployScreen(t, proc, "要先預覽")
	proc.press(t, "n") // skip the --check --diff preview

	waitForNewDeployScreen(t, proc, "確定要執行以上指令嗎")
	proc.press(t, "n") // decline — must exit cleanly without ever running ansible-playbook

	code := proc.waitExit(t, 10*time.Second)
	final := proc.out.String()
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (a decline is a clean abort, not an error), output:\n%s", code, final)
	}
	if strings.Contains(final, "PLAY [") || strings.Contains(final, "PLAY RECAP") {
		t.Fatalf("ansible-playbook must never have actually run, but output looks like it did:\n%s", final)
	}
}
