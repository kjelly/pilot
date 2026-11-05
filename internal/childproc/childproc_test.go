//go:build unix

package childproc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

// A hang is what these tests exist to catch, and one cannot be cancelled: each
// command runs in a goroutine and a result that does not come within hangAfter
// fails the test instead of the package.
const hangAfter = 30 * time.Second

type runResult struct {
	err     error
	stdout  string
	stderr  string
	elapsed time.Duration
}

// runBounded runs cmd to completion the way pilot's callers do (stdout and
// stderr into buffers, so Go makes pipes and copy goroutines), and fails the
// test when it does not return within hangAfter.
func runBounded(t *testing.T, cmd *exec.Cmd) runResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	begin := time.Now()
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		return runResult{err: err, stdout: stdout.String(), stderr: stderr.String(), elapsed: time.Since(begin)}
	case <-time.After(hangAfter):
		t.Fatalf("%v did not return within %s: Wait is not bounded", cmd.Args, hangAfter)
		return runResult{}
	}
}

// script writes an executable sh script and returns its path.
func script(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// helperScript is a script that starts a helper (which keeps only stderr, as
// a vault password client script does) and records its pid, then runs tail.
func helperScript(t *testing.T, pidFile, tail string, escaped bool) string {
	t.Helper()
	sleeper := "sleep 300"
	if escaped {
		if _, err := exec.LookPath("setsid"); err != nil {
			t.Skipf("setsid not installed: %v", err)
		}
		sleeper = "setsid sleep 300"
	}
	return script(t, sleeper+" >/dev/null </dev/null &\necho $! > '"+pidFile+".tmp'\nmv '"+pidFile+".tmp' '"+pidFile+"'\n"+tail)
}

// alive reports whether pid is a running process; a zombie nobody has reaped
// yet is not.
func alive(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	rest := string(data[strings.LastIndexByte(string(data), ')')+1:])
	fields := strings.Fields(rest)
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}

// readPID returns the pid recorded in path and kills it when the test ends,
// so a process that is meant to survive, or one a failing run leaves, never
// outlives the test.
func readPID(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the helper never started: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("pid file %s: %q", path, data)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	return pid
}

// waitGone fails unless pid is gone within within.
func waitGone(t *testing.T, what string, pid int, within time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(within); alive(pid); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%s (pid %d) is still running %s after the command returned", what, pid, within)
		}
	}
}

func commandContext(t *testing.T, ctx context.Context, path string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(ctx, path)
	Isolate(cmd)
	return cmd
}

// The context ending kills the child and a helper in its process group, and
// Wait does not wait for the helper's hold on stderr.
func TestIsolateDeadlineKillsTheChildAndAnInGroupHelper(t *testing.T) {
	dir := t.TempDir()
	childPID, helperPID := filepath.Join(dir, "child"), filepath.Join(dir, "helper")
	path := helperScript(t, helperPID, "echo $$ > '"+childPID+"'\nexec sleep 300", false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res := runBounded(t, commandContext(t, ctx, path))
	if res.elapsed > time.Second+WaitDelay+5*time.Second {
		t.Fatalf("returned after %s, want about the 1s deadline", res.elapsed)
	}
	var exit *exec.ExitError
	if cause := Cause(ctx, res.err); !errors.Is(cause, context.DeadlineExceeded) || !errors.As(cause, &exit) {
		t.Fatalf("Cause = %v, want the deadline with the ExitError behind it (err %v)", cause, res.err)
	}
	waitGone(t, "the child", readPID(t, childPID), time.Second)
	waitGone(t, "the in-group helper", readPID(t, helperPID), time.Second)
}

// A process that left the process group and kept stderr cannot hold the wait:
// it survives (nothing can reach it), but Wait returns within WaitDelay of the
// kill.
func TestIsolateEscapedHelperIsBoundedByWaitDelay(t *testing.T) {
	dir := t.TempDir()
	helperPID := filepath.Join(dir, "helper")
	path := helperScript(t, helperPID, "exec sleep 300", true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res := runBounded(t, commandContext(t, ctx, path))
	if res.elapsed < time.Second || res.elapsed > time.Second+WaitDelay+5*time.Second {
		t.Fatalf("returned after %s, want the 1s deadline plus at most the wait delay", res.elapsed)
	}
	if cause := Cause(ctx, res.err); !errors.Is(cause, context.DeadlineExceeded) {
		t.Fatalf("Cause = %v, want the deadline", cause)
	}
	pid := readPID(t, helperPID)
	if !alive(pid) {
		t.Fatalf("the escaped helper (pid %d) is gone: it was in the process group after all", pid)
	}
}

// The child ended well but a process it started holds a pipe: Wait gives up
// after WaitDelay with exec.ErrWaitDelay, which Cause names, and the helper is
// left alone (the child is reaped, its group id may be reused).
func TestIsolateExitZeroWithAHelperHoldingTheOutput(t *testing.T) {
	dir := t.TempDir()
	helperPID := filepath.Join(dir, "helper")
	path := helperScript(t, helperPID, "echo partial\nexit 0", false)
	res := runBounded(t, commandContext(t, context.Background(), path))
	if !errors.Is(res.err, exec.ErrWaitDelay) {
		t.Fatalf("err = %v, want exec.ErrWaitDelay", res.err)
	}
	if res.elapsed < WaitDelay-500*time.Millisecond || res.elapsed > WaitDelay+5*time.Second {
		t.Fatalf("returned after %s, want about the %s wait delay", res.elapsed, WaitDelay)
	}
	cause := Cause(context.Background(), res.err)
	if !errors.Is(cause, ErrHelperKeptOutput) || !errors.Is(cause, exec.ErrWaitDelay) || errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, context.Canceled) {
		t.Fatalf("Cause = %v, want ErrHelperKeptOutput and ErrWaitDelay and no context error", cause)
	}
	if pid := readPID(t, helperPID); !alive(pid) {
		t.Fatalf("the helper (pid %d) is gone, but a reaped child's group is not signalled", pid)
	}
}

// A failing child with the same helper reports its own failure.
func TestIsolateFailureWithAHelperIsTheExitError(t *testing.T) {
	helperPID := filepath.Join(t.TempDir(), "helper")
	path := helperScript(t, helperPID, "echo boom >&2\nexit 3", false)
	res := runBounded(t, commandContext(t, context.Background(), path))
	readPID(t, helperPID) // killed when the test ends
	var exit *exec.ExitError
	if !errors.As(res.err, &exit) || exit.ExitCode() != 3 {
		t.Fatalf("err = %v, want exit status 3", res.err)
	}
	if cause := Cause(context.Background(), res.err); errors.Is(cause, ErrHelperKeptOutput) || !errors.As(cause, &exit) {
		t.Fatalf("Cause = %v, want the ExitError and not ErrHelperKeptOutput", cause)
	}
	if res.stderr != "boom\n" {
		t.Fatalf("stderr = %q", res.stderr)
	}
}

// The child leads a new session: its session and process group are its own
// pid, so signalling -pid reaches it and what stayed with it, and nothing of
// pilot's.
func TestIsolateStartsANewSession(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exec cat /proc/self/stat")
	Isolate(cmd)
	res := runBounded(t, cmd)
	if res.err != nil {
		t.Fatal(res.err)
	}
	fields := strings.Fields(res.stdout[strings.LastIndexByte(res.stdout, ')')+1:])
	// state ppid pgrp session tty_nr tpgid
	if len(fields) < 6 {
		t.Fatalf("stat = %q", res.stdout)
	}
	pgrp, session, tty := fields[2], fields[3], fields[4]
	pid := strings.Fields(res.stdout)[0]
	if pgrp != pid || session != pid || tty != "0" {
		t.Fatalf("pid %s has process group %s, session %s, tty_nr %s: want a session of its own and no terminal", pid, pgrp, session, tty)
	}
	self, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	mine := strings.Fields(string(self[strings.LastIndexByte(string(self), ')')+1:]))[3]
	if mine == session {
		t.Fatalf("the child's session %s is this process's", session)
	}
}

// ptyChildEnv makes TestIsolateHasNoControllingTerminal run its body, in a
// child of the test binary whose controlling terminal is a pty.
const ptyChildEnv = "PILOT_TEST_CHILDPROC_PTY_CHILD"

// Under a terminal an isolated child cannot open /dev/tty, so a prompt (Python
// getpass, a ProxyJump hop asking for a password) cannot reach it.
func TestIsolateHasNoControllingTerminal(t *testing.T) {
	probe := `if ( : </dev/tty ) 2>/dev/null; then echo HAS_TTY; else echo NO_TTY; fi`
	if os.Getenv(ptyChildEnv) == "1" {
		plain := exec.Command("sh", "-c", probe)
		isolated := exec.Command("sh", "-c", probe)
		Isolate(isolated)
		a, errA := plain.Output()
		b, errB := isolated.Output()
		if errA != nil || errB != nil {
			t.Fatalf("probe: %v %v", errA, errB)
		}
		// Printed for the parent: the control proves the probe can see the
		// terminal at all.
		os.Stdout.WriteString("PLAIN=" + strings.TrimSpace(string(a)) + " ISOLATED=" + strings.TrimSpace(string(b)) + "\n")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestIsolateHasNoControllingTerminal$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), ptyChildEnv+"=1")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	defer ptmx.Close()
	var out bytes.Buffer
	copied := make(chan struct{})
	go func() { _, _ = io.Copy(&out, ptmx); close(copied) }()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("child: %v\n%s", err, out.String())
		}
	case <-time.After(hangAfter):
		_ = cmd.Process.Kill()
		t.Fatal("the pty child hung")
	}
	_ = ptmx.Close()
	<-copied
	if !strings.Contains(out.String(), "PLAIN=HAS_TTY ISOLATED=NO_TTY") {
		t.Fatalf("want the plain child to see the terminal and the isolated one not:\n%s", out.String())
	}
}

// Isolate on a command that has no context leaves Cancel nil (Start rejects a
// Cancel without one) and the command still runs; one with a context gets a
// Cancel that kills the group.
func TestIsolateCancel(t *testing.T) {
	plain := exec.Command("true")
	Isolate(plain)
	if plain.Cancel != nil {
		t.Fatal("Isolate set Cancel on a command with no context")
	}
	if err := plain.Run(); err != nil {
		t.Fatalf("an isolated plain command does not run: %v", err)
	}
	withCtx := exec.CommandContext(context.Background(), "true")
	before := withCtx.Cancel
	Isolate(withCtx)
	if withCtx.Cancel == nil || before == nil {
		t.Fatal("a command with a context has no Cancel")
	}
	if withCtx.SysProcAttr == nil || !withCtx.SysProcAttr.Setsid || withCtx.WaitDelay != WaitDelay {
		t.Fatalf("SysProcAttr = %+v, WaitDelay = %s", withCtx.SysProcAttr, withCtx.WaitDelay)
	}
}

func TestKillGroup(t *testing.T) {
	if err := KillGroup(exec.Command("true")); err != nil {
		t.Fatalf("a command that never started: %v", err)
	}
	cmd := exec.Command("true")
	Isolate(cmd)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if err := KillGroup(cmd); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("an empty group: %v, want os.ErrProcessDone", err)
	}
	sleeper := exec.Command("sleep", "300")
	Isolate(sleeper)
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() })
	if err := KillGroup(sleeper); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- sleeper.Wait() }()
	select {
	case err := <-waited:
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("wait: %v, want it killed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("KillGroup did not end the process")
	}
}

// Cause says what ended the command: a context that ended wins, with the
// command's own error behind it; a held pipe is ErrHelperKeptOutput; anything
// else is passed through untouched.
func TestCause(t *testing.T) {
	exit := exec.Command("sh", "-c", "exit 3").Run()
	var ee *exec.ExitError
	if !errors.As(exit, &ee) {
		t.Fatal(exit)
	}
	waitDelay := exec.ErrWaitDelay
	plain := errors.New("plain")

	live := context.Background()
	expired, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-expired.Done()
	canceled, stop := context.WithCancel(context.Background())
	stop()

	if Cause(live, nil) != nil || Cause(expired, nil) != nil {
		t.Fatal("Cause(nil) is not nil")
	}
	if got := Cause(live, plain); got != plain {
		t.Fatalf("a plain error with a live context: %v", got)
	}
	if got := Cause(live, exit); got != exit {
		t.Fatalf("an ExitError with a live context: %v", got)
	}
	for name, ctx := range map[string]context.Context{"deadline": expired, "canceled": canceled} {
		got := Cause(ctx, exit)
		if !errors.Is(got, ctx.Err()) || !errors.As(got, &ee) {
			t.Fatalf("%s: %v does not wrap both the context error and the ExitError", name, got)
		}
		both := Cause(ctx, waitDelay)
		if !errors.Is(both, ctx.Err()) || errors.Is(both, ErrHelperKeptOutput) {
			t.Fatalf("%s with ErrWaitDelay: %v, want the context error to win", name, both)
		}
	}
	held := Cause(live, waitDelay)
	if !errors.Is(held, ErrHelperKeptOutput) || !errors.Is(held, exec.ErrWaitDelay) || !strings.Contains(held.Error(), "kept its output open") {
		t.Fatalf("a held pipe: %v", held)
	}
	if got := Cause(live, errors.Join(plain, waitDelay)); !errors.Is(got, ErrHelperKeptOutput) {
		t.Fatalf("ErrWaitDelay inside a joined error: %v", got)
	}
}
