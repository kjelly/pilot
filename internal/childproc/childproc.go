//go:build unix

// Package childproc bounds pilot's wait for a child process and for the
// processes it starts. exec.CommandContext alone kills only the direct child
// when the context ends, and Wait then reads the child's output pipes until
// EOF: a process the child started (a vault password client script, an ssh
// ProxyJump hop) that inherited a pipe holds Wait for as long as it lives.
//
// The Go preview of pilot reconcile (spec §2.5) runs every child it starts
// through Isolate; nothing else in pilot does yet.
package childproc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// WaitDelay bounds how long Wait drains a child's pipes after the child
// exited or was killed.
const WaitDelay = 2 * time.Second

// ErrHelperKeptOutput: the child exited 0, but a process it started kept
// one of its output pipes open for more than WaitDelay. What was read may be
// partial, so the result is not used. That process is not killed: the child
// is reaped by then, and signalling its process group could reach an
// unrelated process given the same id.
var ErrHelperKeptOutput = errors.New("a process it started kept its output open")

// Isolate runs cmd in a new session with no controlling terminal: nothing it
// starts can prompt on the terminal, and when the context of an
// exec.CommandContext command ends, cmd and every process it started that
// stayed in the session's process group are SIGKILLed together. Wait is then
// bounded by WaitDelay for the output pipes, and fails with exec.ErrWaitDelay
// when cmd exited 0 but a process it started still holds one. A process that
// left the group (setsid, a daemon) is not killed; WaitDelay is what bounds
// the wait for it.
//
// The terminal's signals (Ctrl-C, hangup) go to pilot's process group and do
// not reach cmd: only a caller that cancels the context on those signals
// itself may use it. Isolate leaves Stdin as it is, so a caller that leaves it
// nil gives cmd /dev/null; do not combine it with os.Stdin. Call it before
// Start.
func Isolate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.WaitDelay = WaitDelay
	// Only a command made by exec.CommandContext has a Cancel, and Start
	// rejects one on any other command.
	if cmd.Cancel != nil {
		cmd.Cancel = func() error { return KillGroup(cmd) }
	}
}

// KillGroup SIGKILLs the process group of a started cmd that was run with
// Isolate (the group of a command that was not is pilot's own). A group with
// nothing left in it is os.ErrProcessDone.
func KillGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}

// Cause is the reason a command run with Isolate failed, given the error its
// Run, Wait or Output returned: an error wrapping ctx.Err() when ctx has
// ended (and err, so an *exec.ExitError stays reachable), a wrapped
// ErrHelperKeptOutput when err is exec.ErrWaitDelay, or err itself.
func Cause(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%w (%w)", ctxErr, err)
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return fmt.Errorf("exited, but %w for more than %s: %w", ErrHelperKeptOutput, WaitDelay, err)
	}
	return err
}
