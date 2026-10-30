//go:build unix

package mcpclient

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// processWaitDelay bounds how long Wait drains a child's pipes after the
// child has exited or been killed: a helper it started (an SSH or
// credential helper, a ProxyCommand) may inherit them and outlive it.
const processWaitDelay = 2 * time.Second

// isolate starts cmd in a new session without a controlling terminal, so
// neither git nor ssh can prompt for a password or passphrase, and so cmd
// and the helpers it starts form one process group killGroup ends
// together. It also bounds how long Wait drains the pipes.
func isolate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.WaitDelay = processWaitDelay
}

// killGroup SIGKILLs cmd's process group: cmd and every helper it started
// that did not leave the group. Callers avoid calling it after cmd has
// been reaped (while helpers remain, the group id stays reserved anyway).
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// boundedCommand is an isolated exec.CommandContext whose cancellation (a
// timeout or a signal) kills the whole process group, not only the direct
// child, so a helper holding its pipes cannot outlive the deadline.
func boundedCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	isolate(cmd)
	cmd.Cancel = func() error { return killGroup(cmd) }
	return cmd
}

// tryFlock takes an exclusive, non-blocking flock on f. It reports false
// when another open file holds it; the kernel releases it on exit.
func tryFlock(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == syscall.EWOULDBLOCK {
		return false, nil
	}
	return err == nil, err
}
