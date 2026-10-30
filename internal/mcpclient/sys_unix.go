//go:build unix

package mcpclient

import (
	"os"
	"os/exec"
	"syscall"
)

// detachFromTerminal starts cmd in a new session, without a controlling
// terminal, so neither git nor ssh can prompt for a password or passphrase.
func detachFromTerminal(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
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
