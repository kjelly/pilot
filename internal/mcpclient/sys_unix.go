//go:build unix

package mcpclient

import (
	"os/exec"
	"syscall"
)

// detachFromTerminal starts cmd in a new session, without a controlling
// terminal, so neither git nor ssh can prompt for a password or passphrase.
func detachFromTerminal(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
