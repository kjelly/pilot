// Package systemdactivation implements the systemd socket-activation
// protocol (sd_listen_fds(3)) for pilot-access-gateway.socket (spec.md
// §29/§30): the process inherits an already-bound, already-listening
// socket at fd 3 instead of binding one itself.
package systemdactivation

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

// listenFDsStart is fd 3 — sd_listen_fds(3)'s documented starting point
// (0, 1, 2 are stdin/stdout/stderr).
const listenFDsStart = 3

// Listener returns the systemd-activated listener. It verifies LISTEN_PID
// matches this process — sd_listen_fds(3)'s documented safety check, so a
// socket meant for a different (e.g. forked-and-exited) process is never
// used by mistake.
func Listener() (net.Listener, error) {
	pidStr := os.Getenv("LISTEN_PID")
	fdsStr := os.Getenv("LISTEN_FDS")
	if pidStr == "" || fdsStr == "" {
		return nil, fmt.Errorf("systemdactivation: LISTEN_PID/LISTEN_FDS not set — not socket-activated")
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return nil, fmt.Errorf("systemdactivation: invalid LISTEN_PID %q: %w", pidStr, err)
	}
	if pid != os.Getpid() {
		return nil, fmt.Errorf("systemdactivation: LISTEN_PID %d does not match this process (%d)", pid, os.Getpid())
	}
	n, err := strconv.Atoi(fdsStr)
	if err != nil || n < 1 {
		return nil, fmt.Errorf("systemdactivation: invalid LISTEN_FDS %q", fdsStr)
	}
	file := os.NewFile(uintptr(listenFDsStart), "systemd-socket")
	ln, err := net.FileListener(file)
	if err != nil {
		return nil, fmt.Errorf("systemdactivation: wrap fd %d: %w", listenFDsStart, err)
	}
	return ln, nil
}
