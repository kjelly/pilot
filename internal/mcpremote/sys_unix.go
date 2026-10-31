//go:build unix

package mcpremote

import (
	"os"
	"syscall"
)

const noFollow = syscall.O_NOFOLLOW

// tryLock takes an exclusive, non-blocking flock on path (creating it).
// It returns nil, nil when another process holds the lock. The kernel
// releases the lock when the process exits, however it exits.
func tryLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|noFollow, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, nil
		}
		return nil, err
	}
	return f, nil
}
