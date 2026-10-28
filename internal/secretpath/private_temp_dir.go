package secretpath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// PrivateTempDir creates a new mode-0700 directory in the system temp
// directory named <prefix>-<pid>-*, for a copy of files that may hold
// secrets: pilot edit's plan scratch workspace, a simulated roster write,
// a decrypted roster. Its caller removes it when done; a pilot killed
// before that leaves it behind, so this first removes this user's
// directories with the same prefix whose pid no longer runs (AGENTS.md
// §5.14 rule 5; PR #148 round 6, P3-4).
func PrivateTempDir(prefix string) (string, error) {
	sweepPrivateTempDirs(os.TempDir(), prefix)
	return os.MkdirTemp("", fmt.Sprintf("%s-%d-*", prefix, os.Getpid()))
}

// sweepPrivateTempDirs removes the <prefix>-<pid>-* directories in dir
// that this user owns and whose process is gone. It never follows a
// symlink and leaves anything it cannot attribute alone.
func sweepPrivateTempDirs(dir, prefix string) {
	matches, err := filepath.Glob(filepath.Join(dir, prefix+"-*"))
	if err != nil {
		return
	}
	self, uid := os.Getpid(), os.Getuid()
	for _, m := range matches {
		pidText, _, ok := strings.Cut(strings.TrimPrefix(filepath.Base(m), prefix+"-"), "-")
		pid, err := strconv.Atoi(pidText)
		if !ok || err != nil || pid <= 0 || pid == self || pidRunning(pid) {
			continue
		}
		info, err := os.Lstat(m)
		if err != nil || !info.IsDir() {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid {
			continue
		}
		_ = os.RemoveAll(m)
	}
}

// pidRunning reports whether pid names a live process (signal 0; EPERM is
// a live process of another user).
func pidRunning(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
