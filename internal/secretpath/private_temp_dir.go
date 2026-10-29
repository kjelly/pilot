package secretpath

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// privateTempMarker names the file in every private temp directory on which
// its creating process holds an exclusive flock for as long as it lives.
const privateTempMarker = ".pilot-alive"

// privateTempMarkerBuilding is the marker's name while it is being made: it
// is renamed to privateTempMarker only after it is locked, so a sweeper that
// can see privateTempMarker always finds it held by its creator.
const privateTempMarkerBuilding = ".pilot-alive.new"

// markerlessGrace is how old a directory without a marker (made by an older
// pilot, or in the instant between mkdir and its marker) must be before the
// sweeper considers removing it.
const markerlessGrace = 10 * time.Minute

// heldMarkers are the marker files this process holds locked, by directory.
// Keeping the *os.File here also keeps its finalizer from closing the
// descriptor, and with it the lock, while the directory is in use.
var heldMarkers = struct {
	sync.Mutex
	byDir map[string]*os.File
}{byDir: map[string]*os.File{}}

// PrivateTempDir creates a new mode-0700 directory in the system temp
// directory named <prefix>-<pid>-*, for a copy of files that may hold
// secrets: pilot edit's plan scratch workspace, a simulated roster write,
// a decrypted roster. Its caller removes it when done (os.RemoveAll); a
// pilot killed before that leaves it behind, so this first removes this
// user's directories with the same prefix whose creator is gone (AGENTS.md
// §5.14 rule 5; PR #148 round 6, P3-4).
//
// "Gone" is not judged by pid — a pilot in another PID namespace sharing
// the temp directory (a sandboxed agent, a container with /tmp mounted)
// cannot see the pid, and would delete a live process's directory. The
// creator instead holds an exclusive flock on a marker file in the
// directory until it exits (the kernel releases it however it exits); the
// sweeper removes a directory only when it can take that lock itself.
func PrivateTempDir(prefix string) (string, error) {
	reapReleasedMarkers()
	sweepPrivateTempDirs(os.TempDir(), prefix)
	dir, err := os.MkdirTemp("", fmt.Sprintf("%s-%d-*", prefix, os.Getpid()))
	if err != nil {
		return "", err
	}
	if err := holdMarker(dir); err != nil {
		// A filesystem that cannot flock still gets its private directory;
		// it is then only swept after markerlessGrace, and only once its
		// pid is gone from the sweeper's own namespace.
		slog.Warn("private temp directory has no liveness marker", "dir", dir, "err", err)
	}
	return dir, nil
}

// holdMarker creates dir's marker, locks it, and keeps it locked until the
// process exits or reapReleasedMarkers sees the directory removed.
func holdMarker(dir string) error {
	building := filepath.Join(dir, privateTempMarkerBuilding)
	f, err := os.OpenFile(building, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return fmt.Errorf("lock %s: %w", building, err)
	}
	if err := os.Rename(building, filepath.Join(dir, privateTempMarker)); err != nil {
		f.Close()
		return err
	}
	heldMarkers.Lock()
	heldMarkers.byDir[dir] = f
	heldMarkers.Unlock()
	return nil
}

// reapReleasedMarkers closes the markers of directories their callers have
// removed (the marker file has no name left), releasing their descriptors;
// callers remove the directory themselves, so this is how the lock is let
// go without changing their cleanup.
func reapReleasedMarkers() {
	heldMarkers.Lock()
	defer heldMarkers.Unlock()
	for dir, f := range heldMarkers.byDir {
		var st syscall.Stat_t
		if err := syscall.Fstat(int(f.Fd()), &st); err == nil && st.Nlink != 0 {
			continue
		}
		f.Close()
		delete(heldMarkers.byDir, dir)
	}
}

// sweepPrivateTempDirs removes the <prefix>-<pid>-* directories in dir
// that this user owns and whose creator is gone. It never follows a
// symlink and leaves anything it cannot attribute alone.
func sweepPrivateTempDirs(dir, prefix string) {
	sweepPrivateTempDirsAs(dir, prefix, os.Getuid())
}

func sweepPrivateTempDirsAs(dir, prefix string, uid int) {
	matches, err := filepath.Glob(filepath.Join(dir, prefix+"-*"))
	if err != nil {
		return
	}
	self := os.Getpid()
	for _, m := range matches {
		pidText, _, ok := strings.Cut(strings.TrimPrefix(filepath.Base(m), prefix+"-"), "-")
		pid, err := strconv.Atoi(pidText)
		if !ok || err != nil || pid <= 0 {
			continue
		}
		info, err := os.Lstat(m)
		if err != nil || !info.IsDir() {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid {
			continue
		}
		removeIfDead(m, info, pid, self, uid)
	}
}

// removeIfDead removes the private temp directory m when nothing holds it:
// its marker can be locked, or — with no marker — it is older than
// markerlessGrace and its pid does not run here. Any doubt keeps it.
func removeIfDead(m string, info os.FileInfo, pid, self, uid int) {
	marker, err := os.OpenFile(filepath.Join(m, privateTempMarker), os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	switch {
	case err == nil:
		defer marker.Close()
		var st syscall.Stat_t
		if syscall.Fstat(int(marker.Fd()), &st) != nil || int(st.Uid) != uid || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return
		}
		// EWOULDBLOCK is a live holder; any other failure is unknown, and
		// unknown is alive. Holding the lock through RemoveAll keeps a
		// concurrent sweeper out.
		if syscall.Flock(int(marker.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
			return
		}
		_ = os.RemoveAll(m)
	case errors.Is(err, os.ErrNotExist):
		if pid == self || pidRunning(pid) || time.Since(info.ModTime()) < markerlessGrace {
			return
		}
		_ = os.RemoveAll(m)
	}
}

// pidRunning reports whether pid names a live process (signal 0; EPERM is
// a live process of another user) in this process's PID namespace.
func pidRunning(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
