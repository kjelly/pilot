package secretpath

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The marker a private temp dir's creator holds locked; the tests name it
// literally so they state the on-disk contract, not a constant.
const markerName = ".pilot-alive"

// deadPID returns the pid of a process that has exited.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return cmd.ProcessState.Pid()
}

// mkPrivate makes a <prefix>-<pid>-<suffix> directory in tmp holding a
// secret, last modified age ago.
func mkPrivate(t *testing.T, tmp, prefix string, pid int, suffix string, age time.Duration) string {
	t.Helper()
	p := filepath.Join(tmp, fmt.Sprintf("%s-%d-%s", prefix, pid, suffix))
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "ipa-identity.yaml"), []byte("password: secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	return p
}

// holdLock makes p's marker and holds an exclusive flock on it the way a
// live creator does, until the returned release is called (or the test
// ends).
func holdLock(t *testing.T, p string) (release func()) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(p, markerName), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release = func() { once.Do(func() { f.Close() }) }
	t.Cleanup(release)
	return release
}

func gone(p string) bool {
	_, err := os.Lstat(p)
	return errors.Is(err, os.ErrNotExist)
}

// A creator in another PID namespace sharing the temp directory cannot see
// the pid in the name; its directory is alive while its lock is held, and
// only then (a pilot in a sandbox must not delete a live pilot's scratch).
func TestSweepKeepsADirectoryWhoseHolderIsAliveWhateverItsPid(t *testing.T) {
	tmp := t.TempDir()
	const prefix = "pilot-edit-plan"
	live := mkPrivate(t, tmp, prefix, deadPID(t), "live", time.Hour)
	release := holdLock(t, live)

	sweepPrivateTempDirs(tmp, prefix)
	if gone(live) {
		t.Fatal("a directory whose holder still holds its lock was swept because its pid is not visible")
	}
	if _, err := os.Stat(filepath.Join(live, "ipa-identity.yaml")); err != nil {
		t.Fatal(err)
	}

	release()
	sweepPrivateTempDirs(tmp, prefix)
	if !gone(live) {
		t.Fatal("a directory whose holder is gone survived the sweep")
	}
}

// The lock, not the pid, decides: an unlocked marker is a dead holder even
// when the pid in the name is a process that runs in this namespace.
func TestSweepRemovesAnUnlockedMarkerWhateverItsPid(t *testing.T) {
	tmp := t.TempDir()
	const prefix = "pilot-roster-decrypt"
	for name, pid := range map[string]int{"dead": deadPID(t), "recycled": os.Getppid()} {
		p := mkPrivate(t, tmp, prefix, pid, name, 0)
		if err := os.WriteFile(filepath.Join(p, markerName), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sweepPrivateTempDirs(tmp, prefix)
	for _, name := range []string{"dead", "recycled"} {
		if matches, _ := filepath.Glob(filepath.Join(tmp, prefix+"-*-"+name)); len(matches) != 0 {
			t.Errorf("%s: an unlocked marker's directory survived: %v", name, matches)
		}
	}
}

// A directory with no marker (an older pilot's, or one between mkdir and
// its marker) is removed only once it is old and its pid is not running
// here; a young one is never removed.
func TestSweepOfAMarkerlessDirectoryNeedsAgeAndADeadPid(t *testing.T) {
	tmp := t.TempDir()
	const prefix = "pilot-roster-scope"
	dead := deadPID(t)
	oldDead := mkPrivate(t, tmp, prefix, dead, "old-dead", time.Hour)
	youngDead := mkPrivate(t, tmp, prefix, dead, "young-dead", time.Minute)
	oldRunning := mkPrivate(t, tmp, prefix, os.Getppid(), "old-running", time.Hour)
	oldSelf := mkPrivate(t, tmp, prefix, os.Getpid(), "old-self", time.Hour)

	sweepPrivateTempDirs(tmp, prefix)
	if !gone(oldDead) {
		t.Error("an old marker-less directory of a dead pid survived")
	}
	for name, p := range map[string]string{"young, dead pid": youngDead, "old, running pid": oldRunning, "old, own pid": oldSelf} {
		if gone(p) {
			t.Errorf("a marker-less directory (%s) was removed", name)
		}
	}
}

// The sweep never follows a symlink, however old, and a marker that is a
// symlink (to a file it could lock) is not a holder it can take over.
func TestSweepNeverFollowsASymlink(t *testing.T) {
	tmp := t.TempDir()
	const prefix = "pilot-roster-scope"
	dead := deadPID(t)
	elsewhere := mkPrivate(t, tmp, "elsewhere", 1, "x", time.Hour)
	link := filepath.Join(tmp, fmt.Sprintf("%s-%d-link", prefix, dead))
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	trap := mkPrivate(t, tmp, prefix, dead, "marker-link", time.Hour)
	real := filepath.Join(tmp, "real-marker")
	if err := os.WriteFile(real, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(trap, markerName)); err != nil {
		t.Fatal(err)
	}

	sweepPrivateTempDirs(tmp, prefix)
	if gone(link) || gone(elsewhere) {
		t.Fatal("the sweep removed a symlink or what it points at")
	}
	if _, err := os.Stat(filepath.Join(elsewhere, "ipa-identity.yaml")); err != nil {
		t.Fatalf("the sweep followed a symlink: %v", err)
	}
	if gone(trap) {
		t.Fatal("a directory whose marker is a symlink was removed")
	}
}

// What PrivateTempDir returns is held: a private directory with a 0600
// marker whose flock another open file description cannot take, until the
// directory is removed.
func TestPrivateTempDirHoldsItsMarkerUntilRemoved(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	dir, err := PrivateTempDir("pilot-edit-plan")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("%s: %v %v", dir, info, err)
	}
	marker := filepath.Join(dir, markerName)
	mi, err := os.Lstat(marker)
	if err != nil || !mi.Mode().IsRegular() || mi.Mode().Perm() != 0o600 {
		t.Fatalf("marker %s: %v %v", marker, mi, err)
	}
	probe, err := os.Open(marker)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("a second holder could take the lock of a live directory: %v", err)
	}
	// The lock is the creator's for the life of the process, not of a
	// garbage-collected *os.File.
	for range 3 {
		sweepPrivateTempDirs(tmp, "pilot-edit-plan")
	}
	if gone(dir) {
		t.Fatal("the process's own live directory was swept")
	}
}

// Concurrent callers (parallel plans) never sweep each other's directories.
func TestConcurrentPrivateTempDirsDoNotSweepEachOther(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	const prefix = "pilot-edit-plan"
	const n = 16
	var wg sync.WaitGroup
	dirs := make([]string, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				d, err := PrivateTempDir(prefix)
				if err != nil {
					errs[i] = err
					return
				}
				if dirs[i] != "" {
					_ = os.RemoveAll(dirs[i])
				}
				dirs[i] = d
			}
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if gone(dirs[i]) {
			t.Errorf("goroutine %d: its directory was swept by another", i)
		}
	}
}

// helperEnv makes a re-executed test binary run TestHelperProcess.
const helperEnv = "PILOT_SECRETPATH_HELPER"

// TestHelperProcess is not a test: re-executed with helperEnv set, it is
// another process — "hold" makes a private temp dir, prints it and waits
// for stdin to close; "sweep" makes one (which sweeps) and prints whether
// parent pid (argument 2) is visible to it.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv(helperEnv)
	if mode == "" {
		t.Skip("helper process")
	}
	dir, err := PrivateTempDir(os.Getenv("PILOT_SECRETPATH_PREFIX"))
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(2)
	}
	switch mode {
	case "hold":
		fmt.Println(dir)
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	case "sweep":
		var parent int
		_, _ = fmt.Sscan(os.Getenv("PILOT_SECRETPATH_PARENT"), &parent)
		fmt.Println("parent-visible", pidRunning(parent))
		_ = os.RemoveAll(dir)
	}
	os.Exit(0)
}

func helperCmd(t *testing.T, tmp, prefix, mode string, argv ...string) *exec.Cmd {
	t.Helper()
	args := append(append([]string{}, argv...), os.Args[0], "-test.run=^TestHelperProcess$")
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "TMPDIR="+tmp, helperEnv+"="+mode, "PILOT_SECRETPATH_PREFIX="+prefix,
		fmt.Sprintf("PILOT_SECRETPATH_PARENT=%d", os.Getpid()))
	return cmd
}

// A process that holds a directory keeps it from another process's sweep
// while it lives; the kernel drops its lock when it is killed, and the next
// sweep removes the directory.
func TestAKilledHoldersDirectoryIsSweptAndALiveOnesIsNot(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	const prefix = "pilot-roster-decrypt"
	cmd := helperCmd(t, tmp, prefix, "hold")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	held := strings.TrimSpace(line)
	if !strings.HasPrefix(filepath.Base(held), fmt.Sprintf("%s-%d-", prefix, cmd.Process.Pid)) {
		t.Fatalf("helper dir %q", held)
	}

	mine, err := PrivateTempDir(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if gone(held) {
		t.Fatal("a live process's directory was swept")
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if _, err := PrivateTempDir(prefix); err != nil {
		t.Fatal(err)
	}
	if !gone(held) {
		t.Error("a killed process's directory survived the next sweep")
	}
	if gone(mine) {
		t.Error("this process's directory was swept")
	}
}

// The failure this lock exists for: a pilot in another PID namespace that
// shares the temp directory (a bwrap-sandboxed agent, a container with /tmp
// mounted) cannot see this process's pid and used to delete its live
// scratch directory — a plan's hosts.yml vanishing mid-run ("label nexus
// not found"). A real sandbox, when this host allows one.
func TestAPilotInAnotherPIDNamespaceDoesNotSweepALiveDirectory(t *testing.T) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap not installed")
	}
	sandbox := []string{bwrap, "--bind", "/", "/", "--dev-bind", "/dev", "/dev", "--proc", "/proc", "--unshare-pid", "--die-with-parent"}
	if out, err := exec.Command(bwrap, append(sandbox[1:], "true")...).CombinedOutput(); err != nil {
		t.Skipf("bwrap cannot make a PID namespace here: %v: %s", err, out)
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	const prefix = "pilot-edit-plan"
	live, err := PrivateTempDir(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, "hosts.yml"), []byte("all: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := helperCmd(t, tmp, prefix, "sweep", sandbox...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sandboxed pilot: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "parent-visible false") {
		t.Skipf("the sandbox can see this process's pid, so it demonstrates nothing: %s", out)
	}
	if _, err := os.Stat(filepath.Join(live, "hosts.yml")); err != nil {
		t.Fatalf("a pilot in another PID namespace deleted this process's live scratch directory: %v", err)
	}
}
