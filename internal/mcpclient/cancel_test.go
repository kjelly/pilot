package mcpclient

import (
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

	"github.com/kjelly/pilot/internal/mcpwire"
)

// processGone reports whether pid has exited (gone, or a zombie waiting
// to be reaped by its new parent).
func processGone(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return syscall.Kill(pid, 0) != nil
	}
	fields := strings.Fields(string(data[strings.LastIndexByte(string(data), ')')+1:]))
	return len(fields) > 0 && fields[0] == "Z"
}

// waitGone fails the test unless the pid in pidFile exits within limit.
func waitGone(t *testing.T, pidFile string, limit time.Duration) {
	t.Helper()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read pid: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	for deadline := time.Now().Add(limit); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if processGone(pid) {
			return
		}
	}
	t.Fatalf("helper %d still running %s later", pid, limit)
}

// A Git timeout ends git and every helper it started, even one that
// inherited git's pipes and would outlive it (an SSH or credential
// helper): the command returns at the timeout, not when the helper ends.
func TestGitTimeoutEndsHelpersHoldingItsPipes(t *testing.T) {
	const timeout = time.Second
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "helper.pid")
	helper := filepath.Join(dir, "ssh-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\necho $$ > "+pidFile+"\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_SSH_COMMAND", helper)
	repo, err := openGitCache(context.Background(), t.TempDir(), "ssh://git.example.invalid/org/config.git", timeout)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = repo.resolve(context.Background(), "main")
	elapsed := time.Since(start)
	if !hasCode(err, CodeGitFailed) || !strings.Contains(err.Error(), "did not finish within") {
		t.Fatalf("err = %v, want GIT_FAILED for the timeout", err)
	}
	if elapsed > timeout+processWaitDelay+2*time.Second {
		t.Fatalf("resolve returned after %v; the timeout is %v", elapsed, timeout)
	}
	waitGone(t, pidFile, 3*time.Second)
}

// A helper that leaves git's process group cannot be killed with it and
// may still hold a pipe. WaitDelay bounds the wait: one holding only
// git's stderr costs WaitDelay after git ends; one holding git's ssh
// transport keeps git itself waiting, until the timeout kills git.
func TestGitDoesNotWaitForAHelperThatLeftItsGroup(t *testing.T) {
	setsid, err := exec.LookPath("setsid")
	if err != nil {
		t.Skip("setsid(1) not available")
	}
	cases := map[string]struct {
		redirect string
		timeout  time.Duration
		limit    time.Duration
	}{
		"holds stderr":        {"</dev/null >/dev/null", 30 * time.Second, processWaitDelay + 3*time.Second},
		"holds the transport": {"", time.Second, time.Second + processWaitDelay + 3*time.Second},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			pidFile := filepath.Join(dir, "helper.pid")
			helper := filepath.Join(dir, "ssh-helper")
			script := "#!/bin/sh\n" + setsid + " -f sh -c 'echo $$ > " + pidFile + "; exec sleep 60' " + tc.redirect + "\nexit 1\n"
			if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("GIT_SSH_COMMAND", helper)
			t.Cleanup(func() {
				if data, err := os.ReadFile(pidFile); err == nil {
					if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
						_ = syscall.Kill(pid, syscall.SIGKILL)
					}
				}
			})
			repo, err := openGitCache(context.Background(), t.TempDir(), "ssh://git.example.invalid/org/config.git", tc.timeout)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			if _, err := repo.resolve(context.Background(), "main"); err == nil {
				t.Fatal("resolve succeeded through a failing ssh helper")
			}
			if elapsed := time.Since(start); elapsed > tc.limit {
				t.Fatalf("resolve returned after %v, want at most %v", elapsed, tc.limit)
			}
			if _, err := os.Stat(pidFile); err != nil {
				t.Skip("setsid -f did not start the helper (busybox setsid has no -f)")
			}
		})
	}
}

// Cancelling (SIGINT/SIGTERM in the CLI) ends a `changes` that is waiting
// on ssh: ssh and its helpers are killed and the call returns ctx.Err(),
// also when a helper keeps stdout open after ssh ends.
func TestChangesStopsOnCancel(t *testing.T) {
	for _, scenario := range []string{"hang", "hang-child"} {
		t.Run(scenario, func(t *testing.T) {
			p := testProfile("https://example.invalid/org/config.git", "prod", mcpwire.ModeEdit)
			useFakeSSH(t, scenario, p)
			pidFile := filepath.Join(t.TempDir(), "pid")
			t.Setenv("PILOT_MCP_FAKE_PID", pidFile)
			o := &Options{ProfileName: "prod-edit", Profile: p, Stderr: io.Discard, CacheDir: t.TempDir()}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := Changes(ctx, o, strings.Repeat("d", 32), t.TempDir())
				done <- err
			}()
			waitForFile(t, pidFile)
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("err = %v, want context.Canceled", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Changes did not return after cancellation")
			}
			waitGone(t, pidFile, 3*time.Second)
		})
	}
}

// Doctor's remote-version step stops on cancellation the same way.
func TestDoctorVersionStopsOnCancel(t *testing.T) {
	allowLocalRepos(t)
	bare, _ := makeRepo(t, map[string]string{"prod/hosts.yml": "hosts: {}\n"})
	p := testProfile(bare, "prod", mcpwire.ModeObserve)
	useFakeSSH(t, "hang", p)
	pidFile := filepath.Join(t.TempDir(), "pid")
	t.Setenv("PILOT_MCP_FAKE_PID", pidFile)
	o := &Options{ProfileName: "prod-observe", Profile: p, Stderr: io.Discard, CacheDir: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *Report, 1)
	go func() { done <- Doctor(ctx, o) }()
	waitForFile(t, pidFile)
	cancel()
	select {
	case rep := <-done:
		var version *Check
		for i := range rep.Checks {
			if rep.Checks[i].ID == "remote-version" {
				version = &rep.Checks[i]
			}
		}
		if version == nil || version.Status != "fail" || !strings.Contains(version.Detail, "canceled") {
			t.Fatalf("remote-version check = %+v, want a failure from the cancellation", version)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Doctor did not return after cancellation")
	}
	waitGone(t, pidFile, 3*time.Second)
}

// A signal ends the wait for the cache lock another pilot-mcp holds;
// the wait would otherwise last up to three Git timeouts.
func TestOpenGitCacheStopsWaitingForTheLockOnCancel(t *testing.T) {
	allowLocalRepos(t)
	bare, _ := makeRepo(t, map[string]string{"prod/hosts.yml": "hosts: {}\n"})
	cacheDir := t.TempDir()
	repo, err := openGitCache(context.Background(), cacheDir, bare, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(repo.dir+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if held, err := tryFlock(f); !held || err != nil {
		t.Fatalf("hold the cache lock: %v %v", held, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	_, err = openGitCache(ctx, cacheDir, bare, 5*time.Second)
	if !hasCode(err, CodeGitFailed) || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("err = %v, want the cancellation", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("returned %v after the start; the cancel came at 200ms", elapsed)
	}
}

// ssh can outlive its stdout (a remote that closed its descriptors, a
// dropped connection waiting for the exit status); a signal then kills it
// instead of waiting for it to exit.
func TestChangesStopsOnCancelAfterStdoutCloses(t *testing.T) {
	p := testProfile("https://example.invalid/org/config.git", "prod", mcpwire.ModeEdit)
	useFakeSSH(t, "close-linger", p)
	pidFile := filepath.Join(t.TempDir(), "pid")
	t.Setenv("PILOT_MCP_FAKE_PID", pidFile)
	o := &Options{ProfileName: "prod-edit", Profile: p, Stderr: io.Discard, CacheDir: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Changes(ctx, o, strings.Repeat("d", 32), t.TempDir())
		done <- err
	}()
	waitForFile(t, pidFile)
	time.Sleep(300 * time.Millisecond) // past the EOF, into the wait for ssh
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Changes did not return after cancellation")
	}
	waitGone(t, pidFile, 3*time.Second)
}

// enclosingRepo returns a cache directory inside a fresh Git repository,
// and a check that the repository was left alone (git must never search
// upward from the cache into it).
func enclosingRepo(t *testing.T) (string, func()) {
	t.Helper()
	outer := t.TempDir()
	git(t, outer, "init", "--quiet")
	return filepath.Join(outer, "cache"), func() {
		t.Helper()
		cmd := exec.Command("git", "-C", outer, "config", "--get", "remote.origin.url")
		if out, err := cmd.Output(); err == nil {
			t.Fatalf("the enclosing repository got remote.origin.url %q", strings.TrimSpace(string(out)))
		}
		if refs := git(t, outer, "for-each-ref", "refs/pilot"); refs != "" {
			t.Fatalf("the enclosing repository got refs: %s", refs)
		}
	}
}

// A git killed while changing the cache can leave lock files or a half
// initialized cache; the next open repairs it under the cache lock, and
// git never reaches a repository around the cache.
func TestGitCacheRepairsWhatAKilledGitLeft(t *testing.T) {
	allowLocalRepos(t)
	bare, commit := makeRepo(t, map[string]string{"prod/hosts.yml": "hosts: {}\n"})
	ctx := context.Background()

	t.Run("stale lock files", func(t *testing.T) {
		cacheDir := t.TempDir()
		repo, err := openGitCache(ctx, cacheDir, bare, 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.resolve(ctx, "main"); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"config.lock", "refs/pilot/fetched.lock"} {
			mustWriteFile(t, filepath.Join(repo.dir, p), "")
		}
		repo, err = openGitCache(ctx, cacheDir, bare, 30*time.Second)
		if err != nil {
			t.Fatalf("open with stale locks: %v", err)
		}
		if got, err := repo.resolve(ctx, "main"); err != nil || got != commit {
			t.Fatalf("resolve = %s, %v", got, err)
		}
	})

	t.Run("half initialized inside a repository", func(t *testing.T) {
		cacheDir, untouched := enclosingRepo(t)
		repo, err := openGitCache(ctx, cacheDir, bare, 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		// What a git init killed after writing HEAD leaves.
		if err := os.RemoveAll(repo.dir); err != nil {
			t.Fatal(err)
		}
		mustWriteFile(t, filepath.Join(repo.dir, "HEAD"), "ref: refs/heads/main\n")
		repo, err = openGitCache(ctx, cacheDir, bare, 30*time.Second)
		if err != nil {
			t.Fatalf("open a half-initialized cache: %v", err)
		}
		if got, err := repo.resolve(ctx, "main"); err != nil || got != commit {
			t.Fatalf("resolve = %s, %v", got, err)
		}
		untouched()
	})
}

// Cancelling at arbitrary points (a signal during startup) never leaves a
// cache the next run cannot use, and never reaches an enclosing repository.
func TestGitCacheSurvivesCancellationAtRandomPoints(t *testing.T) {
	allowLocalRepos(t)
	bare, commit := makeRepo(t, map[string]string{"prod/hosts.yml": "hosts: {}\n"})
	cacheDir, untouched := enclosingRepo(t)
	for i := range 200 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(i%40)*250*time.Microsecond)
		if repo, err := openGitCache(ctx, cacheDir, bare, 30*time.Second); err == nil {
			_, _ = repo.resolve(ctx, "main")
		}
		cancel()
	}
	repo, err := openGitCache(context.Background(), cacheDir, bare, 30*time.Second)
	if err != nil {
		t.Fatalf("open after cancellations: %v", err)
	}
	if got, err := repo.resolve(context.Background(), "main"); err != nil || got != commit {
		t.Fatalf("resolve after cancellations = %s, %v", got, err)
	}
	untouched()
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
	}
	t.Fatalf("%s never appeared", path)
}
