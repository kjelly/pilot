package sshdial

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

	"github.com/kjelly/pilot/internal/childproc"
)

// What these tests are about: every ssh the dialer starts ends, with the
// processes it started that stayed in its process group, when its context
// ends or the connection is closed, and never holds Wait for more than
// childproc.WaitDelay. A fake ssh stands in for OpenSSH and starts a helper
// that keeps only its stderr, as a ProxyJump hop or ProxyCommand would.

// hangAfter is how long a call may take before the test calls it a hang: a
// call that is not bounded cannot be cancelled, so it runs in a goroutine.
const hangAfter = 30 * time.Second

// bounded runs fn and returns how long it took; a call that is still running
// after hangAfter fails the test.
func bounded(t *testing.T, what string, fn func()) time.Duration {
	t.Helper()
	begin := time.Now()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
		return time.Since(begin)
	case <-time.After(hangAfter):
		t.Fatalf("%s did not return within %s: the wait for ssh is not bounded", what, hangAfter)
		return 0
	}
}

// alive reports whether pid is a running process; a zombie nobody has reaped
// is not.
func alive(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	fields := strings.Fields(string(data[strings.LastIndexByte(string(data), ')')+1:]))
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}

// pidFrom reads a recorded pid and kills it when the test ends, so a helper
// that is meant to survive, or one a failing run leaves, never outlives it.
func pidFrom(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s was never written: %v", filepath.Base(path), err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("pid file %s: %q", path, data)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	return pid
}

func mustBeGone(t *testing.T, what string, pid int) {
	t.Helper()
	for deadline := time.Now().Add(time.Second); alive(pid); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%s (pid %d) is still running after the call returned", what, pid)
		}
	}
}

// mustSurvive fails when pid, which nothing was meant to signal, stops running
// within half a second: a SIGKILL takes a moment to show, so checking once
// right away would miss one that was just sent.
func mustSurvive(t *testing.T, what string, pid int) {
	t.Helper()
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if !alive(pid) {
			t.Fatalf("%s (pid %d) was killed, but nothing can (or should) reach it", what, pid)
		}
	}
}

// scriptedSSH writes an ssh stand-in running body (sh) and returns its path
// and the directory it records pids in. The body starts with $PIDS set.
func scriptedSSH(t *testing.T, body string) (path, pids string) {
	t.Helper()
	pids = t.TempDir()
	path = filepath.Join(t.TempDir(), "ssh")
	script := "#!/bin/sh\nPIDS='" + pids + "'\nrecord() { echo \"$2\" > \"$PIDS/$1.tmp\"; mv \"$PIDS/$1.tmp\" \"$PIDS/$1\"; }\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, pids
}

// helper starts, in the fake ssh, a process that holds only ssh's stderr:
// in ssh's process group, or (escaped) in a session of its own.
func helper(escaped bool) string {
	sleeper := "sleep 300"
	if escaped {
		sleeper = "setsid sleep 300"
	}
	return sleeper + " >/dev/null </dev/null &\nrecord helper $!\nrecord ssh $$\n"
}

func needSetsid(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skipf("setsid not installed: %v", err)
	}
}

// ssh and a helper in its group stall; the context ends: both are killed and
// the error says why.
func TestRunStopsAtTheDeadlineWithItsHelper(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(context.Context, *Dialer) error
	}{
		{"hostname -f", func(ctx context.Context, d *Dialer) error { _, err := d.FQDN(ctx); return err }},
		{"cat the CA", func(ctx context.Context, d *Dialer) error { _, err := d.CA(ctx); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ssh, pids := scriptedSSH(t, helper(false)+"exec sleep 300")
			d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var err error
			elapsed := bounded(t, tc.name, func() { err = tc.call(ctx, d) })
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err = %v, want the deadline", err)
			}
			if elapsed > time.Second+2*time.Second+5*time.Second {
				t.Fatalf("returned after %s, want about the 1s deadline", elapsed)
			}
			mustBeGone(t, "ssh", pidFrom(t, filepath.Join(pids, "ssh")))
			mustBeGone(t, "the helper in ssh's group", pidFrom(t, filepath.Join(pids, "helper")))
		})
	}
}

// ssh that exited 0 while a process it started holds its stderr: the command
// fails closed, naming that, and the output it printed is not returned.
func TestRunFailsClosedWhenAHelperKeepsTheOutput(t *testing.T) {
	pem, err := os.ReadFile("testdata/ipa-ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, output string
		call         func(*Dialer) error
	}{
		{"hostname -f", "ipa1.example.test\n", func(d *Dialer) error { _, err := d.FQDN(context.Background()); return err }},
		{"cat the CA", string(pem), func(d *Dialer) error { _, err := d.CA(context.Background()); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ssh, pids := scriptedSSH(t, helper(false)+"cat <<'EOF'\n"+tc.output+"EOF\nexit 0")
			d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
			var err error
			elapsed := bounded(t, tc.name, func() { err = tc.call(d) })
			if !errors.Is(err, childproc.ErrHelperKeptOutput) || !errors.Is(err, exec.ErrWaitDelay) {
				t.Fatalf("err = %v, want it to name the process that kept the output and wrap exec.ErrWaitDelay", err)
			}
			var te *TunnelError
			if errors.As(err, &te) {
				t.Fatalf("a held pipe was reported as an ssh failure: %v", err)
			}
			if elapsed < 1500*time.Millisecond || elapsed > 2*time.Second+10*time.Second {
				t.Fatalf("failed after %s, want about the 2s wait delay", elapsed)
			}
			// The helper is not killed: ssh was reaped, its group id may be reused.
			mustSurvive(t, "the helper", pidFrom(t, filepath.Join(pids, "helper")))
		})
	}
}

// A failing ssh with the same helper is the ssh failure, classified from its
// stderr as before.
func TestRunFailureWithAHelperIsStillClassified(t *testing.T) {
	ssh, pids := scriptedSSH(t, helper(false)+"echo 'root@192.0.2.10: Permission denied (publickey).' >&2\nexit 255")
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
	var err error
	bounded(t, "FQDN", func() { _, err = d.FQDN(context.Background()) })
	var te *TunnelError
	if !errors.Is(err, ErrSSH) || !errors.As(err, &te) || te.ExitCode != 255 || errors.Is(err, childproc.ErrHelperKeptOutput) || errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("err = %v, want the classified ssh failure", err)
	}
	pidFrom(t, filepath.Join(pids, "helper"))
}

// Closing a tunnel ends its ssh and the helper in its group at once; before,
// Close waited for the helper's hold on stderr.
func TestConnCloseKillsSSHAndItsHelper(t *testing.T) {
	ssh, pids := scriptedSSH(t, helper(false)+"exec cat")
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
	c, err := d.DialContext(context.Background(), "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	// One round trip, so the fake ssh has recorded its pids.
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	elapsed := bounded(t, "Close", func() { _ = c.Close() })
	if elapsed > 2*time.Second+5*time.Second {
		t.Fatalf("Close took %s", elapsed)
	}
	mustBeGone(t, "ssh", pidFrom(t, filepath.Join(pids, "ssh")))
	mustBeGone(t, "the helper in ssh's group", pidFrom(t, filepath.Join(pids, "helper")))
}

// A helper that left the group still holds ssh's stderr after the kill; Close
// returns once the wait delay has run out, and the helper, which nothing can
// reach, survives.
func TestConnCloseWithAnEscapedHelperIsBounded(t *testing.T) {
	needSetsid(t)
	ssh, pids := scriptedSSH(t, helper(true)+"exec cat")
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
	c, err := d.DialContext(context.Background(), "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	elapsed := bounded(t, "Close", func() { _ = c.Close() })
	if elapsed > 2*time.Second+5*time.Second {
		t.Fatalf("Close took %s, want at most the wait delay", elapsed)
	}
	mustBeGone(t, "ssh", pidFrom(t, filepath.Join(pids, "ssh")))
	mustSurvive(t, "the escaped helper (is it in ssh's group after all?)", pidFrom(t, filepath.Join(pids, "helper")))
}

// The server closes the connection (ssh exits 0 after its output ended) while
// a process ssh started still holds its stderr: the data stream ended
// cleanly, which is what Read reports. A failure here would make a
// server-closed keep-alive connection look like an ssh error.
func TestConnReadEndsCleanlyWhenAHelperKeepsStderr(t *testing.T) {
	ssh, pids := scriptedSSH(t, helper(false)+"printf bye\nexit 0")
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
	c, err := d.DialContext(context.Background(), "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	bounded(t, "Read", func() { got, err = io.ReadAll(c) })
	if err != nil || string(got) != "bye" {
		t.Fatalf("read %q, %v; want bye and a clean EOF", got, err)
	}
	// ssh was reaped: closing the connection signals nothing, so the helper,
	// which is in a group that may since have been given to another process,
	// is left alone.
	_ = c.Close()
	mustSurvive(t, "the helper (Close signalled the group of a reaped ssh)", pidFrom(t, filepath.Join(pids, "helper")))
}

// AcquireLock gives up with its context, and then ssh and the helper in its
// group are gone.
func TestAcquireLockCancelKillsSSHAndItsHelper(t *testing.T) {
	ssh, pids := scriptedSSH(t, helper(false)+"exec sleep 300")
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if _, err := os.Stat(filepath.Join(pids, "ssh")); err == nil {
				break
			}
		}
		cancel()
	}()
	var err error
	elapsed := bounded(t, "AcquireLock", func() { _, err = d.AcquireLock(ctx, LockOptions{Path: "/etc/ipa"}) })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cancellation", err)
	}
	if elapsed > 2*time.Second+5*time.Second {
		t.Fatalf("AcquireLock took %s after the cancel", elapsed)
	}
	mustBeGone(t, "ssh", pidFrom(t, filepath.Join(pids, "ssh")))
	mustBeGone(t, "the helper in ssh's group", pidFrom(t, filepath.Join(pids, "helper")))
}

// Every ssh the dialer starts leads a session of its own: the one place that
// starts them isolates them, whatever the caller (a remote command, a tunnel,
// the lock).
func TestEverySSHLeadsItsOwnSession(t *testing.T) {
	ssh, pids := scriptedSSH(t, `
cat /proc/$$/stat > "$PIDS/stat.$$"
case "$*" in
*" -W "*) exec cat ;;
*flock*) echo locked; exec cat ;;
*"hostname -f"*) echo ipa1.example.test ;;
*) exit 0 ;;
esac
`)
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
	ctx := context.Background()
	if _, err := d.FQDN(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CA(ctx); err == nil {
		t.Fatal("the fake ssh printed no CA, but CA succeeded")
	}
	c, err := d.DialContext(ctx, "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	lock, err := d.AcquireLock(ctx, LockOptions{Path: "/etc/ipa"})
	if err != nil {
		t.Fatal(err)
	}
	_ = lock.Release()

	files, _ := filepath.Glob(filepath.Join(pids, "stat.*"))
	if len(files) != 4 {
		t.Fatalf("recorded %d ssh processes, want 4 (hostname -f, the CA, the tunnel, the lock)", len(files))
	}
	self, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	mySession := strings.Fields(string(self[strings.LastIndexByte(string(self), ')')+1:]))[3]
	for _, file := range files {
		data, _ := os.ReadFile(file)
		pid := strings.Fields(string(data))[0]
		fields := strings.Fields(string(data[strings.LastIndexByte(string(data), ')')+1:]))
		pgrp, session := fields[2], fields[3]
		if pgrp != pid || session != pid || session == mySession {
			t.Errorf("ssh pid %s has process group %s and session %s (this process's is %s): want a session of its own", pid, pgrp, session, mySession)
		}
	}
}
