package sshdial

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

// reaped reports that pid has no /proc entry at all, not even a zombie: Wait
// has returned for it.
func reaped(pid int) bool {
	_, err := os.Stat("/proc/" + strconv.Itoa(pid))
	return errors.Is(err, os.ErrNotExist)
}

// waitForFile waits until path exists (the fake ssh has got that far).
func waitForFile(t *testing.T, path string) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was never written: the fake ssh did not get there", filepath.Base(path))
		}
	}
}

// A tunnel nobody closes (net/http dials in a goroutine of its own, and
// CloseIdleConnections does not wait for a dial in progress) is ended by
// Dialer.Close, which returns once Wait has returned for it: ssh has no
// /proc entry when Close returns. A helper in ssh's group goes with it at
// once; an escaped one holds stderr, so Close takes the wait delay (and the
// helper survives, nothing can reach it). Afterwards the Dialer starts no
// ssh, and closing the connection or the Dialer again is harmless.
func TestDialerCloseEndsATunnelNobodyClosed(t *testing.T) {
	for _, escaped := range []bool{false, true} {
		name := "a helper in ssh's group"
		if escaped {
			name = "an escaped helper"
		}
		t.Run(name, func(t *testing.T) {
			if escaped {
				needSetsid(t)
			}
			ssh, pids := scriptedSSH(t, "echo run >> \"$PIDS/log\"\n"+helper(escaped)+"exec sleep 300")
			d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
			c, err := d.DialContext(context.Background(), "tcp", "")
			if err != nil {
				t.Fatal(err)
			}
			waitForFile(t, filepath.Join(pids, "ssh"))
			sshPID, helperPID := pidFrom(t, filepath.Join(pids, "ssh")), pidFrom(t, filepath.Join(pids, "helper"))

			elapsed := bounded(t, "Close", func() { d.Close() })
			if !reaped(sshPID) {
				t.Fatalf("ssh %d is not reaped when Close returned", sshPID)
			}
			if escaped {
				if elapsed < childproc.WaitDelay-500*time.Millisecond {
					t.Fatalf("Close returned after %s: it did not wait for Wait (the escaped helper holds stderr for the %s wait delay)", elapsed, childproc.WaitDelay)
				}
				mustSurvive(t, "the escaped helper", helperPID)
			} else {
				if elapsed >= childproc.WaitDelay {
					t.Fatalf("Close took %s: the helper in ssh's group was not killed with it", elapsed)
				}
				mustBeGone(t, "the helper in ssh's group", helperPID)
			}

			if _, err := d.DialContext(context.Background(), "tcp", ""); !errors.Is(err, ErrDialerClosed) {
				t.Fatalf("DialContext after Close: %v, want ErrDialerClosed", err)
			}
			if _, err := d.FQDN(context.Background()); !errors.Is(err, ErrDialerClosed) {
				t.Fatalf("FQDN after Close: %v, want ErrDialerClosed", err)
			}
			if _, err := d.CA(context.Background()); !errors.Is(err, ErrDialerClosed) {
				t.Fatalf("CA after Close: %v, want ErrDialerClosed", err)
			}
			if _, err := d.AcquireLock(context.Background(), LockOptions{Path: "/etc/ipa"}); !errors.Is(err, ErrDialerClosed) {
				t.Fatalf("AcquireLock after Close: %v, want ErrDialerClosed", err)
			}
			if data, _ := os.ReadFile(filepath.Join(pids, "log")); string(data) != "run\n" {
				t.Fatalf("ssh ran %q, want once: nothing is started after Close", data)
			}
			bounded(t, "closing the connection after Close", func() { _ = c.Close() })
			bounded(t, "a second Close", func() { d.Close() })
			d.mu.Lock()
			left := len(d.live)
			d.mu.Unlock()
			if left != 0 {
				t.Fatalf("%d processes still registered after every one was reaped", left)
			}
		})
	}
}

// Close ends whatever the Dialer started, not only tunnels: a remote command
// that is stalled (its caller gets an error, not ErrDialerClosed) and a held
// lock (Lost fires).
func TestDialerCloseEndsARemoteCommandAndAHeldLock(t *testing.T) {
	ssh, pids := scriptedSSH(t, `
case "$*" in
*flock*) echo locked; record lock $$; exec cat ;;
*"hostname -f"*) record fqdn $$; exec sleep 300 ;;
esac
exit 99
`)
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
	lock, err := d.AcquireLock(context.Background(), LockOptions{Path: "/etc/ipa"})
	if err != nil {
		t.Fatal(err)
	}
	fqdnErr := make(chan error, 1)
	go func() { _, err := d.FQDN(context.Background()); fqdnErr <- err }()
	waitForFile(t, filepath.Join(pids, "fqdn"))
	lockPID, fqdnPID := pidFrom(t, filepath.Join(pids, "lock")), pidFrom(t, filepath.Join(pids, "fqdn"))

	bounded(t, "Close", func() { d.Close() })
	if !reaped(lockPID) || !reaped(fqdnPID) {
		t.Fatalf("lock ssh %d reaped: %v, hostname -f ssh %d reaped: %v", lockPID, reaped(lockPID), fqdnPID, reaped(fqdnPID))
	}
	select {
	case <-lock.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("the lock was not reported lost after Close ended its ssh")
	}
	select {
	case err := <-fqdnErr:
		var te *TunnelError
		if err == nil || errors.Is(err, ErrDialerClosed) || !errors.As(err, &te) {
			t.Fatalf("FQDN ended by Close returned %v, want the ssh failure (it was started before Close)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FQDN did not return after Close ended its ssh")
	}
}

// Dials racing Close: every ssh that started is reaped when Close returns,
// and every dial that came after it is refused. start registers a process
// under the lock that Close takes its snapshot under, so none escapes.
func TestDialerCloseRacingDials(t *testing.T) {
	ssh, pids := scriptedSSH(t, "record \"ssh.$$\" $$\nexec sleep 300")
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
	const dialers = 8
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		conns []net.Conn
		other []error
	)
	started := make(chan struct{}, dialers)
	for range dialers {
		wg.Go(func() {
			first := true
			// The cap only keeps a Close that is late from piling up
			// processes: Close comes after the first tunnel of each.
			for range 40 {
				c, err := d.DialContext(context.Background(), "tcp", "")
				if errors.Is(err, ErrDialerClosed) {
					return
				}
				mu.Lock()
				if err != nil {
					other = append(other, err)
				} else {
					conns = append(conns, c)
				}
				mu.Unlock()
				if first {
					first = false
					started <- struct{}{}
				}
				if err != nil {
					return
				}
			}
		})
	}
	for range dialers {
		select {
		case <-started:
		case <-time.After(30 * time.Second):
			t.Fatal("the dialers never got a tunnel")
		}
	}
	// recorded lists the ssh that wrote their pid: record writes name.tmp and
	// renames it, so a process killed in between leaves the .tmp behind and has
	// not recorded itself.
	recorded := func() []string {
		all, _ := filepath.Glob(filepath.Join(pids, "ssh.*"))
		var files []string
		for _, f := range all {
			if !strings.HasSuffix(f, ".tmp") {
				files = append(files, f)
			}
		}
		return files
	}
	// A dial returns when ssh is started, not when the script got to record
	// itself: Close comes once every dialer has a running ssh that did.
	for deadline := time.Now().Add(30 * time.Second); len(recorded()) < dialers; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("recorded %d ssh, want %d before Close", len(recorded()), dialers)
		}
	}
	bounded(t, "Close", func() { d.Close() })
	bounded(t, "the dialers", wg.Wait)
	files := recorded()
	d.mu.Lock()
	registered := len(d.live)
	d.mu.Unlock()
	if registered != 0 {
		t.Errorf("%d ssh still registered after Close returned: started, but never signalled or waited for", registered)
	}
	for _, f := range files {
		pid := pidFrom(t, f)
		if !reaped(pid) {
			t.Errorf("ssh %d is not reaped after Close returned", pid)
		}
	}
	if len(other) != 0 {
		t.Errorf("dials failed with something else than ErrDialerClosed: %v", other)
	}
	for _, c := range conns {
		_ = c.Close()
	}
}
