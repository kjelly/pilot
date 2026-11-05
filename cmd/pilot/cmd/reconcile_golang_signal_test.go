package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Spec §3: the session ends after --timeout or Ctrl-C ended the preview, and
// that logout is bounded: it goes out on a context that has not been
// canceled, but a server that is not answering cannot hold pilot for the
// client's whole request timeout (2 minutes) after the deadline.
func TestReconcileGolangLogoutAfterTheDeadlineIsBounded(t *testing.T) {
	f := newFakeIPA(t, "p1-self")
	withFakeDialer(t, f)
	golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
	f.hang = map[string]bool{"ping": true, "session_logout": true}
	prev := golangLogoutTimeout
	golangLogoutTimeout = time.Second
	t.Cleanup(func() { golangLogoutTimeout = prev })

	type result struct {
		out string
		err error
	}
	done := make(chan result, 1)
	begin := time.Now()
	go func() {
		out, err := runReconcileCLI(t, previewArgs("--timeout", "2s")...)
		done <- result{out, err}
	}()
	var res result
	select {
	case res = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the preview did not return: the logout after the deadline is not bounded")
	}
	elapsed := time.Since(begin)
	if !errors.Is(res.err, context.DeadlineExceeded) || processExitCode(res.err) != 1 {
		t.Fatalf("err = %v (exit %d), want the deadline and exit 1\n%s", res.err, processExitCode(res.err), res.out)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("took %s: --timeout 2s plus a 1s logout bound", elapsed)
	}
	_, methods := f.requests()
	if !slices.Equal(methods, []string{"ping", "session_logout"}) {
		t.Fatalf("methods = %v, want the logout sent after the deadline (on a context that was not canceled)", methods)
	}
}

// secondInterruptChildEnv, set to 1, makes TestReconcileGolangSecondInterruptEndsPilot
// run its body (the preview) instead of starting the child that runs it.
const secondInterruptChildEnv = "PILOT_TEST_SECOND_INTERRUPT_CHILD"

// Ctrl-C ends the preview but the logout after it still runs; a second
// Ctrl-C then ends pilot at once instead of waiting for it, because the first
// signal restores the default handling (context.AfterFunc(sigCtx, stop)).
// The preview runs in a child process of this test binary whose server never
// answers the ping or the logout; the parent signals it twice, each time once
// the child reports it reached the matching step, and the child must die of
// the second signal well before its 30-second logout bound.
func TestReconcileGolangSecondInterruptEndsPilot(t *testing.T) {
	if os.Getenv(secondInterruptChildEnv) == "1" {
		secondInterruptChild(t)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marks := t.TempDir()
	cmd := exec.Command(exe, "-test.run=^TestReconcileGolangSecondInterruptEndsPilot$", "-test.count=1")
	cmd.Env = append(os.Environ(), secondInterruptChildEnv+"=1", "PILOT_TEST_MARKS="+marks)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	waitMark := func(name string) {
		t.Helper()
		for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(20 * time.Millisecond) {
			if _, err := os.Stat(filepath.Join(marks, name)); err == nil {
				return
			}
			select {
			case err := <-exited:
				t.Fatalf("the child ended (%v) before %s:\n%s", err, name, out.String())
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("the child never reached %s:\n%s", name, out.String())
			}
		}
	}
	waitMark("ping")
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	waitMark("logout") // the first Ctrl-C ended the preview; the logout is under way
	begin := time.Now()
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("the child ended with %v, want it killed by the second SIGINT\n%s", err, out.String())
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGINT {
			t.Fatalf("the child ended with %v after %s, want it killed by SIGINT\n%s", err, time.Since(begin), out.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the second Ctrl-C did not end pilot (the child was still in its logout after %s)", time.Since(begin))
	}
}

// secondInterruptChild is the preview the parent signals: a server that never
// answers the ping or the logout, and marks the parent waits for.
func secondInterruptChild(t *testing.T) {
	marks := os.Getenv("PILOT_TEST_MARKS")
	f := newFakeIPA(t, "p1-self")
	withFakeDialer(t, f)
	golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
	f.hang = map[string]bool{"ping": true, "session_logout": true}
	golangLogoutTimeout = 30 * time.Second
	mark := func(name string, seen func(methods []string) bool) {
		go func() {
			for {
				if _, methods := f.requests(); seen(methods) {
					_ = os.WriteFile(filepath.Join(marks, name), nil, 0o600)
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}
	mark("ping", func(m []string) bool { return slices.Contains(m, "ping") })
	mark("logout", func(m []string) bool { return slices.Contains(m, "session_logout") })
	_, err := runReconcileCLI(t, previewArgs("--timeout", "10m")...)
	t.Fatalf("the preview returned (%v): the second SIGINT should have ended the process", err)
}
