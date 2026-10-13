package loginprobe

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeSSH(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunner_ArgvIsFixedAndPinsTheConfig(t *testing.T) {
	r := Runner{SSHBinary: "/usr/bin/ssh", SSHConfig: "/etc/pilot/login-probe/ssh_config", User: "pilot-login-canary", Command: "/bin/true", ConnectTimeout: 10 * time.Second, TotalTimeout: 30 * time.Second}
	got := strings.Join(r.Argv(Target{Name: "a", Host: "a.ipa.pilot.internal", Port: 2222}), " ")
	want := "/usr/bin/ssh -F /etc/pilot/login-probe/ssh_config -v -o BatchMode=yes -o ConnectTimeout=10 -p 2222 -l pilot-login-canary a.ipa.pilot.internal /bin/true"
	if got != want {
		t.Errorf("argv:\n got %s\nwant %s", got, want)
	}
}

func TestRunner_CapturesExitCodeAndStreams(t *testing.T) {
	bin := fakeSSH(t, `echo "debug1: Authenticated to $7" >&2; echo "Permission denied (publickey)." >&2; echo out; exit 255`)
	r := Runner{SSHBinary: bin, SSHConfig: "/dev/null", User: "u", Command: "/bin/true", ConnectTimeout: time.Second, TotalTimeout: 5 * time.Second, Env: []string{"PATH=/usr/bin:/bin"}}
	res := r.Run(context.Background(), Target{Name: "a", Host: "a.x", Port: 22})
	if res.ExitCode != 255 || res.TimedOut || res.StartErr != nil {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !strings.Contains(res.Stderr, "Permission denied") || !strings.Contains(res.Stdout, "out") {
		t.Errorf("streams not captured: %+v", res)
	}
}

func TestRunner_TimeoutKillsTheProcessGroup(t *testing.T) {
	// The fake ssh spawns a child (like a ProxyCommand) and both sleep; the
	// runner must return at total_timeout and leave no child behind.
	bin := fakeSSH(t, `sleep 30 & echo $! > "$TESTPID"; sleep 30`)
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	r := Runner{SSHBinary: bin, SSHConfig: "/dev/null", User: "u", Command: "/bin/true", ConnectTimeout: time.Second, TotalTimeout: 300 * time.Millisecond, Env: []string{"PATH=/usr/bin:/bin", "TESTPID=" + pidFile}}
	start := time.Now()
	res := r.Run(context.Background(), Target{Name: "a", Host: "a.x", Port: 22})
	if !res.TimedOut {
		t.Fatalf("expected TimedOut, got %+v", res)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("Run took %s, want about total_timeout", el)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("child pid not recorded: %v", err)
	}
	pid := strings.TrimSpace(string(data))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat("/proc/" + pid); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("child process %s survived the timeout: the process group was not killed", pid)
}

func TestRunner_MissingBinaryIsAStartError(t *testing.T) {
	r := Runner{SSHBinary: filepath.Join(t.TempDir(), "nope"), SSHConfig: "/dev/null", User: "u", Command: "/bin/true", ConnectTimeout: time.Second, TotalTimeout: time.Second}
	res := r.Run(context.Background(), Target{Name: "a", Host: "a.x", Port: 22})
	if res.StartErr == nil || res.ExitCode != -1 {
		t.Errorf("expected StartErr, got %+v", res)
	}
}
