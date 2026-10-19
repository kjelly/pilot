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

// A SIGTERM while ssh is mid-login (key accepted, PAM account phase running)
// kills ssh with exactly the signature of a PAM account denial. The attempt
// must come back Canceled and leave the metrics as they were (PR #80
// review: `systemctl stop` produced a critical AccountDenied).
func TestProber_CanceledMidLoginIsNotRecorded(t *testing.T) {
	bin := fakeSSH(t, `echo "debug1: Remote protocol version 2.0, remote software version OpenSSH_9.6p1" >&2
echo "debug1: Server accepts key: /etc/pilot/login-probe/id_ed25519 ED25519 SHA256:x explicit" >&2
sleep 30`)
	targets := []Target{{Name: "t1", Host: "t1.x", Port: 22}}
	cfg := Config{Targets: targets, Concurrency: 1}
	metrics := NewMetrics(targets)
	before := metrics.Registry.Render()
	r := Runner{SSHBinary: bin, SSHConfig: "/dev/null", User: "u", Command: "/bin/true", ConnectTimeout: time.Second, TotalTimeout: 20 * time.Second, Env: []string{"PATH=/usr/bin:/bin"}}
	p := NewProber(cfg, r, metrics, nil)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	start := time.Now()
	outcomes := p.Round(ctx)
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("Round took %s after cancel; ssh was not killed", el)
	}
	if len(outcomes) != 1 || !outcomes[0].Canceled || outcomes[0].Stage != "" {
		t.Fatalf("outcomes = %+v, want one Canceled outcome without a stage", outcomes)
	}
	if after := metrics.Registry.Render(); after != before {
		t.Errorf("a canceled attempt changed the metrics:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	// The same output without cancellation is a PAM account denial: the
	// test above is about cancellation, not about the classifier.
	r.TotalTimeout = 20 * time.Second
	bin2 := fakeSSH(t, `echo "debug1: Remote protocol version 2.0, remote software version OpenSSH_9.6p1" >&2
echo "debug1: Server accepts key: /etc/pilot/login-probe/id_ed25519 ED25519 SHA256:x explicit" >&2
exit 255`)
	r.SSHBinary = bin2
	if got := NewProber(cfg, r, NewMetrics(targets), nil).Round(context.Background()); got[0].Canceled || got[0].Stage != StageAccount {
		t.Errorf("uncanceled outcome = %+v, want stage account", got[0])
	}
}

func TestProber_TargetsNeverStartedAreCanceled(t *testing.T) {
	targets := []Target{{Name: "a", Host: "a.x", Port: 22}, {Name: "b", Host: "b.x", Port: 22}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Runner{SSHBinary: "/bin/false", SSHConfig: "/dev/null", User: "u", Command: "/bin/true", ConnectTimeout: time.Second, TotalTimeout: time.Second}
	for _, o := range NewProber(Config{Targets: targets, Concurrency: 1}, r, NewMetrics(targets), nil).Round(ctx) {
		if !o.Canceled {
			t.Errorf("%s: %+v, want Canceled", o.Target.Name, o)
		}
	}
}
