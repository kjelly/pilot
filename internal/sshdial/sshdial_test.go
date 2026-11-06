package sshdial

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeSSH writes an `ssh` stand-in and returns its path and a function
// listing the argv it was run with (one call per line, tab-separated).
//
// FAKE_SSH_MODE selects what it does:
//   - echo: copy stdin to stdout (a working -W tunnel to an echo server)
//   - replay: print testdata/<FAKE_SSH_CAPTURE>.stderr to stderr and exit
//     with its .rc (real OpenSSH failures)
//   - stdout: print FAKE_SSH_STDOUT and exit 0
//   - local: run the remote command locally with sh -c
func fakeSSH(t *testing.T, mode string, env ...string) (string, func() [][]string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "argv.log")
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/bash
( IFS=$'\t'; printf '%s\n' "$*" ) >> "` + log + `"
case "$FAKE_SSH_MODE" in
echo) exec cat ;;
replay) cat "` + testdata + `/$FAKE_SSH_CAPTURE.stderr" >&2; exit "$(cat "` + testdata + `/$FAKE_SSH_CAPTURE.rc")" ;;
stdout) printf '%s' "$FAKE_SSH_STDOUT"; exit 0 ;;
local)
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
  shift 2
  exec sh -c "$*" ;;
esac
exit 99
`
	path := filepath.Join(dir, "ssh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_SSH_MODE", mode)
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
	return path, func() [][]string {
		raw, err := os.ReadFile(log)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		var calls [][]string
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			calls = append(calls, strings.Split(line, "\t"))
		}
		return calls
	}
}

var testTarget = Target{
	Host: "192.0.2.10", User: "root", Port: 2222, IdentityFile: "/keys/id_ed25519",
	Options: map[string]string{"UserKnownHostsFile": "/dev/null", "StrictHostKeyChecking": "no"},
}

func TestDialerRunsSSHWithFixedArgv(t *testing.T) {
	ssh, calls := fakeSSH(t, "echo")
	d := &Dialer{Target: testTarget, SSH: ssh}
	c, err := d.DialContext(context.Background(), "tcp", "ignored.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	// One round trip, so ssh has started (and logged) before Close kills it.
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	want := []string{
		"-o", "BatchMode=yes", "-o", "ControlPath=none", "-o", "ClearAllForwardings=yes",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "2222", "-i", "/keys/id_ed25519", "-l", "root",
		"-W", "127.0.0.1:443", "--", "192.0.2.10",
	}
	if got := calls(); len(got) != 1 || !slices.Equal(got[0], want) {
		t.Fatalf("ssh argv = %q\nwant %q", got, want)
	}
}

func TestTargetRejectsUnsafeInput(t *testing.T) {
	ssh, calls := fakeSSH(t, "echo")
	for name, tgt := range map[string]Target{
		"host that is an option":   {Host: "-oProxyCommand=sh"},
		"unsupported option":       {Host: "ipa1.example.test", Options: map[string]string{"ProxyCommand": "nc %h %p"}},
		"option value with spaces": {Host: "ipa1.example.test", Options: map[string]string{"ProxyJump": "a b"}},
		"user with a space":        {Host: "ipa1.example.test", User: "root admin"},
	} {
		t.Run(name, func(t *testing.T) {
			d := &Dialer{Target: tgt, SSH: ssh}
			if _, err := d.DialContext(context.Background(), "tcp", ""); err == nil {
				t.Fatal("expected the target to be rejected")
			}
		})
	}
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, Destination: "127.0.0.1:443; rm -rf /", SSH: ssh}
	if _, err := d.DialContext(context.Background(), "tcp", ""); err == nil {
		t.Fatal("expected the destination to be rejected")
	}
	if got := calls(); len(got) != 0 {
		t.Fatalf("ssh ran for rejected input: %q", got)
	}
}

func TestConnCarriesBytesBothWays(t *testing.T) {
	ssh, _ := fakeSSH(t, "echo")
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
	c, err := d.DialContext(context.Background(), "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping\n" {
		t.Fatalf("read %q, %v", buf, err)
	}
	// A deadline in the past makes Read fail instead of blocking.
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read past the deadline: %v", err)
	}
}

func TestConnReportsWhySSHFailed(t *testing.T) {
	for capture, kind := range map[string]error{
		"allowtcpforwarding-no": ErrForwardingDenied,
		"disableforwarding-yes": ErrForwardingDenied,
		"permitopen-other":      ErrForwardingDenied,
		"destination-refused":   ErrDestinationRefused,
		"auth-failed":           ErrSSH,
	} {
		t.Run(capture, func(t *testing.T) {
			ssh, _ := fakeSSH(t, "replay", "FAKE_SSH_CAPTURE="+capture)
			d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
			c, err := d.DialContext(context.Background(), "tcp", "")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_, err = c.Read(make([]byte, 1))
			var te *TunnelError
			if !errors.Is(err, kind) || !errors.As(err, &te) || te.ExitCode != 255 {
				t.Fatalf("read error = %v, want %v with ssh exit 255", err, kind)
			}
			stderr, _ := os.ReadFile(filepath.Join("testdata", capture+".stderr"))
			last := strings.Split(strings.TrimSpace(string(stderr)), "\n")
			if !strings.Contains(err.Error(), last[len(last)-1]) {
				t.Fatalf("error %q does not carry ssh's message", err)
			}
		})
	}
}

func TestConnClosedHereIsNotAnSSHFailure(t *testing.T) {
	ssh, _ := fakeSSH(t, "echo")
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
	c, err := d.DialContext(context.Background(), "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after Close = %v, want net.ErrClosed", err)
	}
}

func TestConnEndsCleanlyWhenTheServerCloses(t *testing.T) {
	ssh, _ := fakeSSH(t, "stdout", "FAKE_SSH_STDOUT=bye")
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
	c, err := d.DialContext(context.Background(), "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "bye" {
		t.Fatalf("read %q, %v; want bye and a clean EOF", got, err)
	}
}

func TestFQDNAndCA(t *testing.T) {
	t.Run("fqdn is lowered", func(t *testing.T) {
		ssh, calls := fakeSSH(t, "stdout", "FAKE_SSH_STDOUT=IPA1.Example.TEST\n")
		got, err := (&Dialer{Target: Target{Host: "192.0.2.10"}, SSH: ssh}).FQDN(context.Background())
		if err != nil || got != "ipa1.example.test" {
			t.Fatalf("FQDN = %q, %v", got, err)
		}
		if c := calls(); c[0][len(c[0])-1] != "hostname -f" {
			t.Fatalf("remote command = %q", c[0])
		}
	})
	t.Run("a short name is rejected", func(t *testing.T) {
		ssh, _ := fakeSSH(t, "stdout", "FAKE_SSH_STDOUT=ipa1\n")
		if _, err := (&Dialer{Target: Target{Host: "192.0.2.10"}, SSH: ssh}).FQDN(context.Background()); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("the CA is read and pinned", func(t *testing.T) {
		pem, err := os.ReadFile("testdata/ipa-ca.crt")
		if err != nil {
			t.Fatal(err)
		}
		ssh, calls := fakeSSH(t, "stdout", "FAKE_SSH_STDOUT="+string(pem))
		pool, err := (&Dialer{Target: Target{Host: "192.0.2.10"}, SSH: ssh}).CA(context.Background())
		if err != nil || pool == nil {
			t.Fatalf("CA: %v", err)
		}
		if c := calls(); c[0][len(c[0])-1] != "cat /etc/ipa/ca.crt" {
			t.Fatalf("remote command = %q", c[0])
		}
	})
	t.Run("no certificate is an error", func(t *testing.T) {
		ssh, _ := fakeSSH(t, "stdout", "FAKE_SSH_STDOUT=not a certificate")
		if _, err := (&Dialer{Target: Target{Host: "192.0.2.10"}, SSH: ssh}).CA(context.Background()); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestLockIsExclusiveUntilReleased(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock not installed")
	}
	ssh, calls := fakeSSH(t, "local")
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
	opts := LockOptions{Path: t.TempDir()}
	ctx := context.Background()

	first, err := d.AcquireLock(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.AcquireLock(ctx, opts); !errors.Is(err, ErrLockBusy) {
		t.Fatalf("second acquire = %v, want ErrLockBusy", err)
	}
	waited := opts
	waited.Wait = time.Second
	start := time.Now()
	if _, err := d.AcquireLock(ctx, waited); !errors.Is(err, ErrLockBusy) || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("acquire with a 1s wait = %v after %v, want ErrLockBusy after about 1s", err, time.Since(start))
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first.Lost():
	default:
		t.Fatal("Lost is not closed after Release")
	}
	again, err := d.AcquireLock(ctx, opts)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	_ = again.Release()

	want := "flock --nonblock --conflict-exit-code 75 " + opts.Path + " sh -c 'echo locked; exec cat'"
	if c := calls(); c[0][len(c[0])-1] != want || c[2][len(c[2])-1] != strings.Replace(want, "--nonblock", "--wait 1", 1) {
		t.Fatalf("remote commands = %q", c)
	}
}

func TestLockRejectsUnsafePath(t *testing.T) {
	ssh, calls := fakeSSH(t, "local")
	d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
	for _, p := range []string{"relative", "/etc/ipa; reboot", "/etc/../root", "/etc/ipa'x"} {
		if _, err := d.AcquireLock(context.Background(), LockOptions{Path: p}); err == nil {
			t.Fatalf("lock path %q was accepted", p)
		}
	}
	if got := calls(); len(got) != 0 {
		t.Fatalf("ssh ran for a rejected path: %q", got)
	}
}

// The lock is held by its ssh session, so that session runs with a keepalive
// (about 45 s of a dead network ends it and Lost fires), unless the Target set
// its own. The tunnel's ssh does not get it: only the lock's session has the
// "I still hold it" meaning (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md
// R8, R10).
func TestLockSessionRunsWithAKeepaliveUnlessTheTargetSetsItsOwn(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock not installed")
	}
	option := func(argv []string, key string) (string, bool) {
		for i := 0; i+1 < len(argv); i++ {
			if argv[i] == "-o" {
				if v, ok := strings.CutPrefix(argv[i+1], key+"="); ok {
					return v, true
				}
			}
		}
		return "", false
	}
	for name, tc := range map[string]struct {
		options        map[string]string
		wantInterval   string
		wantCountMax   string
		wantFromTarget bool
	}{
		"the defaults":                  {nil, "15", "3", false},
		"the target's own settings win": {map[string]string{"ServerAliveInterval": "5", "ServerAliveCountMax": "9"}, "5", "9", true},
		"one of the two set":            {map[string]string{"ServerAliveInterval": "7"}, "7", "3", true},
	} {
		t.Run(name, func(t *testing.T) {
			ssh, calls := fakeSSH(t, "local")
			target := Target{Host: "ipa1.example.test", Options: tc.options}
			d := &Dialer{Target: target, SSH: ssh}
			lock, err := d.AcquireLock(context.Background(), LockOptions{Path: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			_ = lock.Release()
			argv := calls()[0]
			if got, ok := option(argv, "ServerAliveInterval"); !ok || got != tc.wantInterval {
				t.Fatalf("ServerAliveInterval = %q (set: %v) in %q, want %q", got, ok, argv, tc.wantInterval)
			}
			if got, ok := option(argv, "ServerAliveCountMax"); !ok || got != tc.wantCountMax {
				t.Fatalf("ServerAliveCountMax = %q (set: %v) in %q, want %q", got, ok, argv, tc.wantCountMax)
			}
			// The Dialer's Target is not edited: what AcquireLock added is its own.
			if len(d.Target.Options) != len(tc.options) {
				t.Fatalf("AcquireLock wrote into the Dialer's Target: %v", d.Target.Options)
			}
		})
	}
	t.Run("the tunnel's ssh has none", func(t *testing.T) {
		ssh, calls := fakeSSH(t, "echo")
		d := &Dialer{Target: Target{Host: "ipa1.example.test"}, SSH: ssh}
		c, err := d.DialContext(context.Background(), "tcp", "")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("x"))
		_, _ = io.ReadFull(c, make([]byte, 1))
		_ = c.Close()
		if _, ok := option(calls()[0], "ServerAliveInterval"); ok {
			t.Fatalf("the tunnel's ssh has the lock's keepalive: %q", calls()[0])
		}
		if _, ok := option(calls()[0], "ConnectTimeout"); ok {
			t.Fatalf("the tunnel's ssh has the lock's connect timeout: %q", calls()[0])
		}
	})
}

// The lock's ssh also bounds its TCP connect, unless the Target says how long
// it should wait: the pilot edit break-glass takes the lock synchronously
// with no context, and a server that does not answer would otherwise hold the
// screen for the operating system's connect timeout. The bound is for the
// connection only: waiting for a busy lock is flock's, and is not touched.
func TestLockSessionBoundsItsConnectUnlessTheTargetSetsItsOwn(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock not installed")
	}
	for name, tc := range map[string]struct {
		options map[string]string
		want    string
	}{
		"the default":               {nil, "ConnectTimeout=" + lockConnectTimeout},
		"the target's own value":    {map[string]string{"ConnectTimeout": "7"}, "ConnectTimeout=7"},
		"unrelated options present": {map[string]string{"StrictHostKeyChecking": "no"}, "ConnectTimeout=" + lockConnectTimeout},
	} {
		t.Run(name, func(t *testing.T) {
			ssh, calls := fakeSSH(t, "local")
			d := &Dialer{Target: Target{Host: "ipa1.example.test", Options: tc.options}, SSH: ssh}
			lock, err := d.AcquireLock(context.Background(), LockOptions{Path: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			_ = lock.Release()
			argv := strings.Join(calls()[0], " ")
			if !strings.Contains(argv, "-o "+tc.want+" ") {
				t.Fatalf("argv = %q, want -o %s", argv, tc.want)
			}
			if strings.Count(argv, "ConnectTimeout=") != 1 {
				t.Fatalf("argv = %q: ConnectTimeout must appear exactly once", argv)
			}
		})
	}
}
