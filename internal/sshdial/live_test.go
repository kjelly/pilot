package sshdial

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// Live tests against a disposable FreeIPA server. They run only when
// PILOT_FREEIPA_LIVE_SSH is set:
//
//	PILOT_FREEIPA_LIVE_SSH       user@host
//	PILOT_FREEIPA_LIVE_SSH_KEY   identity file (optional)
//	PILOT_FREEIPA_LIVE_SSH_OPTS  Key=Value,… ssh options (optional)
//	PILOT_FREEIPA_LIVE_EXPECT    "forwarding-denied" when the server's sshd
//	                             was set to refuse forwarding for this run
//
// docs/superpowers/specs/2026-10-16-freeipa-go-reconcile-phase0-contract.md §5.

// LiveTarget builds the Target the live tests use, or skips the test.
func LiveTarget(t *testing.T) Target {
	t.Helper()
	dest := os.Getenv("PILOT_FREEIPA_LIVE_SSH")
	if dest == "" {
		t.Skip("PILOT_FREEIPA_LIVE_SSH is not set")
	}
	tgt := Target{Host: dest, IdentityFile: os.Getenv("PILOT_FREEIPA_LIVE_SSH_KEY"), Options: map[string]string{}}
	if user, host, ok := strings.Cut(dest, "@"); ok {
		tgt.User, tgt.Host = user, host
	}
	for _, kv := range strings.Split(os.Getenv("PILOT_FREEIPA_LIVE_SSH_OPTS"), ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			tgt.Options[k] = v
		}
	}
	return tgt
}

func TestLiveTunnelReachesFreeIPA(t *testing.T) {
	d := &Dialer{Target: LiveTarget(t)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// Something the server's httpd answers on a plain socket: an HTTP
	// request on the TLS port gets a 400 in clear text.
	_, _ = c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	got, err := io.ReadAll(c)
	if os.Getenv("PILOT_FREEIPA_LIVE_EXPECT") == "forwarding-denied" {
		if !errors.Is(err, ErrForwardingDenied) {
			t.Fatalf("read = %q, %v; want ErrForwardingDenied", got, err)
		}
		t.Logf("sshd refused the forwarding: %v", err)
		return
	}
	if err != nil || !strings.HasPrefix(string(got), "HTTP/1.1 400") {
		t.Fatalf("read %q, %v; want httpd's 400", got, err)
	}
	fqdn, err := d.FQDN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CA(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("tunnel to %s works; CA read", fqdn)
}

// A dropped holder releases the lock: sshd ends the session when the
// client's connection goes away.
func TestLiveLockIsExclusiveAndFreedWhenTheHolderDies(t *testing.T) {
	if os.Getenv("PILOT_FREEIPA_LIVE_EXPECT") != "" {
		t.Skip("not with a modified sshd")
	}
	d := &Dialer{Target: LiveTarget(t)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	first, err := d.AcquireLock(ctx, LockOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.AcquireLock(ctx, LockOptions{}); !errors.Is(err, ErrLockBusy) {
		t.Fatalf("second acquire = %v, want ErrLockBusy", err)
	}
	first.p.kill() // as if Pilot were SIGKILLed
	select {
	case <-first.Lost():
	case <-time.After(10 * time.Second):
		t.Fatal("Lost did not close after the holder died")
	}
	start := time.Now()
	second, err := d.AcquireLock(ctx, LockOptions{Wait: 60 * time.Second})
	if err != nil {
		t.Fatalf("acquire after the holder died: %v", err)
	}
	t.Logf("lock taken %v after the holder's ssh was killed", time.Since(start).Round(time.Millisecond))
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
	third, err := d.AcquireLock(ctx, LockOptions{})
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	_ = third.Release()
}
