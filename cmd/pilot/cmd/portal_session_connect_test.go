package cmd

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/gatewayapi"
	"github.com/kjelly/pilot/internal/sessionaudit"
)

// testEmitter builds a sessionaudit.Emitter for tests. NewEmitter is
// fail-soft by design (see its doc comment) — it never errors even when
// the test sandbox has no reachable local syslog, falling back to
// slog.Default() instead, so it's always safe to use here.
func testEmitter(t *testing.T) *sessionaudit.Emitter {
	t.Helper()
	e, err := sessionaudit.NewEmitter("pilot-access-gateway-test")
	if err != nil {
		t.Fatalf("sessionaudit.NewEmitter: %v", err)
	}
	return e
}

// startFakeGatewayWithProvider serves a gateway backed by provider, so a
// test controls each host's FreeIPA recording policy.
func startFakeGatewayWithProvider(t *testing.T, provider *fakeGatewayProvider, policy gatewayapi.RecordingPolicy) *portalClient {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "gw.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	gw := accessportal.GatewayConfig{ID: "gpu-01", Scope: "gpu", TargetHostgroup: "pilot-target-gpu"}
	resolver := accessportal.NewResolver(provider, gw)
	srv := gatewayapi.NewServer(gw, provider, resolver, nil)
	srv.RecordingPolicy = policy
	go srv.Serve(ln)                                         //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown(context.Background()) }) //nolint:errcheck

	return newPortalClient(sockPath)
}

// TestRunPortalOneShotConnect_Allowed proves a fresh, allowed authorize
// launches ssh with exactly the fixed argv spec.md §31 requires — the same
// invocation shape the interactive Connect path uses, just driven
// non-interactively — against a real fake-provider-backed
// internal/gatewayapi.Server (Phase 3's already-proven wire protocol),
// never a mock of the gateway itself.
func TestRunPortalOneShotConnect_Allowed(t *testing.T) {
	username := currentOSUsername(t)
	client := startFakeGateway(t, username)
	credentials := &fakePortalCredentialSession{cache: "FILE:/run/user/1000/pilot-test/krb5cc"}
	var launched *exec.Cmd
	withSSHLauncher(t, func(cmd *exec.Cmd) error {
		launched = cmd
		return nil
	})

	if err := runPortalOneShotConnect(context.Background(), client, credentials, testEmitter(t), "/etc/pilot/ssh_config", "0d33c638-83fa-4d77-9811-a97a7a7af1d5", "gpu-a.example.com"); err != nil {
		t.Fatalf("runPortalOneShotConnect: %v", err)
	}
	if launched == nil {
		t.Fatalf("expected sshLauncher to be invoked")
	}
	wantArgs := []string{sshBinaryPath, "-F", "/etc/pilot/ssh_config", "gpu-a.example.com"}
	if strings.Join(launched.Args, " ") != strings.Join(wantArgs, " ") {
		t.Fatalf("Args = %v, want %v", launched.Args, wantArgs)
	}
	if len(credentials.users) != 1 || credentials.users[0] != username {
		t.Fatalf("credential users = %v, want [%s]", credentials.users, username)
	}
}

// TestRunPortalOneShotConnect_Denied proves a target outside the gateway's
// own scope is denied by a FRESH authorize call — never ssh-launched, and
// credentials are never even requested (spec.md D1/D6: this one-shot path
// must not trust whatever Directory decided before sending the user here).
func TestRunPortalOneShotConnect_Denied(t *testing.T) {
	username := currentOSUsername(t)
	client := startFakeGateway(t, username)
	credentials := &fakePortalCredentialSession{cache: "FILE:/should-not-be-used"}
	launched := false
	withSSHLauncher(t, func(cmd *exec.Cmd) error {
		launched = true
		return nil
	})

	err := runPortalOneShotConnect(context.Background(), client, credentials, testEmitter(t), "/etc/pilot/ssh_config", "0d33c638-83fa-4d77-9811-a97a7a7af1d5", "not-in-scope.example.com")
	if err == nil {
		t.Fatalf("expected an error for a denied target")
	}
	if launched {
		t.Fatalf("ssh must not be launched for a denied target")
	}
	if len(credentials.users) != 0 {
		t.Fatalf("credentials must not be requested before authorization, got users %v", credentials.users)
	}
}

// TestRunPortalOneShotConnect_CredentialFailure proves a Kerberos
// credential failure denies the connect without ever invoking ssh.
func TestRunPortalOneShotConnect_CredentialFailure(t *testing.T) {
	username := currentOSUsername(t)
	client := startFakeGateway(t, username)
	credentials := &fakePortalCredentialSession{err: errors.New("kerberos test failure")}
	launched := false
	withSSHLauncher(t, func(cmd *exec.Cmd) error {
		launched = true
		return nil
	})

	if err := runPortalOneShotConnect(context.Background(), client, credentials, testEmitter(t), "/etc/pilot/ssh_config", "0d33c638-83fa-4d77-9811-a97a7a7af1d5", "gpu-a.example.com"); err == nil {
		t.Fatalf("expected an error when the credential session fails")
	}
	if launched {
		t.Fatalf("ssh must not be launched when Ensure fails")
	}
}

// TestRunPortalOneShotConnect_PropagatesSSHExitCode proves spec.md §18
// point 6/7 ("target session exit -> process exit"): a real nonzero ssh
// exit code (via a real *exec.ExitError, not a hand-built error string)
// comes back out through portalSessionExitError.ExitCode() unchanged.
func TestRunPortalOneShotConnect_PropagatesSSHExitCode(t *testing.T) {
	username := currentOSUsername(t)
	client := startFakeGateway(t, username)
	credentials := &fakePortalCredentialSession{cache: "FILE:/run/user/1000/pilot-test/krb5cc"}
	withSSHLauncher(t, func(cmd *exec.Cmd) error {
		return exec.Command("sh", "-c", "exit 7").Run()
	})

	err := runPortalOneShotConnect(context.Background(), client, credentials, testEmitter(t), "/etc/pilot/ssh_config", "0d33c638-83fa-4d77-9811-a97a7a7af1d5", "gpu-a.example.com")
	if err == nil {
		t.Fatalf("expected an error for a nonzero ssh exit")
	}
	var withCode ExitCoder
	if !errors.As(err, &withCode) {
		t.Fatalf("expected the error to implement ExitCoder, got %T: %v", err, err)
	}
	if withCode.ExitCode() != 7 {
		t.Fatalf("ExitCode() = %d, want 7", withCode.ExitCode())
	}
}
