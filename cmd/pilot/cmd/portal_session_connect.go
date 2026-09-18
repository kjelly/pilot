// portal_session_connect.go is the Gateway-side half of the Directory ->
// Gateway -> Target handoff (docs/tmp/now/spec.md §18): a one-shot,
// non-interactive Connect invoked as sshd's entire ForceCommand session,
// not a menu action inside a TUI loop. There is no TTY-menu context here
// — this process IS the user's whole SSH session, so failures are
// reported as a single stderr line + a non-zero process exit, never an
// interactive confirm prompt.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/kjelly/pilot/internal/sessionaudit"
)

// portalSessionExitError lets runPortalOneShotConnect propagate a specific
// process exit code (spec.md §18 point 6/7: "target session exit -> process
// exit") through cobra's normal error-printing path, matching the existing
// networkCheckExitError pattern (network_check.go) rather than calling
// os.Exit directly, so this stays testable as an ordinary function.
type portalSessionExitError struct {
	err  error
	code int
}

func (e *portalSessionExitError) Error() string { return e.err.Error() }
func (e *portalSessionExitError) ExitCode() int { return e.code }
func (e *portalSessionExitError) Unwrap() error { return e.err }

// runPortalOneShotConnect implements spec.md §18's exact sequence:
//  1. connect to the Gateway API (identity via its own SO_PEERCRED
//     resolution — the same client used by the interactive path, nothing
//     new needed here beyond calling it non-interactively);
//  2. POST /v1/connect/authorize with only {"target": fqdn} — a FRESH,
//     independent authorize (D1/D6): whatever Directory decided before
//     sending the user here is not trusted at all;
//  3. Allowed=false -> deny, non-zero exit, no SSH attempt;
//  4. Allowed=true -> the exact same controlled SSH launch the interactive
//     Connect action uses (buildConnectSSHCmd + the session-scoped
//     Kerberos credential flow) — no new SSH invocation shape;
//  5. target session exit -> this process's own exit, with the ssh
//     child's exit code propagated via portalSessionExitError.
//
// sessionID is accepted only for structured-log correlation (spec.md
// §17.2/§21, Phase 6: internal/sessionaudit.Emitter carries it into every
// event this function emits); it is never read by, or passed into, the
// authorize decision above.
//
// client/credentials/sshConfigPath/emitter are injected (mirroring
// connectToHost's own dependency-injection shape in portal_ssh.go) so
// tests can exercise this against a real fake-provider-backed
// gatewayapi.Server without a real Kerberos environment, a real target
// host, or a real syslog daemon.
func runPortalOneShotConnect(ctx context.Context, client *portalClient, credentials portalCredentialSession, emitter *sessionaudit.Emitter, sshConfigPath, sessionID, target string) error {
	identity, err := client.Identity(ctx)
	if err != nil {
		return fmt.Errorf("pilot-session: resolve identity: %w", err)
	}

	authz, err := client.ConnectAuthorize(ctx, target)
	if err != nil {
		emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindGatewayAuthorizeDenied, User: identity.Username, TargetFQDN: target, Result: "authorize call failed: " + err.Error()})
		return fmt.Errorf("pilot-session: connect authorize failed: %w", err)
	}
	if !authz.Allowed {
		emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindGatewayAuthorizeDenied, User: identity.Username, TargetFQDN: target})
		return fmt.Errorf("pilot-session: access denied for %s", target)
	}
	emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindGatewayAuthorizeAllowed, User: identity.Username, TargetFQDN: authz.Target, GatewayID: authz.GatewayID, GatewayScope: authz.GatewayScope})

	cache, err := credentials.Ensure(ctx, identity.Username)
	if err != nil {
		return fmt.Errorf("pilot-session: kerberos authentication failed: %w", err)
	}

	emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindTargetConnectStarted, User: identity.Username, TargetFQDN: authz.Target, GatewayID: authz.GatewayID, GatewayScope: authz.GatewayScope})
	runErr := sshLauncher(buildConnectSSHCmd(sshConfigPath, authz.Target, cache))
	if runErr == nil {
		emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindSessionEnded, User: identity.Username, TargetFQDN: authz.Target, GatewayID: authz.GatewayID, GatewayScope: authz.GatewayScope, Result: "ok"})
		return nil
	}

	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		code := exitErr.ExitCode()
		emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindSessionEnded, User: identity.Username, TargetFQDN: authz.Target, GatewayID: authz.GatewayID, GatewayScope: authz.GatewayScope, Result: "error", ExitCode: &code})
		return &portalSessionExitError{err: fmt.Errorf("pilot-session: ssh exited: %w", runErr), code: code}
	}
	emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindTargetConnectFailed, User: identity.Username, TargetFQDN: authz.Target, GatewayID: authz.GatewayID, GatewayScope: authz.GatewayScope, Result: runErr.Error()})
	return fmt.Errorf("pilot-session: ssh failed to start: %w", runErr)
}
