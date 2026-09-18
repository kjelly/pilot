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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/kjelly/pilot/internal/sessionaudit"
	"github.com/kjelly/pilot/internal/sessionrecording"
)

// recordingStdin/recordingStdout are the recorded session's outer
// terminal (spec.md §25.1) — the real process stdio by default,
// overridable in tests so they never need a real controlling terminal.
var (
	recordingStdin  io.Reader = os.Stdin
	recordingStdout io.Writer = os.Stdout
)

// defaultRecordingPath derives one session's recording file path under
// this process's own per-uid runtime base (the same
// portalKerberosRuntimeBase(os.Getuid()) newRecordedConnectSession
// already uses for its private control-socket directory, see
// portal_ssh_recording.go) — a bounded, transient runtime location (D9:
// "bounded transient buffers / runtime temp files", never durable local
// state) for Phase 7's plain FileSink, a deliberate stopgap until Phase
// 8's real pilot-session-store sink exists (spec.md §35).
//
// Deliberately NOT a shared location like /run/pilot/ (found live: that
// directory is root-owned mode 0755 for the gateway daemon's own socket,
// so the CONNECTING USER's own one-shot connect process — running as
// them, not as the gateway service account — cannot create anything
// under it; every recording attempt failed closed with "no such file or
// directory" until this was found and fixed). The per-uid runtime base is
// already correctly permissioned for exactly this "this user's own
// process writes its own private runtime file" use, and every file
// created under it is private (0700 dir, see defaultRecordingPath below).
func defaultRecordingPath(sessionID string) string {
	dir := filepath.Join(portalKerberosRuntimeBase(os.Getuid()), "pilot-session-recordings")
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, sessionID+".ndjson")
}

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

// recordingConfig is the (optional) session-recording policy for one
// one-shot connect (spec.md §23/§27). The zero value (Mode == "", treated
// identically to sessionrecording.ModeMetadata) is the unconditional
// default: runPortalOneShotConnect's behavior with a zero-value
// recordingConfig is byte-for-byte the same direct
// buildConnectSSHCmd/sshLauncher call this file used before recording
// existed — recording is additive, opt-in machinery, never a default risk
// (D8).
type recordingConfig struct {
	Mode          string
	FailurePolicy string
	QueueEvents   int
	FlushInterval time.Duration
	// LocalPath is where a FileSink writes when Mode is terminal_output/
	// terminal_io — a deliberately plain, unencrypted, transient stopgap
	// (D9: "bounded transient buffers / runtime temp files", never durable
	// local state) until Phase 8's real pilot-session-store sink exists.
	// Empty means "recording enabled but nowhere to write it", which is a
	// misconfiguration this function fails closed on rather than silently
	// dropping every event.
	LocalPath string
}

func (c recordingConfig) enabled() bool {
	return c.Mode == sessionrecording.ModeTerminalOutput || c.Mode == sessionrecording.ModeTerminalIO
}

// runPortalOneShotConnect implements spec.md §18's exact sequence:
//  1. connect to the Gateway API (identity via its own SO_PEERCRED
//     resolution — the same client used by the interactive path, nothing
//     new needed here beyond calling it non-interactively);
//  2. POST /v1/connect/authorize with only {"target": fqdn} — a FRESH,
//     independent authorize (D1/D6): whatever Directory decided before
//     sending the user here is not trusted at all;
//  3. Allowed=false -> deny, non-zero exit, no SSH attempt;
//  4. Allowed=true -> either the exact same controlled SSH launch the
//     interactive Connect action uses (recording.enabled() == false, the
//     unconditional default) or, when session recording is enabled, the
//     two-phase ControlMaster flow (portal_ssh_recording.go) + an
//     internal/sessionrecording.Recorder wrapping the recorded phase
//     (spec.md §24/§25) — a real behavior fork, not a recorder-with-a-
//     no-op-mode;
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
//
// Recording policy is deliberately NOT a parameter here: it comes back on
// the SAME fresh ConnectAuthorize response as the allow/deny decision
// (gatewayapi.Server.RecordingPolicy, set from this gateway's own
// /etc/pilot/access-gateway.yaml) — the Gateway daemon is the single
// source of truth for whether/how this session records, exactly like it
// already is for the authorize decision itself. A caller/test that never
// sets a fake gateway's RecordingPolicy gets the zero value, which
// authz.RecordingMode below then reports as "" — recordingConfig.enabled()
// treats that identically to "metadata", so every pre-Phase-7 test needs
// no change at all.
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

	recording := recordingConfig{
		Mode:          authz.RecordingMode,
		FailurePolicy: authz.RecordingFailurePolicy,
		QueueEvents:   authz.RecordingQueueEvents,
		FlushInterval: time.Duration(authz.RecordingFlushIntervalMS) * time.Millisecond,
	}
	if recording.enabled() {
		recording.LocalPath = defaultRecordingPath(sessionID)
	}

	cache, err := credentials.Ensure(ctx, identity.Username)
	if err != nil {
		return fmt.Errorf("pilot-session: kerberos authentication failed: %w", err)
	}

	emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindTargetConnectStarted, User: identity.Username, TargetFQDN: authz.Target, GatewayID: authz.GatewayID, GatewayScope: authz.GatewayScope})

	if !recording.enabled() {
		return runPortalOneShotConnectPlain(sshConfigPath, sessionID, authz.Target, cache, identity.Username, authz.GatewayID, authz.GatewayScope, emitter)
	}
	return runPortalOneShotConnectRecorded(ctx, sshConfigPath, sessionID, authz.Target, cache, identity.Username, authz.GatewayID, authz.GatewayScope, recording, emitter)
}

// runPortalOneShotConnectPlain is the unmodified pre-Phase-7 direct SSH
// path — byte-for-byte the same buildConnectSSHCmd/sshLauncher call and
// exit-handling this file always used before recording existed.
func runPortalOneShotConnectPlain(sshConfigPath, sessionID, target, cache, username, gatewayID, gatewayScope string, emitter *sessionaudit.Emitter) error {
	runErr := sshLauncher(buildConnectSSHCmd(sshConfigPath, target, cache))
	if runErr == nil {
		emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindSessionEnded, User: username, TargetFQDN: target, GatewayID: gatewayID, GatewayScope: gatewayScope, Result: "ok"})
		return nil
	}

	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		code := exitErr.ExitCode()
		emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindSessionEnded, User: username, TargetFQDN: target, GatewayID: gatewayID, GatewayScope: gatewayScope, Result: "error", ExitCode: &code})
		return &portalSessionExitError{err: fmt.Errorf("pilot-session: ssh exited: %w", runErr), code: code}
	}
	emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindTargetConnectFailed, User: username, TargetFQDN: target, GatewayID: gatewayID, GatewayScope: gatewayScope, Result: runErr.Error()})
	return fmt.Errorf("pilot-session: ssh failed to start: %w", runErr)
}

// waitWithTimeout waits for cmd to exit, force-killing it if it hasn't
// within timeout. Used only on the recorded path (see the comment at its
// call site for why the plain path doesn't need this).
func waitWithTimeout(cmd *exec.Cmd, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return <-done
	}
}

// runPortalOneShotConnectRecorded is spec.md §24's two-phase flow: an
// unrecorded pre-auth ControlMaster (Phase A), then a recorded
// interactive channel (Phase B) wrapped by internal/sessionrecording's
// Recorder, so the target's own SSH authentication is never captured.
func runPortalOneShotConnectRecorded(ctx context.Context, sshConfigPath, sessionID, target, cache, username, gatewayID, gatewayScope string, recording recordingConfig, emitter *sessionaudit.Emitter) error {
	if recording.LocalPath == "" {
		emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindRecordingFailed, User: username, TargetFQDN: target, Result: "recording enabled but no local sink path configured", RecordingMode: recording.Mode})
		return fmt.Errorf("pilot-session: session recording is enabled (%s) but no sink is configured", recording.Mode)
	}

	sess, err := newRecordedConnectSession()
	if err != nil {
		return fmt.Errorf("pilot-session: %w", err)
	}
	defer sess.cleanup()

	if err := sess.authenticate(sshConfigPath, target, cache); err != nil {
		return fmt.Errorf("pilot-session: %w", err)
	}
	defer sess.closeMaster(sshConfigPath, target)

	ptmx, cmd, err := sess.startRecorded(sshConfigPath, target)
	if err != nil {
		return fmt.Errorf("pilot-session: %w", err)
	}
	defer ptmx.Close()

	sink, err := sessionrecording.NewFileSink(recording.LocalPath)
	if err != nil {
		emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindRecordingFailed, User: username, TargetFQDN: target, Result: err.Error(), RecordingMode: recording.Mode})
		return fmt.Errorf("pilot-session: %w", err)
	}

	emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindRecordingStarted, User: username, TargetFQDN: target, GatewayID: gatewayID, GatewayScope: gatewayScope, RecordingMode: recording.Mode})

	rec := sessionrecording.New(recording.Mode, sessionID, sink, emitter, recording.FailurePolicy, recording.QueueEvents, recording.FlushInterval)
	runErr := rec.Run(ctx, ptmx, recordingStdin, recordingStdout)

	if errors.Is(runErr, sessionrecording.ErrRecordingFailedClosed) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindSessionEnded, User: username, TargetFQDN: target, GatewayID: gatewayID, GatewayScope: gatewayScope, Result: "recording failed closed"})
		return fmt.Errorf("pilot-session: %w", runErr)
	}

	// Run() returning does not by itself guarantee the child has (or ever
	// will) exit: unlike the plain path's direct stdio passthrough (where
	// the child shares this process's own controlling terminal and a
	// hangup cascades to it automatically), the recorded path's child
	// talks to a pty THIS process allocated — an abrupt outer disconnect
	// (relay's outerIn side hits EOF/error) ends Run without necessarily
	// signaling the child at all. Wait with a bound, then force-kill
	// rather than risk this process hanging forever on a child that will
	// never exit on its own.
	waitErr := waitWithTimeout(cmd, 5*time.Second)
	if waitErr == nil {
		emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindSessionEnded, User: username, TargetFQDN: target, GatewayID: gatewayID, GatewayScope: gatewayScope, Result: "ok"})
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		code := exitErr.ExitCode()
		emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindSessionEnded, User: username, TargetFQDN: target, GatewayID: gatewayID, GatewayScope: gatewayScope, Result: "error", ExitCode: &code})
		return &portalSessionExitError{err: fmt.Errorf("pilot-session: ssh exited: %w", waitErr), code: code}
	}
	emitter.Emit(sessionaudit.SessionAuditEvent{SessionID: sessionID, Kind: sessionaudit.KindTargetConnectFailed, User: username, TargetFQDN: target, GatewayID: gatewayID, GatewayScope: gatewayScope, Result: waitErr.Error()})
	return fmt.Errorf("pilot-session: ssh failed: %w", waitErr)
}
