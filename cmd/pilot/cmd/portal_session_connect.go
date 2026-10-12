// portal_session_connect.go is the connect core shared by the interactive
// Portal Connect action and the Directory -> Gateway -> Target one-shot
// handoff (per-host recording spec §18). Both paths re-authorize fresh and
// then take the plain or the recorded path strictly from the gateway's
// ConnectAuthorize response; neither reads hosts.yml, the environment, a
// CLI flag or SSH_ORIGINAL_COMMAND to decide whether a session records
// (§18.5).
//
// The one-shot path runs as sshd's entire ForceCommand session, so its
// failures are a single stderr line plus a non-zero process exit; the
// interactive path turns the same errors into a confirm prompt and returns
// to the Portal menu.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/kjelly/pilot/internal/gatewayapi"
	"github.com/kjelly/pilot/internal/ingesttoken"
	"github.com/kjelly/pilot/internal/sessionaudit"
	"github.com/kjelly/pilot/internal/sessionrecording"
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

// portalConnectStage says where a connect stopped, so the interactive Portal
// can pick its prompt.
type portalConnectStage int

const (
	portalStageAuthorizeCall portalConnectStage = iota // identity or authorize request failed
	portalStageDenied                                  // the gateway denied the target
	portalStageCredentials                             // Kerberos credentials could not be obtained
	portalStageRecording                               // recording could not start; nothing was connected
	portalStageSSH                                     // the target connection failed or ended with an error
)

// portalConnectError is a connect that ended before, or instead of, a clean
// target session. msg is the user-facing sentence.
type portalConnectError struct {
	stage portalConnectStage
	msg   string
	err   error
	// reason is the gateway's DenyReason for a recording deny.
	reason string
}

func (e *portalConnectError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("pilot-session: %s: %v", e.msg, e.err)
	}
	return "pilot-session: " + e.msg
}

func (e *portalConnectError) Unwrap() error { return e.err }

// portalDenyReasonMessage is the user-facing sentence for a recording deny
// reason (per-host recording spec §18.1); "" for an ordinary HBAC/scope deny.
func portalDenyReasonMessage(reason string) string {
	switch reason {
	case gatewayapi.DenyReasonRecordingPolicyUnavailable:
		return "Connection not started: this host's recording policy could not be verified."
	case gatewayapi.DenyReasonRecordingPolicyInvalid:
		return "Connection not started: this host's recording policy is misconfigured. Contact an administrator."
	case gatewayapi.DenyReasonRecordingBackend:
		return "Connection not started: session recording is required for this host but the recording service is not configured."
	case gatewayapi.DenyReasonRecordingSessionID:
		return "Connection not started: internal session id error."
	case "":
		return ""
	default:
		return "Connection not started: " + reason + "."
	}
}

// portalRecordingNotice is the pre-connect notice for a recorded session
// (per-host recording spec §24.3); "" for metadata.
func portalRecordingNotice(mode, sessionID string) string {
	switch mode {
	case sessionrecording.ModeTerminalOutput:
		return "This SSH session is recorded by Pilot (terminal output). Session ID: " + sessionID
	case sessionrecording.ModeTerminalIO:
		return "This SSH session is recorded by Pilot (terminal output and input; typed input is stored as redacted byte counts). Session ID: " + sessionID
	default:
		return ""
	}
}

// portalSessionDeps bundles the injectable dependencies shared by both
// connect paths (per-host recording spec §18.1).
type portalSessionDeps struct {
	Client        *portalClient
	Credentials   portalCredentialSession
	Emitter       *sessionaudit.Emitter
	SSHConfigPath string
	// Terminal is the outer terminal the recorded path puts in raw mode,
	// sizes the child from and watches for SIGWINCH. nil records at 80x24
	// without raw mode.
	Terminal *os.File
	// Stdin is the recorded path's outer input. On the interactive path it
	// is a cancelreader, canceled once the session ends so no goroutine is
	// left reading the terminal.
	Stdin io.Reader
	// Stdout is the recorded path's outer output.
	Stdout io.Writer
	// Notice receives the pre-connect recording notice (stderr).
	Notice io.Writer
}

// recordingConfig is the recording policy one ConnectAuthorize response
// grants (per-host recording spec §15). A metadata or empty Mode never
// constructs a recorder.
type recordingConfig struct {
	Mode          string
	PolicySource  string
	FailurePolicy string
	QueueEvents   int
	FlushInterval time.Duration
	FailureGrace  time.Duration

	SessionStoreURL         string
	SessionStoreCAFile      string
	SessionStoreIngestToken string
}

func recordingConfigFrom(authz gatewayapi.ConnectAuthorizeResponse) recordingConfig {
	return recordingConfig{
		Mode:                    authz.RecordingMode,
		PolicySource:            authz.RecordingPolicySource,
		FailurePolicy:           authz.RecordingFailurePolicy,
		QueueEvents:             authz.RecordingQueueEvents,
		FlushInterval:           time.Duration(authz.RecordingFlushIntervalMS) * time.Millisecond,
		FailureGrace:            time.Duration(authz.RecordingFailureGraceMS) * time.Millisecond,
		SessionStoreURL:         authz.RecordingSessionStoreURL,
		SessionStoreCAFile:      authz.RecordingSessionStoreCAFile,
		SessionStoreIngestToken: authz.RecordingSessionStoreIngestToken,
	}
}

func (c recordingConfig) enabled() bool {
	return c.Mode == sessionrecording.ModeTerminalOutput || c.Mode == sessionrecording.ModeTerminalIO
}

// portalSessionAudit emits target-session audit events carrying the fields
// per-host recording spec §22 requires on every one of them.
type portalSessionAudit struct {
	emitter *sessionaudit.Emitter
	base    sessionaudit.SessionAuditEvent
}

func (a *portalSessionAudit) emit(kind, result string, exitCode *int) {
	ev := a.base
	ev.Kind, ev.Result, ev.ExitCode = kind, result, exitCode
	a.emitter.Emit(ev)
}

// recordedTransport is the recorded path's two-phase ControlMaster SSH flow
// (portal_ssh_recording.go).
type recordedTransport interface {
	authenticate(sshConfigPath, target, credentialCache string) error
	startRecorded(sshConfigPath, target string, size sessionrecording.Winsize) (*os.File, *exec.Cmd, error)
	closeMaster(sshConfigPath, target string)
	cleanup()
}

// newRecordedTransport builds one recorded session's transport. Overridden
// by tests so they can drive the recorded path without a real target.
var newRecordedTransport = func() (recordedTransport, error) { return newRecordedConnectSession() }

// runPortalOneShotConnect is the Directory handoff one-shot connect
// (spec.md §18): the process is the user's whole SSH session, so it uses
// the real process stdio and ends with the target session.
func runPortalOneShotConnect(ctx context.Context, client *portalClient, credentials portalCredentialSession, emitter *sessionaudit.Emitter, sshConfigPath, sessionID, target string) error {
	return runPortalTargetSession(ctx, portalSessionDeps{
		Client: client, Credentials: credentials, Emitter: emitter, SSHConfigPath: sshConfigPath,
		Terminal: os.Stdin, Stdin: os.Stdin, Stdout: os.Stdout, Notice: os.Stderr,
	}, sessionID, target)
}

// runPortalTargetSession runs one fully authorized target session for both
// the interactive Portal Connect action and the Directory handoff
// one-shot path (per-host recording spec §18). It re-authorizes fresh,
// then takes the plain or recorded path strictly from the authorize response.
//
// The authorize happens before credentials.Ensure, so a denied target never
// prompts for a Kerberos password (AG38). sessionID never influences the
// authorize decision; the gateway only binds it into a recorded session's
// ingest token (AG37).
func runPortalTargetSession(ctx context.Context, deps portalSessionDeps, sessionID, target string) error {
	identity, err := deps.Client.Identity(ctx)
	if err != nil {
		return &portalConnectError{stage: portalStageAuthorizeCall, msg: "resolve identity", err: err}
	}
	audit := &portalSessionAudit{emitter: deps.Emitter, base: sessionaudit.SessionAuditEvent{
		SessionID: sessionID, User: identity.Username, TargetFQDN: target,
	}}

	authz, err := deps.Client.ConnectAuthorize(ctx, target, sessionID)
	if err != nil {
		audit.emit(sessionaudit.KindGatewayAuthorizeDenied, "authorize call failed", nil)
		return &portalConnectError{stage: portalStageAuthorizeCall, msg: "connect authorize failed", err: err}
	}
	audit.base.TargetFQDN = authz.Target
	audit.base.GatewayID, audit.base.GatewayScope = authz.GatewayID, authz.GatewayScope
	if !authz.Allowed {
		audit.emit(sessionaudit.KindGatewayAuthorizeDenied, authz.DenyReason, nil)
		if msg := portalDenyReasonMessage(authz.DenyReason); msg != "" {
			return &portalConnectError{stage: portalStageDenied, msg: msg, reason: authz.DenyReason}
		}
		return &portalConnectError{stage: portalStageDenied, msg: "access denied for " + authz.Target}
	}

	recording := recordingConfigFrom(authz)
	audit.base.RecordingMode, audit.base.RecordingPolicySource = recording.Mode, recording.PolicySource
	audit.emit(sessionaudit.KindGatewayAuthorizeAllowed, "", nil)

	cache, err := deps.Credentials.Ensure(ctx, identity.Username)
	if err != nil {
		return &portalConnectError{stage: portalStageCredentials, msg: "kerberos authentication failed", err: err}
	}

	if !recording.enabled() {
		audit.emit(sessionaudit.KindTargetConnectStarted, "", nil)
		return runPortalTargetSessionPlain(deps.SSHConfigPath, authz.Target, cache, audit)
	}
	return runPortalTargetSessionRecorded(ctx, deps, sessionID, authz.Target, cache, recording, audit)
}

// runPortalTargetSessionPlain is the metadata path: the same direct
// buildConnectSSHCmd/sshLauncher call both connect paths used before
// recording existed (per-host recording spec §18.2).
func runPortalTargetSessionPlain(sshConfigPath, target, cache string, audit *portalSessionAudit) error {
	runErr := sshLauncher(buildConnectSSHCmd(sshConfigPath, target, cache))
	return finishTargetProcess(runErr, audit)
}

// finishTargetProcess reports how the target ssh process ended.
func finishTargetProcess(runErr error, audit *portalSessionAudit) error {
	if runErr == nil {
		audit.emit(sessionaudit.KindSessionEnded, "ok", nil)
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		code := exitErr.ExitCode()
		audit.emit(sessionaudit.KindSessionEnded, "error", &code)
		return &portalSessionExitError{err: fmt.Errorf("pilot-session: ssh exited: %w", runErr), code: code}
	}
	audit.emit(sessionaudit.KindTargetConnectFailed, runErr.Error(), nil)
	return &portalConnectError{stage: portalStageSSH, msg: "ssh failed", err: runErr}
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

// portalTerminalSize is the recorded child's initial size: the outer
// terminal's, or 80x24 when there is none.
func portalTerminalSize(f *os.File) sessionrecording.Winsize {
	if f != nil && term.IsTerminal(int(f.Fd())) {
		if cols, rows, err := term.GetSize(int(f.Fd())); err == nil && rows > 0 && cols > 0 {
			return sessionrecording.Winsize{Rows: rows, Cols: cols}
		}
	}
	return sessionrecording.Winsize{Rows: 24, Cols: 80}
}

// releasePortalInput cancels a cancelable outer reader and waits (up to 1s)
// for the recorder's input relay to exit, so the next TUI prompt is the only
// reader of the terminal (per-host recording spec §18.1).
func releasePortalInput(in io.Reader, rec *sessionrecording.Recorder) {
	c, ok := in.(interface{ Cancel() bool })
	if !ok {
		return
	}
	c.Cancel()
	select {
	case <-rec.InputDone():
	case <-time.After(time.Second):
	}
}

// runPortalTargetSessionRecorded is the recorded path (per-host recording
// spec §18.3): notice, store start, then the unrecorded pre-auth
// ControlMaster (Phase A), then the recorded interactive channel (Phase B)
// wrapped by the Recorder. Nothing connects to the target until the store
// has accepted the session, and once it has, every exit path finishes it.
func runPortalTargetSessionRecorded(ctx context.Context, deps portalSessionDeps, sessionID, target, cache string, recording recordingConfig, audit *portalSessionAudit) (retErr error) {
	if recording.SessionStoreURL == "" || recording.SessionStoreIngestToken == "" {
		audit.emit(sessionaudit.KindRecordingFailed, "authorize response carries no session-store coordinates", nil)
		return &portalConnectError{stage: portalStageRecording, msg: portalDenyReasonMessage(gatewayapi.DenyReasonRecordingBackend)}
	}

	if deps.Notice != nil {
		_, _ = fmt.Fprintln(deps.Notice, portalRecordingNotice(recording.Mode, sessionID))
	}

	sink, err := sessionrecording.NewHTTPSink(ctx, sessionrecording.HTTPSinkConfig{
		BaseURL: recording.SessionStoreURL, IngestToken: recording.SessionStoreIngestToken,
		CAFile: recording.SessionStoreCAFile, SessionID: sessionID, User: audit.base.User,
		GatewayID: audit.base.GatewayID, Scope: audit.base.GatewayScope, Target: target, RecordingMode: recording.Mode,
	})
	if err != nil {
		audit.emit(sessionaudit.KindRecordingFailed, "session-store start: "+err.Error(), nil)
		msg := "Connection not started: session recording could not start."
		if strings.Contains(err.Error(), ingesttoken.ReasonStartWindowClosed) {
			msg += " The recording authorization expired; connect again."
		}
		return &portalConnectError{stage: portalStageRecording, msg: msg, err: err}
	}

	// The store now holds a started session. Any exit that the recorder
	// itself does not finish must report an incomplete finish.
	var rec *sessionrecording.Recorder
	recorderFinished := false
	finishIncomplete := func(reason string) {
		if recorderFinished {
			return
		}
		recorderFinished = true
		var lastSeq uint64
		if rec != nil {
			lastSeq = rec.LastSeq()
		}
		fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := sink.Finish(fctx, sessionrecording.FinishInfo{LastSeq: lastSeq, Reason: reason}); err != nil {
			audit.emit(sessionaudit.KindRecordingFailed, "finish: "+err.Error(), nil)
		}
	}
	defer func() {
		if p := recover(); p != nil {
			finishIncomplete("internal_error")
			audit.emit(sessionaudit.KindRecordingFailed, "internal error", nil)
			retErr = &portalConnectError{stage: portalStageRecording, msg: "internal error during the recorded session", err: fmt.Errorf("%v", p)}
		}
	}()

	audit.emit(sessionaudit.KindTargetConnectStarted, "", nil)
	sess, err := newRecordedTransport()
	if err != nil {
		finishIncomplete("internal_error")
		audit.emit(sessionaudit.KindTargetConnectFailed, err.Error(), nil)
		return &portalConnectError{stage: portalStageSSH, msg: "prepare the recorded connection", err: err}
	}
	defer sess.cleanup()

	if err := sess.authenticate(deps.SSHConfigPath, target, cache); err != nil {
		finishIncomplete("target_connect_failed")
		audit.emit(sessionaudit.KindTargetConnectFailed, err.Error(), nil)
		return &portalConnectError{stage: portalStageSSH, msg: "target connection failed", err: err}
	}
	defer sess.closeMaster(deps.SSHConfigPath, target)

	size := portalTerminalSize(deps.Terminal)
	ptmx, cmd, err := sess.startRecorded(deps.SSHConfigPath, target, size)
	if err != nil {
		finishIncomplete("session_start_failed")
		audit.emit(sessionaudit.KindTargetConnectFailed, err.Error(), nil)
		return &portalConnectError{stage: portalStageSSH, msg: "recorded session failed to start", err: err}
	}
	defer ptmx.Close()

	rec = sessionrecording.New(sessionrecording.Options{
		Mode: recording.Mode, SessionID: sessionID, FailurePolicy: recording.FailurePolicy,
		QueueEvents: recording.QueueEvents, FlushInterval: recording.FlushInterval, FailureGrace: recording.FailureGrace,
		InitialSize: size, Terminal: deps.Terminal,
		Identity: sessionrecording.AuditIdentity{
			User: audit.base.User, TargetFQDN: target, GatewayID: audit.base.GatewayID, GatewayScope: audit.base.GatewayScope,
			RecordingPolicySource: recording.PolicySource,
		},
		// End the target session as soon as recording fails closed, not
		// after Run's drain and finish (up to FailureGrace plus the finish
		// timeout later).
		OnFailClosed: func() { _ = cmd.Process.Kill() },
	}, sink, deps.Emitter)
	audit.emit(sessionaudit.KindRecordingStarted, "", nil)
	runErr := rec.Run(ctx, ptmx, deps.Stdin, deps.Stdout)
	recorderFinished = true
	releasePortalInput(deps.Stdin, rec)

	if errors.Is(runErr, sessionrecording.ErrRecordingFailedClosed) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		audit.emit(sessionaudit.KindSessionEnded, "recording failed closed", nil)
		return &portalConnectError{stage: portalStageSSH, msg: "session ended: recording could not be saved", err: runErr}
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
	return finishTargetProcess(waitWithTimeout(cmd, 5*time.Second), audit)
}
