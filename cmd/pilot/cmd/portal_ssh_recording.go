// portal_ssh_recording.go is the two-phase ControlMaster SSH flow spec.md
// §24.1 requires whenever session recording is enabled
// (terminal_output/terminal_io): the target's own SSH authentication must
// never be captured, so authentication happens in an unrecorded Phase A
// before the Recorder (internal/sessionrecording) ever starts, and the
// recorded Phase B reuses that already-authenticated connection.
//
// The default "metadata" mode never touches this file — buildConnectSSHCmd
// in portal_ssh.go (a single, direct, non-recorded ssh invocation) stays
// exactly as it was before this phase existed. This file is additive.
package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/creack/pty"

	"github.com/kjelly/pilot/internal/sessionrecording"
)

// recordedConnectSession owns one recorded session's private ControlMaster
// socket directory (spec.md §24.1: "random pathname, user-private
// directory, mode 0700, session end 必須 cleanup").
type recordedConnectSession struct {
	dir         string
	controlPath string
}

// newRecordedConnectSession creates a fresh, private control-socket
// directory under runtimeBase (the same per-uid runtime base
// portalKerberosRuntimeBase already resolves — reused here rather than
// duplicating that fallback logic).
func newRecordedConnectSession() (*recordedConnectSession, error) {
	runtimeBase := portalKerberosRuntimeBase(os.Getuid())
	dir, err := os.MkdirTemp(runtimeBase, "pilot-recording-")
	if err != nil {
		return nil, fmt.Errorf("create session control directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("secure session control directory: %w", err)
	}
	suffix, err := randomHex(8)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("generate control socket name: %w", err)
	}
	return &recordedConnectSession{dir: dir, controlPath: filepath.Join(dir, "control-"+suffix)}, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// authenticate runs spec.md §24.1's Phase A: an unrecorded, non-TTY
// background SSH connection that does nothing but authenticate and
// establish the ControlMaster socket. RequestTTY=no here is an
// implementation-owned constant appended after -F <config> to override
// that config's own "RequestTTY force" (spec.md §24.1: "必須使用...覆蓋
// 它") — never a caller-supplied option, same fixed-argv discipline as
// buildConnectSSHCmd.
//
// Deliberately does NOT use cmd.CombinedOutput()/cmd.Output() — found
// live (a real hang, not a guess) that with `-fN`, ssh forks into the
// background AFTER authenticating and that backgrounded process inherits
// whatever pipe CombinedOutput set up for stdout/stderr; since the
// long-lived ControlMaster child never closes that inherited pipe (it
// isn't the same process CombinedOutput is waiting on, but it holds the
// write end open forever), CombinedOutput's internal read-until-EOF never
// sees EOF and blocks the whole one-shot connect indefinitely — every
// recorded-mode Connect hung forever at Phase A until this was found and
// fixed (see docs/evidence/pilot-access-directory/2026-09-18-phase7-pty-recorder.md).
// Redirecting to real *os.File temp files instead means the backgrounded
// child can hold those fds open forever harmlessly — cmd.Run only waits
// for the DIRECT child (the foreground ssh invocation, which exits
// promptly once it forks) to exit, never for the files to close.
func (s *recordedConnectSession) authenticate(sshConfigPath, target, credentialCache string) error {
	outFile, err := os.CreateTemp(s.dir, "auth-output-")
	if err != nil {
		return fmt.Errorf("create pre-auth output capture file: %w", err)
	}
	defer os.Remove(outFile.Name())
	defer outFile.Close()

	cmd := exec.Command(sshBinaryPath,
		"-F", sshConfigPath,
		"-M", "-S", s.controlPath,
		"-o", "RequestTTY=no",
		"-fN", target,
	)
	cmd.Stdout = outFile
	cmd.Stderr = outFile
	if credentialCache != "" {
		cmd.Env = replaceProcessEnv(os.Environ(), "KRB5CCNAME", credentialCache)
	}
	if err := cmd.Run(); err != nil {
		out, _ := os.ReadFile(outFile.Name())
		return fmt.Errorf("pre-auth ControlMaster failed: %w: %s", err, out)
	}
	return nil
}

// startRecorded runs spec.md §24.1's Phase B: the recorded interactive
// channel, reusing Phase A's already-authenticated ControlMaster
// connection (-S <path>, no fresh authentication attempted or possible
// here). Returns the child's pty master — what the Recorder wraps — and
// the *exec.Cmd for lifecycle/exit-code handling by the caller.
//
// The pty starts at size (per-host recording spec §18.3 step 6), so ssh's
// first window-size report matches the resize event the recorder writes
// as seq 1 instead of racing a later resize.
func (s *recordedConnectSession) startRecorded(sshConfigPath, target string, size sessionrecording.Winsize) (*os.File, *exec.Cmd, error) {
	cmd := exec.Command(sshBinaryPath, "-F", sshConfigPath, "-S", s.controlPath, "-tt", target)
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(size.Rows), Cols: uint16(size.Cols)})
	if err != nil {
		return nil, nil, fmt.Errorf("start recorded session: %w", err)
	}
	return ptmx, cmd, nil
}

// closeMaster runs spec.md §24.1's session-end step: `ssh -O exit` tears
// down the ControlMaster connection cleanly. Errors are non-fatal — the
// control socket directory removal below is what actually matters for
// cleanup, and a ControlMaster already gone (e.g. Phase B's own ssh exit
// already tore it down) is not a failure worth surfacing.
func (s *recordedConnectSession) closeMaster(sshConfigPath, target string) {
	cmd := exec.Command(sshBinaryPath, "-F", sshConfigPath, "-S", s.controlPath, "-O", "exit", target)
	_ = cmd.Run()
}

// cleanup removes the private control-socket directory. Always safe to
// call, including when authenticate/startRecorded never succeeded.
func (s *recordedConnectSession) cleanup() {
	_ = os.RemoveAll(s.dir)
}
