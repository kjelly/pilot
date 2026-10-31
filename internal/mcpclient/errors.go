package mcpclient

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kjelly/pilot/internal/mcpwire"
)

// pilot-mcp error codes (spec §11).
const (
	CodeProfileInvalid    = "PROFILE_INVALID"
	CodeGitAuthRequired   = "GIT_AUTH_REQUIRED"
	CodeGitRefNotFound    = "GIT_REF_NOT_FOUND"
	CodeGitFailed         = "GIT_FAILED"
	CodeSnapshotInvalid   = "SNAPSHOT_INVALID"
	CodeSnapshotTooLarge  = "SNAPSHOT_TOO_LARGE"
	CodeSSHFailed         = "SSH_FAILED"
	CodeRemoteRejected    = "REMOTE_REJECTED"
	CodeRemoteRuntime     = "REMOTE_RUNTIME"
	CodeDockerFailed      = "DOCKER_FAILED"
	CodeChangesetConflict = "CHANGESET_CONFLICT"
	CodeChangesetInvalid  = "CHANGESET_INVALID"
)

// Error is a pilot-mcp failure: a code, a one-line message and, when the
// deploy node reported it, the remote code.
type Error struct {
	Code       string
	RemoteCode string
	Msg        string
}

func (e *Error) Error() string {
	if e.RemoteCode != "" {
		return fmt.Sprintf("pilot-mcp: %s: %s: %s", e.Code, e.RemoteCode, e.Msg)
	}
	return fmt.Sprintf("pilot-mcp: %s: %s", e.Code, e.Msg)
}

// ExitCode is the process exit status for the error's code.
func (e *Error) ExitCode() int {
	switch e.Code {
	case CodeProfileInvalid:
		return 2
	case CodeGitAuthRequired, CodeGitRefNotFound, CodeGitFailed:
		return 3
	case CodeSnapshotInvalid, CodeSnapshotTooLarge:
		return 4
	case CodeSSHFailed:
		return 5
	case CodeRemoteRejected:
		return 6
	case CodeChangesetConflict, CodeChangesetInvalid:
		return 8
	default:
		return 7
	}
}

// ExitCodeOf maps any error to an exit status; untyped errors are 7.
func ExitCodeOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.ExitCode()
	}
	return 7
}

// remoteFailure interprets a non-zero exit of the ssh process (spec §11):
// 255 is ssh itself; otherwise the remote's code line wins over the exit
// status; without one, docker's own statuses get a hint.
func remoteFailure(exit int, stderr string) *Error {
	if exit == 255 {
		return &Error{Code: CodeSSHFailed, Msg: "ssh failed (connection, host key or authentication): " + lastLine(stderr)}
	}
	if code, msg, ok := mcpwire.ParseErrorLine(stderr); ok {
		switch code {
		case mcpwire.CodeChangesetInvalid:
			return &Error{Code: CodeChangesetInvalid, RemoteCode: code, Msg: msg}
		case mcpwire.CodeRuntimeError:
			return &Error{Code: CodeRemoteRuntime, RemoteCode: code, Msg: msg}
		default:
			return &Error{Code: CodeRemoteRejected, RemoteCode: code, Msg: msg}
		}
	}
	switch exit {
	case 125:
		return &Error{Code: CodeDockerFailed, Msg: "docker could not start the container (is the image on the deploy node?): " + lastLine(stderr)}
	case 126, 127:
		return &Error{Code: CodeDockerFailed, Msg: "docker was not found or not permitted on the deploy node: " + lastLine(stderr)}
	}
	return &Error{Code: CodeRemoteRuntime, Msg: fmt.Sprintf("remote exited with status %d (the image may be too old for pilot mcp remote; run pilot-mcp doctor): %s", exit, lastLine(stderr))}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\r\n"), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
