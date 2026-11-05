package mcpwire

import (
	"fmt"
	"regexp"
	"strings"
)

// Error codes pilot mcp remote reports.
const (
	CodeCommandInvalid        = "COMMAND_INVALID"
	CodeProtocolUnsupported   = "PROTOCOL_UNSUPPORTED"
	CodeSnapshotInvalid       = "SNAPSHOT_INVALID"
	CodeSnapshotTooLarge      = "SNAPSHOT_TOO_LARGE"
	CodeEnvMismatch           = "ENV_MISMATCH"
	CodePathOutOfScope        = "PATH_OUT_OF_SCOPE"
	CodeSecretPolicyViolation = "SECRET_POLICY_VIOLATION"
	CodeWorkspaceInvalid      = "WORKSPACE_INVALID"
	CodeSessionNotFound       = "SESSION_NOT_FOUND"
	CodeChangesetInvalid      = "CHANGESET_INVALID"
	CodeRuntimeError          = "RUNTIME_ERROR"
)

// Exit codes. They avoid 1 (generic), 2 (Go panic), 125-127 (docker and
// the shell) and 255 (ssh).
const (
	ExitUsage    = 64
	ExitRejected = 65
	ExitRuntime  = 66
)

// ExitCode maps a remote error code to its exit code.
func ExitCode(code string) int {
	switch code {
	case CodeCommandInvalid, CodeProtocolUnsupported:
		return ExitUsage
	case CodeRuntimeError:
		return ExitRuntime
	default:
		return ExitRejected
	}
}

// ErrorLinePrefix starts every error line on stderr.
const ErrorLinePrefix = "pilot-mcp-remote: "

// ErrorLine formats one error line, including its newline. The message is
// flattened to one line.
func ErrorLine(code, msg string) string {
	msg = strings.Join(strings.Fields(msg), " ")
	return fmt.Sprintf("%s%s: %s\n", ErrorLinePrefix, code, msg)
}

var errorLinePattern = regexp.MustCompile(`^pilot-mcp-remote: ([A-Z_]+): (.*)$`)

// ParseErrorLine returns the code and message of the last error line in
// stderr text, if any.
func ParseErrorLine(stderr string) (code, msg string, ok bool) {
	lines := strings.Split(strings.TrimRight(stderr, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if m := errorLinePattern.FindStringSubmatch(strings.TrimRight(lines[i], "\r")); m != nil {
			return m[1], m[2], true
		}
	}
	return "", "", false
}
