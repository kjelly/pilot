package gatewayapi

import (
	"errors"

	"github.com/kjelly/pilot/internal/accessportal"
)

// Recording policy resolution errors (per-host recording spec §13).
var (
	// ErrRecordingPolicyUnknown: the host's policy could not be read
	// (host_show failed, or userclass was unreadable).
	ErrRecordingPolicyUnknown = errors.New("recording policy unavailable")
	// ErrRecordingPolicyInvalid: the host carries a malformed, duplicate or
	// unknown pilot.policy.ssh-recording marker.
	ErrRecordingPolicyInvalid = errors.New("recording policy invalid")
)

// Recording policy sources reported in the authorize response.
const (
	RecordingSourceHost           = "host"
	RecordingSourceGatewayDefault = "gateway_default"
	RecordingSourceBuiltInDefault = "built_in_default"
)

// Deny reasons for recording-related authorize refusals (per-host
// recording spec §15.2). HBAC/scope denials keep an empty DenyReason.
const (
	DenyReasonRecordingPolicyUnavailable = "recording_policy_unavailable"
	DenyReasonRecordingPolicyInvalid     = "recording_policy_invalid"
	DenyReasonRecordingBackend           = "recording_backend_unavailable"
	DenyReasonRecordingSessionID         = "recording_session_id_invalid"
)

const recordingModeMetadata = "metadata"

// ResolveRecordingMode applies per-host recording spec §4's precedence:
// a valid host override, else the gateway's configured default, else the
// built-in metadata. gatewayDefault must be the RAW configured value (""
// when unset) so the built-in default stays distinguishable. It returns
// the effective mode (metadata | terminal_output | terminal_io) and where
// it came from. A policy that could not be read or is invalid is an error:
// it never silently becomes "off".
func ResolveRecordingMode(gatewayDefault string, host accessportal.SSHRecordingAccessPolicy) (mode, source string, err error) {
	if !host.Known {
		return "", "", ErrRecordingPolicyUnknown
	}
	if !host.Valid {
		return "", "", ErrRecordingPolicyInvalid
	}
	switch host.Override {
	case "":
		if gatewayDefault == "" {
			return recordingModeMetadata, RecordingSourceBuiltInDefault, nil
		}
		return gatewayDefault, RecordingSourceGatewayDefault, nil
	case "off":
		return recordingModeMetadata, RecordingSourceHost, nil
	case "terminal_output":
		return "terminal_output", RecordingSourceHost, nil
	default:
		return "", "", ErrRecordingPolicyInvalid
	}
}

// isTerminalRecording reports whether mode records terminal bytes.
func isTerminalRecording(mode string) bool {
	return mode == "terminal_output" || mode == "terminal_io"
}
