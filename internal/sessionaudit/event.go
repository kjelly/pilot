// Package sessionaudit is the shared, structured metadata-audit event type
// and emitter for the Directory -> Gateway -> Target handoff (docs/tmp/now/
// spec.md §21/§22). It is deliberately small and dependency-free (no
// roster/inventory, matching every other package in this feature's
// family) so both cmd/pilot/cmd (Directory's and Gateway's CLI code) can
// import it without pulling in anything else.
//
// This package NEVER carries terminal recording payload (D9) — only the
// small, structured lifecycle records spec.md §21.2 defines. Phase 7/8's
// separate terminal-recording sink is a different concern with different
// sensitivity, and the two must never share a transport.
package sessionaudit

import "time"

// SessionAuditEvent is one structured record per session lifecycle
// milestone (spec.md §21.2), correlated across Directory and Gateway by
// SessionID — the whole point of Phase 6. Field shape matches the spec's
// Go struct literal exactly; do not rename/reorder without updating the
// spec doc too.
type SessionAuditEvent struct {
	SchemaVersion int       `json:"schema_version"`
	EventID       string    `json:"event_id"`
	SessionID     string    `json:"session_id"`
	Seq           uint64    `json:"seq"`
	Timestamp     time.Time `json:"timestamp"`

	Kind string `json:"kind"`

	User string `json:"user"`
	UID  int    `json:"uid,omitempty"`

	DirectoryID  string `json:"directory_id,omitempty"`
	GatewayID    string `json:"gateway_id,omitempty"`
	GatewayScope string `json:"gateway_scope,omitempty"`
	GatewayFQDN  string `json:"gateway_fqdn,omitempty"`
	TargetFQDN   string `json:"target_fqdn,omitempty"`

	Result   string `json:"result,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`

	RecordingMode string `json:"recording_mode,omitempty"`
	// RecordingPolicySource is where the effective recording mode came
	// from: host | gateway_default | built_in_default (per-host recording
	// spec §22).
	RecordingPolicySource string `json:"recording_policy_source,omitempty"`

	// Auditor is the account that replayed or exported a recording
	// (recording_replayed / recording_exported).
	Auditor string `json:"auditor,omitempty"`
}

// SchemaVersion1 is the only schema version this package currently emits.
const SchemaVersion1 = 1

// Event kinds (spec.md §21.2's minimum list, Directory/Gateway half from
// Phase 6, plus Phase 7's three recording-lifecycle kinds — reusing this
// same Emitter/facility, never a second metadata channel, per D9).
const (
	KindDirectoryConnectRequested = "directory_connect_requested"
	KindDirectoryRouteResolved    = "directory_route_resolved"
	KindDirectoryGatewayAttempt   = "directory_gateway_attempt"
	KindDirectoryGatewayConnected = "directory_gateway_connected"
	KindGatewayAuthorizeAllowed   = "gateway_authorize_allowed"
	KindGatewayAuthorizeDenied    = "gateway_authorize_denied"
	KindTargetConnectStarted      = "target_connect_started"
	KindTargetConnectFailed       = "target_connect_failed"
	KindSessionStarted            = "session_started"
	KindSessionEnded              = "session_ended"

	// KindRecordingStarted/KindRecordingGap/KindRecordingFailed carry no
	// terminal bytes — only status/counts (D9: recording payload never
	// goes through this metadata channel).
	KindRecordingStarted = "recording_started"
	KindRecordingGap     = "recording_gap"
	KindRecordingFailed  = "recording_failed"

	// KindRecordingReplayed/KindRecordingExported record an auditor reading
	// a stored recording (per-host recording spec §21.5/§22).
	KindRecordingReplayed = "recording_replayed"
	KindRecordingExported = "recording_exported"
)
