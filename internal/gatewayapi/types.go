package gatewayapi

import "time"

// GatewayInfo is the gateway-identity block spec.md §22 requires on every
// response — never omitted, never client-overridable.
type GatewayInfo struct {
	ID              string `json:"id"`
	Scope           string `json:"scope"`
	TargetHostgroup string `json:"target_hostgroup"`
}

// IdentityResponse is GET /v1/identity (spec.md §22.1).
type IdentityResponse struct {
	UID      uint32      `json:"uid"`
	Username string      `json:"username"`
	Gateway  GatewayInfo `json:"gateway"`
}

// AccessResponse is GET /v1/access (spec.md §22.2) — always the calling
// socket peer's own access, never a caller-suppliable user/scope. Hosts is
// never nil: spec.md §22.2 shows an explicit "hosts": [] for a user with
// no accessible hosts, not a JSON null.
type AccessResponse struct {
	User        string      `json:"user"`
	Gateway     GatewayInfo `json:"gateway"`
	GeneratedAt time.Time   `json:"generated_at"`
	Hosts       []HostJSON  `json:"hosts"`
	// RecordingDefault is this gateway's effective default recording mode
	// (metadata when unset); per-host recording spec §17.
	RecordingDefault string `json:"recording_default"`
}

// HostJSON is one host entry in AccessResponse / the GET /v1/access/{fqdn} response.
type HostJSON struct {
	FQDN        string            `json:"fqdn"`
	SSH         SSHJSON           `json:"ssh"`
	Sudo        SudoJSON          `json:"sudo"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Recording   RecordingJSON     `json:"recording"`
}

// RecordingJSON is a host's non-secret recording summary (per-host
// recording spec §17). Status is the host's own policy (inherit | off |
// terminal_output | unknown | invalid); Effective is the mode a connect
// would use now (metadata | terminal_output | terminal_io), empty when the
// policy is unknown or invalid. Portal renders it; it never recomputes it.
type RecordingJSON struct {
	Status    string `json:"status"`
	Effective string `json:"effective,omitempty"`
}

type SSHJSON struct {
	Allowed bool     `json:"allowed"`
	Rules   []string `json:"rules"`
}

type SudoJSON struct {
	Scope         string   `json:"scope"`
	AllowCommands []string `json:"allow_commands"`
	DenyCommands  []string `json:"deny_commands"`
	Rules         []string `json:"rules"`
}

// ConnectAuthorizeRequest is POST /v1/connect/authorize's body (spec.md
// §22.4). Only "target" is accepted — DisallowUnknownFields (authz.go)
// rejects username/gateway_id/scope/target_hostgroup/anything else the
// client might try to smuggle in, rather than merely not reading them.
type ConnectAuthorizeRequest struct {
	Target string `json:"target"`
	// SessionID is bound into the per-session ingest token when the
	// effective mode records (per-host recording spec §15). It never
	// influences the HBAC/scope decision.
	SessionID string `json:"session_id,omitempty"`
}

// ConnectAuthorizeResponse is POST /v1/connect/authorize's response.
//
// The Recording* fields (docs/tmp/now/spec.md §23/§27, Phase 7) let this
// SAME fresh authorize call also answer "does this session record, and
// how" — this gateway's own /etc/pilot/access-gateway.yaml is the single
// source of truth (Server.RecordingPolicy), never a caller-supplied
// parameter. Populated only when Allowed (a denied caller gets no
// recording policy — there is no session to record). Zero-value
// RecordingMode ("") means "metadata", the unconditional default (D8).
type ConnectAuthorizeResponse struct {
	Allowed      bool      `json:"allowed"`
	Target       string    `json:"target"`
	Username     string    `json:"username"`
	GatewayID    string    `json:"gateway_id"`
	GatewayScope string    `json:"gateway_scope"`
	CheckedAt    time.Time `json:"checked_at"`
	Rules        []string  `json:"rules"`

	// DenyReason is set only for recording-related denials (per-host
	// recording spec §15.2); HBAC/scope denials leave it empty.
	DenyReason string `json:"deny_reason,omitempty"`

	RecordingMode            string `json:"recording_mode,omitempty"`
	RecordingPolicySource    string `json:"recording_policy_source,omitempty"`
	RecordingFailurePolicy   string `json:"recording_failure_policy,omitempty"`
	RecordingQueueEvents     int    `json:"recording_queue_events,omitempty"`
	RecordingFlushIntervalMS int64  `json:"recording_flush_interval_ms,omitempty"`
	RecordingFailureGraceMS  int64  `json:"recording_failure_grace_ms,omitempty"`

	// RecordingSessionStore* (docs/tmp/now/spec.md §28, Phase 8) tell the
	// connecting client's own pilot portal-session process where — and
	// with what credential — to ship terminal_output/terminal_io
	// recordings, so internal/sessionrecording.HTTPSink never needs its
	// own config file. Populated only when Allowed AND this gateway's
	// RecordingPolicy names a session-store URL; empty otherwise (e.g.
	// metadata mode, or a deployment still using local-file recording).
	// The ingest token here is a write-only credential (spec.md §28.2:
	// "ingest 憑證只有 write/append 權限，不能 read/replay") delivered over
	// this ALREADY-SO_PEERCRED-authenticated Unix socket response, held
	// only in the calling process's memory — never written to disk,
	// never passed as a CLI argument, matching spec.md §28.2's
	// prohibition on that specifically.
	RecordingSessionStoreURL    string `json:"recording_session_store_url,omitempty"`
	RecordingSessionStoreCAFile string `json:"recording_session_store_ca_file,omitempty"`
	// RecordingSessionStoreIngestToken is the per-session PIT1 token minted
	// for exactly this session (per-host recording spec §16); only terminal
	// modes ever carry it.
	RecordingSessionStoreIngestToken string `json:"recording_session_store_ingest_token,omitempty"`

	// TransportAllowed/TransportDenyReason (docs/superpowers/specs/
	// 2026-09-23-pilot-access-gateway-captive-ssh-transport-spec.md §8.1)
	// answer, on this SAME fresh authorize, whether the caller may also
	// open an opaque `pilot-transport-v1` byte transport to Target. Only
	// ever computed when Allowed; a client that finds TransportAllowed
	// absent (an older gateway daemon) must treat it as false.
	TransportAllowed    bool   `json:"transport_allowed,omitempty"`
	TransportDenyReason string `json:"transport_deny_reason,omitempty"`
}

// Transport deny reasons carried in ConnectAuthorizeResponse.TransportDenyReason.
const (
	TransportDenyDisabled          = "disabled"
	TransportDenyTargetNotReady    = "target_not_ready"
	TransportDenyReadyLookupFailed = "ready_lookup_failed"
)

// TransportHostKeysRequest is POST /v1/transport/host-keys's body — like
// ConnectAuthorizeRequest, only "target" is accepted.
type TransportHostKeysRequest struct {
	Target string `json:"target"`
}

// TransportHostKeysResponse is POST /v1/transport/host-keys's response
// (captive-transport spec §8.3): the target's FreeIPA-published SSH host
// public keys, returned only when the same fresh authorize + transport
// gate as /v1/connect/authorize allows a transport to Target. HostKeys is
// never nil — a denied caller gets "host_keys": [], never a reason.
type TransportHostKeysResponse struct {
	Allowed  bool     `json:"allowed"`
	Target   string   `json:"target"`
	HostKeys []string `json:"host_keys"`
}

// HealthResponse is GET /v1/health (spec.md §22.5) — never secret/path content.
type HealthResponse struct {
	Status          string `json:"status"`
	GatewayID       string `json:"gateway_id"`
	GatewayScope    string `json:"gateway_scope"`
	TargetHostgroup string `json:"target_hostgroup"`
	FreeIPA         string `json:"freeipa"`
	TargetScope     string `json:"target_scope"`
	Credential      string `json:"credential"`
}

// ErrorResponse is the body for every non-2xx response.
type ErrorResponse struct {
	Error string `json:"error"`
}
