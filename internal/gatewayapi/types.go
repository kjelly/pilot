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
}

// HostJSON is one host entry in AccessResponse / the GET /v1/access/{fqdn} response.
type HostJSON struct {
	FQDN string   `json:"fqdn"`
	SSH  SSHJSON  `json:"ssh"`
	Sudo SudoJSON `json:"sudo"`
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
}

// ConnectAuthorizeResponse is POST /v1/connect/authorize's response.
type ConnectAuthorizeResponse struct {
	Allowed      bool      `json:"allowed"`
	Target       string    `json:"target"`
	Username     string    `json:"username"`
	GatewayID    string    `json:"gateway_id"`
	GatewayScope string    `json:"gateway_scope"`
	CheckedAt    time.Time `json:"checked_at"`
	Rules        []string  `json:"rules"`
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
