package directoryapi

import "time"

// DirectoryInfo is the directory-identity block included on every
// response — never client-overridable.
type DirectoryInfo struct {
	ID                     string `json:"id"`
	TargetHostgroupPrefix  string `json:"target_hostgroup_prefix"`
	GatewayHostgroupPrefix string `json:"gateway_hostgroup_prefix"`
}

// IdentityResponse is GET /v1/identity (spec.md §11.1).
type IdentityResponse struct {
	UID       uint32        `json:"uid"`
	Username  string        `json:"username"`
	Directory DirectoryInfo `json:"directory"`
}

// AccessResponse is GET /v1/access (spec.md §11.1) — always the calling
// socket peer's own cross-scope access, never a caller-suppliable user.
// Targets is never nil: a user with no accessible targets gets an
// explicit "targets": [], not a JSON null (matching gatewayapi's
// AccessResponse.Hosts convention).
type AccessResponse struct {
	User        string        `json:"user"`
	Directory   DirectoryInfo `json:"directory"`
	GeneratedAt time.Time     `json:"generated_at"`
	Targets     []TargetJSON  `json:"targets"`
}

// TargetJSON is one target host entry in AccessResponse / the
// GET /v1/access/{fqdn} response — SSH/Sudo plus every scope-specific
// Route it is reachable through (spec.md §10.3: one merged entry per
// FQDN, never duplicated per scope).
type TargetJSON struct {
	FQDN   string      `json:"fqdn"`
	SSH    SSHJSON     `json:"ssh"`
	Sudo   SudoJSON    `json:"sudo"`
	Routes []RouteJSON `json:"routes"`
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

// RouteJSON is one scope's routing detail for a TargetJSON (spec.md
// §10.2). RouteStatus "no_gateway" means Connect must be disabled for
// this route (spec.md §13.1) — GatewayCandidates is then empty.
type RouteJSON struct {
	Scope             string   `json:"scope"`
	TargetHostgroup   string   `json:"target_hostgroup"`
	GatewayHostgroup  string   `json:"gateway_hostgroup"`
	GatewayCandidates []string `json:"gateway_candidates"`
	RouteStatus       string   `json:"route_status"`
}

// ConnectResolveRequest is POST /v1/connect/resolve's body (spec.md
// §11.2). Only "target" is accepted — DisallowUnknownFields (authz.go)
// rejects anything else the client might try to smuggle in (user/scope/
// gateway/session_id/...), matching gatewayapi's ConnectAuthorizeRequest
// discipline.
type ConnectResolveRequest struct {
	Target string `json:"target"`
}

// ConnectResolveResponse is POST /v1/connect/resolve's response (spec.md
// §11.2). SessionID/Route are omitted (zero value) when Allowed is
// false — there is nothing to hand off to. This is discovery-time
// routing metadata, never a capability or grant token (D1/D6): the
// Gateway that eventually receives this session_id still performs its
// own fresh authorize, completely independent of what this response
// says.
type ConnectResolveResponse struct {
	Allowed   bool              `json:"allowed"`
	SessionID string            `json:"session_id,omitempty"`
	Target    string            `json:"target"`
	Route     *ConnectRouteJSON `json:"route,omitempty"`
}

// ConnectRouteJSON is the route chosen by handleConnectResolve: the
// lexically-first route_status=ready scope for this target (spec.md
// §10.3's deterministic-selection rule).
type ConnectRouteJSON struct {
	Scope             string   `json:"scope"`
	GatewayCandidates []string `json:"gateway_candidates"`
}

// HealthResponse is GET /v1/health (spec.md §11.1) — never secret/path content.
type HealthResponse struct {
	Status       string `json:"status"`
	DirectoryID  string `json:"directory_id"`
	FreeIPA      string `json:"freeipa"`
	ScopeCatalog string `json:"scope_catalog"`
}

// ErrorResponse is the body for every non-2xx response.
type ErrorResponse struct {
	Error string `json:"error"`
}
