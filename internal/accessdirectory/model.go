// Package accessdirectory computes one user's GLOBAL, cross-scope access
// view for pilot-access-directory (docs/tmp/now/spec.md §9/§10): which
// scopes currently have published targets, which Gateway instances serve
// each scope, and — merged across every scope — which targets a user can
// actually reach and by which route(s).
//
// This package is a discovery/routing PROJECTION, not a second
// authorization engine (spec.md D1, §9, §49.12): every bit of HBAC/sudo
// matching happens inside internal/accessportal.LoadPolicySnapshot/
// ResolveScopeAccess. This package only (a) discovers the scope catalog
// via internal/freeipaaccess.HostgroupFinder and (b) merges accessportal's
// per-scope results by FQDN. It never reads roster, inventory, or any
// local persistent state, matching internal/freeipaaccess and
// internal/accessportal's own discipline.
package accessdirectory

import (
	"time"

	"github.com/kjelly/pilot/internal/accessportal"
)

// ScopeRoute is one discovered scope's routing facts (spec.md §10.1):
// which target hostgroup it publishes and which Gateway instances
// currently serve it. GatewayHostgroup is always the expected
// "<gatewayPrefix><scope>" name, even when no such hostgroup exists yet
// (GatewayFQDNs is then empty) — that "target scope exists, no gateway
// published for it" state is exactly what RouteStatus "no_gateway"
// surfaces to a caller, not an error.
type ScopeRoute struct {
	Scope            string
	TargetHostgroup  string
	GatewayHostgroup string
	GatewayFQDNs     []string
}

// DirectoryAccess is the top-level per-user result (spec.md §10.2): every
// target the user can reach, across every scope, merged by FQDN.
type DirectoryAccess struct {
	User        string
	GeneratedAt time.Time
	Targets     []DirectoryTarget
}

// DirectoryTarget is one target host, reachable via one or more scopes
// (spec.md §10.3: "同一 target 出現在多個 scope... 合併成 DirectoryTarget
// with Routes[]" — never duplicated into separate rows per scope). SSH/
// Sudo reflect whichever route resolved first in scope-name order; in
// practice these never disagree across routes for the same user+host,
// since HBAC/sudo rules are global and every route's resolve shares one
// internal/accessportal.PolicySnapshot.
type DirectoryTarget struct {
	FQDN   string
	SSH    accessportal.SSHAccess
	Sudo   accessportal.SudoAccess
	Routes []TargetRoute
	// Recording is the host's recording-policy override as seen by the
	// Directory's own FreeIPA read (per-host recording spec §12). The
	// Directory does not know any gateway's default, so it reports only the
	// override; the effective mode comes from the target gateway's fresh
	// authorize.
	Recording accessportal.SSHRecordingAccessPolicy
}

// TargetRoute is one scope's routing detail for a DirectoryTarget
// (spec.md §10.2). RouteStatus is "ready" when at least one live Gateway
// instance serves this scope, "no_gateway" otherwise — Connect must be
// disabled for the latter (spec.md §13.1).
type TargetRoute struct {
	Scope             string
	TargetHostgroup   string
	GatewayHostgroup  string
	GatewayCandidates []string
	RouteStatus       string // "ready" | "no_gateway"
}
