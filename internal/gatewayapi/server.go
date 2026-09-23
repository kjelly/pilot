// Package gatewayapi is pilot-access-gateway's HTTP-over-Unix-socket API
// (spec.md §22): /v1/identity, /v1/access, /v1/access/{fqdn},
// /v1/connect/authorize, /v1/health. It never listens on TCP.
package gatewayapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// Server is pilot-access-gateway's API surface for exactly one gateway
// instance.
type Server struct {
	Gateway  accessportal.GatewayConfig
	Provider freeipaaccess.Provider
	Resolver *accessportal.Resolver
	Logger   *slog.Logger

	// PortalUserGroup, when non-empty, restricts every user-facing
	// endpoint (identity/access/connect — NOT health, an ops probe with
	// no per-user concept) to callers whose resolved username is a
	// member of this group. Set after construction so existing callers
	// that don't need this gate (tests, Phase 3-5 fixtures) are
	// unaffected.
	//
	// This is a defense-in-depth layer alongside (not a replacement for)
	// the Unix socket's own SocketGroup= (spec.md §29's first layer),
	// which live vm-target testing confirmed DOES reliably enforce an
	// SSSD/FreeIPA-backed group once nothing else on the host shadows it
	// — see internal/identity.PeerInGroup's doc comment for the real
	// hazards this compensates for (a same-named local fallback group
	// shadowing the real one via nsswitch's "files" source) and why it
	// checks the peer process's kernel groups, not the SSSD-cached member
	// list.
	PortalUserGroup string

	// RecordingPolicy is this gateway's session-recording configuration
	// (docs/tmp/now/spec.md §23/§27, Phase 7), sourced from
	// /etc/pilot/access-gateway.yaml and set after construction (same
	// pattern as PortalUserGroup). The zero value's Mode == "" is
	// authoritative for "metadata" — handleConnectAuthorize never needs a
	// separate default-substitution step.
	RecordingPolicy RecordingPolicy

	// Transport is this gateway's opaque SSH transport policy
	// (docs/superpowers/specs/2026-09-23-pilot-access-gateway-captive-ssh-
	// transport-spec.md §8.2), sourced from /etc/pilot/access-gateway.yaml
	// gateway.transport and set after construction like RecordingPolicy.
	// The zero value (Enabled == false) is the unconditional default.
	Transport TransportPolicy

	httpServer *http.Server
}

// TransportPolicy is the gateway.transport config section as the API
// server needs it.
type TransportPolicy struct {
	Enabled bool
}

// TransportReadyHostgroup is the FreeIPA hostgroup a target must belong
// to before any gateway will open a transport to it. Only
// playbooks/apply/pilot-access-target-policy-apply.yml adds a host to it,
// and only after that host's sshd forwarding policy verified cleanly —
// so "reachable by transport" can never outrun "forwarding restricted"
// (captive-transport spec D5). Deliberately not configurable.
const TransportReadyHostgroup = "pilot-transport-ready"

// RecordingPolicy mirrors cmd/pilot-access-gateway/config.go's recording
// fields — kept as a small value type here (not the config package's own
// type, which internal/gatewayapi must not depend on) so a test can set
// it directly without needing a whole Config/LoadConfig round trip.
//
// SessionStore* (docs/tmp/now/spec.md §28, Phase 8) are populated only
// when this gateway is configured to ship recordings to
// pilot-session-store; a Gateway using local-file recording (or
// "metadata" mode, which never records terminal content at all) leaves
// them empty. SessionStoreIngestToken is read once from
// cmd/pilot-access-gateway/config.go's session_store_ingest_token_file
// (never a CLI argument, never logged, matching spec.md §28.2) and held
// only in memory — this Server never writes it to disk.
type RecordingPolicy struct {
	Mode            string
	FailurePolicy   string
	QueueEvents     int
	FlushIntervalMS int64

	SessionStoreURL         string
	SessionStoreCAFile      string
	SessionStoreIngestToken string
}

// NewServer builds a Server bound to one gateway's config, provider, and
// resolver. logger defaults to slog.Default() when nil.
func NewServer(gw accessportal.GatewayConfig, provider freeipaaccess.Provider, resolver *accessportal.Resolver, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{Gateway: gw, Provider: provider, Resolver: resolver, Logger: logger}
	s.httpServer = &http.Server{
		Handler:     s.routes(),
		ConnContext: connContext(logger),
	}
	return s
}

// Serve blocks, serving over ln — always a Unix socket listener; the
// caller (cmd/pilot-access-gateway) owns systemd socket activation vs. a
// plain bind.
func (s *Server) Serve(ln net.Listener) error {
	return s.httpServer.Serve(ln)
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
