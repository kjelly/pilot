// Package gatewayapi is pilot-access-gateway's HTTP-over-Unix-socket API
// (spec.md §22): /v1/identity, /v1/access, /v1/access/{fqdn},
// /v1/connect/authorize, /v1/health. It never listens on TCP.
package gatewayapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/freeipaaccess"
	"github.com/kjelly/pilot/internal/ingesttoken"
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
	// — see internal/identity.IsMemberOfGroup's doc comment for the real
	// hazard this compensates for (a same-named local fallback group
	// permanently shadowing the real one via nsswitch's "files" source).
	PortalUserGroup string

	// RecordingPolicy is this gateway's session-recording configuration
	// (docs/tmp/now/spec.md §23/§27, Phase 7), sourced from
	// /etc/pilot/access-gateway.yaml and set after construction (same
	// pattern as PortalUserGroup). The zero value's Mode == "" is
	// authoritative for "metadata" — handleConnectAuthorize never needs a
	// separate default-substitution step.
	RecordingPolicy RecordingPolicy

	// Metrics, when non-nil, counts authorize decisions for the
	// node_exporter textfile (per-host recording spec §31).
	Metrics *Metrics

	httpServer *http.Server
}

// RecordingPolicy is this gateway's recording configuration (per-host
// recording spec §14) as a small value type — internal/gatewayapi does not
// depend on internal/gatewayconfig, so a test can set it directly.
//
// DefaultMode is the RAW configured recording.mode ("" = unset, built-in
// metadata); the effective mode is resolved per connect from it and the
// target host's FreeIPA policy. Signer mints the per-session ingest tokens
// (PIT1) handed to recorded sessions; it is nil when no session store is
// configured, and the signing key never leaves this process.
type RecordingPolicy struct {
	DefaultMode        string
	FailurePolicy      string
	QueueEvents        int
	FlushIntervalMS    int64
	FailureGraceMS     int64
	MaxSessionDuration time.Duration

	SessionStoreURL    string
	SessionStoreCAFile string
	Signer             *ingesttoken.Signer
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
