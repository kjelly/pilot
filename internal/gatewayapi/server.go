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
	// — see internal/identity.IsMemberOfGroup's doc comment for the real
	// hazard this compensates for (a same-named local fallback group
	// permanently shadowing the real one via nsswitch's "files" source).
	PortalUserGroup string

	httpServer *http.Server
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
