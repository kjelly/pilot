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
