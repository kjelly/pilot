// Package directoryapi is pilot-access-directory's HTTP-over-Unix-socket
// API (docs/tmp/now/spec.md §11): /v1/identity, /v1/access,
// /v1/access/{fqdn}, /v1/connect/resolve, /v1/health. It never listens on
// TCP. It is a global discovery/routing projection, never a second
// authorization authority (D1) — every response is a fresh
// internal/accessdirectory.LoadDirectoryAccess call, never a cached row a
// Gateway would be expected to trust.
package directoryapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// DirectoryConfig is this Directory instance's identity (spec.md §12.1):
// which hostgroup-name prefixes define the scope catalog it discovers.
// Never derived from hostname (D3) — ID is operator-assigned; the
// prefixes are FreeIPA hostgroup-naming convention, not per-instance
// secrets.
type DirectoryConfig struct {
	ID                     string
	TargetHostgroupPrefix  string
	GatewayHostgroupPrefix string
}

// Server is pilot-access-directory's API surface for one Directory
// instance.
type Server struct {
	Directory DirectoryConfig
	Provider  freeipaaccess.Provider
	Finder    freeipaaccess.HostgroupFinder
	Logger    *slog.Logger

	// PortalUserGroup, when non-empty, restricts every user-facing
	// endpoint (identity/access/connect — NOT health, an ops probe with
	// no per-user concept) to callers whose resolved username is a
	// member of this group — the same defense-in-depth gate
	// internal/gatewayapi.Server.PortalUserGroup documents, alongside
	// (not instead of) the Unix socket's own SocketGroup=.
	PortalUserGroup string

	httpServer *http.Server
}

// NewServer builds a Server bound to one Directory's config, provider,
// and hostgroup finder. logger defaults to slog.Default() when nil.
func NewServer(dir DirectoryConfig, provider freeipaaccess.Provider, finder freeipaaccess.HostgroupFinder, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{Directory: dir, Provider: provider, Finder: finder, Logger: logger}
	s.httpServer = &http.Server{
		Handler:     s.routes(),
		ConnContext: connContext(logger),
	}
	return s
}

// Serve blocks, serving over ln — always a Unix socket listener; the
// caller (cmd/pilot-access-directory) owns systemd socket activation vs.
// a plain bind.
func (s *Server) Serve(ln net.Listener) error {
	return s.httpServer.Serve(ln)
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
