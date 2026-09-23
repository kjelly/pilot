package directoryapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"github.com/kjelly/pilot/internal/identity"
	"github.com/kjelly/pilot/internal/peercred"
)

// Peer is the trusted caller identity for one connection: kernel UID via
// SO_PEERCRED, mapped to a username via getent — never derived from
// anything the client sent. Same shape/derivation as
// internal/gatewayapi.Peer; duplicated rather than shared because
// gatewayapi keeps this logic package-local too (no shared internal
// helper package exists for it), and Directory must not depend on
// Gateway's package for something this fundamental.
type Peer struct {
	UID      uint32
	Username string
	// PID is the SO_PEERCRED process id, used only to read that process's
	// kernel group credentials for the group gate (identity.PeerInGroup).
	PID int32
}

type peerCtxKey struct{}

// connContext is installed as http.Server.ConnContext. It runs once per
// accepted connection (not per request), extracting SO_PEERCRED and
// resolving the username immediately — every request on this connection
// then reuses the same trusted Peer from the context, never re-deriving
// it from request data.
func connContext(logger *slog.Logger) func(ctx context.Context, c net.Conn) context.Context {
	return func(ctx context.Context, c net.Conn) context.Context {
		uc, ok := c.(*net.UnixConn)
		if !ok {
			logger.Warn("connection is not a unix socket; refusing to trust it", "remote", c.RemoteAddr())
			return ctx
		}
		cred, err := peercred.FromConn(uc)
		if err != nil {
			logger.Warn("SO_PEERCRED failed", "error", err)
			return ctx
		}
		username, err := identity.LookupUsername(ctx, cred.UID)
		if err != nil {
			logger.Warn("getent passwd lookup failed", "uid", cred.UID, "error", err)
			return ctx
		}
		return context.WithValue(ctx, peerCtxKey{}, Peer{UID: cred.UID, Username: username, PID: cred.PID})
	}
}

// peerFromContext returns the trusted Peer for this request's connection.
// ok is false if SO_PEERCRED or the getent lookup failed for this
// connection — callers MUST treat that as unauthenticated, never fall
// back to any client-supplied identity.
func peerFromContext(ctx context.Context) (Peer, bool) {
	p, ok := ctx.Value(peerCtxKey{}).(Peer)
	return p, ok
}

// authorizedPeer is peerFromContext plus s.PortalUserGroup membership —
// the user-facing endpoints' defense-in-depth gate alongside the
// socket's own SocketGroup=, mirroring internal/gatewayapi.Server's
// identically-named method exactly. When PortalUserGroup is unset, this
// is exactly peerFromContext (no additional gate configured).
func (s *Server) authorizedPeer(r *http.Request) (Peer, bool) {
	peer, ok := peerFromContext(r.Context())
	if !ok {
		return Peer{}, false
	}
	if s.PortalUserGroup == "" {
		return peer, true
	}
	member, err := identity.PeerInGroup(r.Context(), peer.PID, peer.UID, s.PortalUserGroup)
	if err != nil {
		s.Logger.Warn("portal user group check failed", "user", peer.Username, "group", s.PortalUserGroup, "error", err)
		return Peer{}, false
	}
	return peer, member
}
