package gatewayapi

import (
	"context"
	"log/slog"
	"net"

	"github.com/kjelly/pilot/internal/identity"
	"github.com/kjelly/pilot/internal/peercred"
)

// Peer is the trusted caller identity for one connection: kernel UID via
// SO_PEERCRED, mapped to a username via getent (spec.md §10.1). Never
// derived from anything the client sent (SI-04/AG10/AG11).
type Peer struct {
	UID      uint32
	Username string
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
		return context.WithValue(ctx, peerCtxKey{}, Peer{UID: cred.UID, Username: username})
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
