package directoryapi

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kjelly/pilot/internal/accessdirectory"
	"github.com/kjelly/pilot/internal/accessportal"
)

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/identity", s.handleIdentity)
	mux.HandleFunc("GET /v1/access", s.handleAccess)
	mux.HandleFunc("GET /v1/access/{fqdn}", s.handleAccessHost)
	mux.HandleFunc("POST /v1/connect/resolve", s.handleConnectResolve)
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	return mux
}

func (s *Server) directoryInfo() DirectoryInfo {
	return DirectoryInfo{
		ID:                     s.Directory.ID,
		TargetHostgroupPrefix:  s.Directory.TargetHostgroupPrefix,
		GatewayHostgroupPrefix: s.Directory.GatewayHostgroupPrefix,
	}
}

// loadAccess is the one place every user-facing handler calls into
// internal/accessdirectory — always a fresh resolve (D1), never a cached
// row reused across requests or across handlers within the same request.
func (s *Server) loadAccess(ctx context.Context, username string) (accessdirectory.DirectoryAccess, error) {
	return accessdirectory.LoadDirectoryAccess(ctx, s.Provider, s.Finder, username,
		s.Directory.TargetHostgroupPrefix, s.Directory.GatewayHostgroupPrefix, time.Now())
}

// handleIdentity is GET /v1/identity (spec.md §11.1).
func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.authorizedPeer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, IdentityResponse{UID: peer.UID, Username: peer.Username, Directory: s.directoryInfo()})
}

// handleAccess is GET /v1/access (spec.md §11.1) — only ever the calling
// peer's own cross-scope access; there is no ?user= query parameter this
// handler reads, by construction.
func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.authorizedPeer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	access, err := s.loadAccess(r.Context(), peer.Username)
	if err != nil {
		s.Logger.Error("resolve directory access failed", "user", peer.Username, "error", err)
		writeError(w, http.StatusServiceUnavailable, "access service unavailable")
		return
	}
	writeJSON(w, http.StatusOK, toAccessResponse(peer.Username, s.directoryInfo(), access))
}

// handleAccessHost is GET /v1/access/{fqdn} (spec.md §11.1): the same
// 404 whether fqdn is unmanaged or simply not reachable by this user, so
// no information about which case it was leaks.
func (s *Server) handleAccessHost(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.authorizedPeer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	fqdn := accessportal.CanonicalizeFQDN(r.PathValue("fqdn"))
	access, err := s.loadAccess(r.Context(), peer.Username)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "access service unavailable")
		return
	}
	for _, t := range access.Targets {
		if t.FQDN == fqdn {
			writeJSON(w, http.StatusOK, toTargetJSON(t))
			return
		}
	}
	writeError(w, http.StatusNotFound, "not found")
}

// handleConnectResolve is POST /v1/connect/resolve (spec.md §11.2): a
// FRESH LoadDirectoryAccess on every call (D1 — never trust a cached
// /v1/access row here). Picks the lexically-first route_status=ready
// route for a deterministic choice among multiple candidates (spec.md
// §10.3); Route is left nil when nothing is ready. This is routing
// metadata only — the Gateway that later receives this session_id still
// performs its own fresh, independent authorize (D1/D6): this response
// is not a capability, ticket, or grant.
func (s *Server) handleConnectResolve(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.authorizedPeer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req ConnectResolveRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	target := accessportal.CanonicalizeFQDN(req.Target)
	resp := ConnectResolveResponse{Target: target}

	access, err := s.loadAccess(r.Context(), peer.Username)
	if err != nil {
		s.Logger.Error("connect resolve: directory access failed, denying", "user", peer.Username, "target", target, "error", err)
		writeJSON(w, http.StatusOK, resp) // Allowed stays false.
		return
	}

	for _, t := range access.Targets {
		if t.FQDN != target {
			continue
		}
		for _, route := range t.Routes { // already scope-sorted by accessdirectory
			if route.RouteStatus != "ready" {
				continue
			}
			resp.Allowed = true
			resp.SessionID = uuid.NewString()
			resp.Route = &ConnectRouteJSON{Scope: route.Scope, GatewayCandidates: route.GatewayCandidates}
			break
		}
		break
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleHealth is GET /v1/health (spec.md §11.1) — fails closed (D1/§9.5)
// on either a FreeIPA outage or a scope-catalog read failure, never
// falling back to a previously-successful result.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{DirectoryID: s.Directory.ID, Status: "ok", FreeIPA: "reachable", ScopeCatalog: "ok"}
	if _, err := s.Provider.Ping(r.Context()); err != nil {
		resp.Status = "degraded"
		resp.FreeIPA = "unreachable"
	}
	if _, err := accessdirectory.LoadScopeCatalog(r.Context(), s.Provider, s.Finder, s.Directory.TargetHostgroupPrefix, s.Directory.GatewayHostgroupPrefix); err != nil {
		resp.Status = "degraded"
		resp.ScopeCatalog = "unreachable"
	}
	status := http.StatusOK
	if resp.Status != "ok" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, resp)
}

func toAccessResponse(username string, dir DirectoryInfo, access accessdirectory.DirectoryAccess) AccessResponse {
	resp := AccessResponse{User: username, Directory: dir, GeneratedAt: access.GeneratedAt, Targets: []TargetJSON{}}
	for _, t := range access.Targets {
		resp.Targets = append(resp.Targets, toTargetJSON(t))
	}
	return resp
}

func toTargetJSON(t accessdirectory.DirectoryTarget) TargetJSON {
	sshRules := make([]string, 0, len(t.SSH.Rules))
	for _, r := range t.SSH.Rules {
		sshRules = append(sshRules, r.Rule)
	}
	sudoRules := make([]string, 0, len(t.Sudo.Rules))
	for _, r := range t.Sudo.Rules {
		sudoRules = append(sudoRules, r.Rule)
	}
	routes := make([]RouteJSON, 0, len(t.Routes))
	for _, route := range t.Routes {
		routes = append(routes, RouteJSON{
			Scope:             route.Scope,
			TargetHostgroup:   route.TargetHostgroup,
			GatewayHostgroup:  route.GatewayHostgroup,
			GatewayCandidates: route.GatewayCandidates,
			RouteStatus:       route.RouteStatus,
		})
	}
	return TargetJSON{
		FQDN:   t.FQDN,
		SSH:    SSHJSON{Allowed: t.SSH.Allowed, Rules: sshRules},
		Sudo:   SudoJSON{Scope: t.Sudo.Scope, AllowCommands: t.Sudo.AllowCommands, DenyCommands: t.Sudo.DenyCommands, Rules: sudoRules},
		Routes: routes,
	}
}
