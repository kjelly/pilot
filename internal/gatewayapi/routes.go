package gatewayapi

import (
	"context"
	"net/http"
	"time"

	"github.com/kjelly/pilot/internal/accessportal"
)

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/identity", s.handleIdentity)
	mux.HandleFunc("GET /v1/access", s.handleAccess)
	mux.HandleFunc("GET /v1/access/{fqdn}", s.handleAccessHost)
	mux.HandleFunc("POST /v1/connect/authorize", s.handleConnectAuthorize)
	mux.HandleFunc("POST /v1/transport/host-keys", s.handleTransportHostKeys)
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	return mux
}

func (s *Server) gatewayInfo() GatewayInfo {
	return GatewayInfo{ID: s.Gateway.ID, Scope: s.Gateway.Scope, TargetHostgroup: s.Gateway.TargetHostgroup}
}

// handleIdentity is GET /v1/identity (spec.md §22.1).
func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.authorizedPeer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, IdentityResponse{UID: peer.UID, Username: peer.Username, Gateway: s.gatewayInfo()})
}

// handleAccess is GET /v1/access (spec.md §22.2) — only ever the calling
// peer's own access; there is no ?user=/?scope=/?target_hostgroup= query
// parameter this handler reads, by construction.
func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.authorizedPeer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	access, err := s.Resolver.LoadUserAccess(r.Context(), peer.Username)
	if err != nil {
		s.Logger.Error("resolve access failed", "user", peer.Username, "error", err)
		writeError(w, http.StatusServiceUnavailable, "access service unavailable")
		return
	}
	writeJSON(w, http.StatusOK, toAccessResponse(peer.Username, s.gatewayInfo(), access))
}

// handleAccessHost is GET /v1/access/{fqdn} (spec.md §22.3): fqdn must be
// both in gateway scope and in the user's effective SSH-allowed set, or
// this returns 404 — the same 404 for "not in scope" and "in scope but
// not allowed", so no information about which case it was leaks (spec.md
// §14: not displayable, not detail-able, either way).
func (s *Server) handleAccessHost(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.authorizedPeer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	fqdn := accessportal.CanonicalizeFQDN(r.PathValue("fqdn"))
	access, err := s.Resolver.LoadUserAccess(r.Context(), peer.Username)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "access service unavailable")
		return
	}
	for _, h := range access.Hosts {
		if h.FQDN == fqdn {
			writeJSON(w, http.StatusOK, toHostJSON(h))
			return
		}
	}
	writeError(w, http.StatusNotFound, "not found")
}

// handleConnectAuthorize is POST /v1/connect/authorize (spec.md §22.4): a
// fresh, full resolve on every call (spec.md §16 — "Connect 每次 fresh
// authorize"; this package does not cache LoadUserAccess at all yet, so
// staleness cannot occur by construction). FreeIPA/resolve failure denies
// rather than erroring the connect decision (spec.md §16/§34).
func (s *Server) handleConnectAuthorize(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.authorizedPeer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req ConnectAuthorizeRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	writeJSON(w, http.StatusOK, s.authorizeConnect(r.Context(), peer, req.Target))
}

// authorizeConnect is the one HBAC ∩ gateway-scope decision every connect
// path shares — /v1/connect/authorize and /v1/transport/host-keys both
// call it, so there is exactly one authorization semantics
// (captive-transport spec §8.2), never a second ACL.
func (s *Server) authorizeConnect(ctx context.Context, peer Peer, rawTarget string) ConnectAuthorizeResponse {
	target := accessportal.CanonicalizeFQDN(rawTarget)
	resp := ConnectAuthorizeResponse{
		Target: target, Username: peer.Username,
		GatewayID: s.Gateway.ID, GatewayScope: s.Gateway.Scope,
		CheckedAt: time.Now().UTC(),
	}
	access, err := s.Resolver.LoadUserAccess(ctx, peer.Username)
	if err != nil {
		s.Logger.Error("connect authorize: resolve failed, denying", "user", peer.Username, "target", target, "error", err)
		return resp // Allowed stays false.
	}
	for _, h := range access.Hosts {
		if h.FQDN == target && h.SSH.Allowed {
			resp.Allowed = true
			for _, rs := range h.SSH.Rules {
				resp.Rules = append(resp.Rules, rs.Rule)
			}
			break
		}
	}
	if resp.Allowed {
		resp.RecordingMode = s.RecordingPolicy.Mode
		resp.RecordingFailurePolicy = s.RecordingPolicy.FailurePolicy
		resp.RecordingQueueEvents = s.RecordingPolicy.QueueEvents
		resp.RecordingFlushIntervalMS = s.RecordingPolicy.FlushIntervalMS
		resp.RecordingSessionStoreURL = s.RecordingPolicy.SessionStoreURL
		resp.RecordingSessionStoreCAFile = s.RecordingPolicy.SessionStoreCAFile
		resp.RecordingSessionStoreIngestToken = s.RecordingPolicy.SessionStoreIngestToken
		s.applyTransportGate(ctx, &resp)
	}
	return resp
}

// applyTransportGate sets TransportAllowed only when this gateway enables
// transport, the connect's recording mode allows it (D8), AND the
// (already authorized) target is a member of TransportReadyHostgroup,
// direct or nested. Any lookup failure fails closed. Neither a disabled
// gateway nor a recording-incompatible connect touches FreeIPA for this.
// /v1/transport/host-keys reads the same result, so a target's keys are
// served only while a transport to it is allowed.
func (s *Server) applyTransportGate(ctx context.Context, resp *ConnectAuthorizeResponse) {
	if !s.Transport.Enabled {
		resp.TransportDenyReason = TransportDenyDisabled
		return
	}
	if !TransportRecordingCompatible(resp.RecordingMode) {
		resp.TransportDenyReason = TransportDenyRecordingIncompatible
		return
	}
	hg, err := s.Provider.HostgroupShow(ctx, TransportReadyHostgroup)
	if err != nil {
		s.Logger.Warn("transport gate: ready hostgroup lookup failed, denying transport", "hostgroup", TransportReadyHostgroup, "target", resp.Target, "error", err)
		resp.TransportDenyReason = TransportDenyReadyLookupFailed
		return
	}
	for _, members := range [][]string{hg.MemberHosts, hg.IndirectMemberHosts} {
		for _, h := range members {
			if accessportal.CanonicalizeFQDN(h) == resp.Target {
				resp.TransportAllowed = true
				return
			}
		}
	}
	resp.TransportDenyReason = TransportDenyTargetNotReady
}

// handleTransportHostKeys is POST /v1/transport/host-keys (captive-
// transport spec §8.3): the FreeIPA-published SSH host keys of a target
// the caller may open a transport to right now, so the workstation's
// inner OpenSSH can verify the target end to end without TOFU. Uses the
// exact same authorizeConnect + transport gate as /v1/connect/authorize;
// a denied caller gets allowed=false and an empty key list, never a
// reason.
func (s *Server) handleTransportHostKeys(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.authorizedPeer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req TransportHostKeysRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	authz := s.authorizeConnect(r.Context(), peer, req.Target)
	resp := TransportHostKeysResponse{Target: authz.Target, HostKeys: []string{}}
	if !authz.Allowed || !authz.TransportAllowed {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	host, err := s.Provider.HostShow(r.Context(), authz.Target)
	if err != nil {
		s.Logger.Error("transport host keys: host_show failed", "user", peer.Username, "target", authz.Target, "error", err)
		writeError(w, http.StatusServiceUnavailable, "access service unavailable")
		return
	}
	resp.Allowed = true
	resp.HostKeys = append(resp.HostKeys, host.SSHPublicKeys...)
	writeJSON(w, http.StatusOK, resp)
}

// handleHealth is GET /v1/health (spec.md §22.5).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		GatewayID: s.Gateway.ID, GatewayScope: s.Gateway.Scope, TargetHostgroup: s.Gateway.TargetHostgroup,
		Status: "ok", FreeIPA: "reachable", TargetScope: "ok", Credential: "ok",
	}
	if _, err := s.Provider.Ping(r.Context()); err != nil {
		resp.Status = "degraded"
		resp.FreeIPA = "unreachable"
		resp.Credential = "unknown"
	}
	if _, err := s.Resolver.ResolveGatewayScope(r.Context()); err != nil {
		resp.Status = "degraded"
		resp.TargetScope = "missing"
	}
	status := http.StatusOK
	if resp.Status != "ok" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, resp)
}

func toAccessResponse(username string, gw GatewayInfo, access accessportal.UserAccess) AccessResponse {
	resp := AccessResponse{User: username, Gateway: gw, GeneratedAt: access.GeneratedAt, Hosts: []HostJSON{}}
	for _, h := range access.Hosts {
		resp.Hosts = append(resp.Hosts, toHostJSON(h))
	}
	return resp
}

func toHostJSON(h accessportal.HostAccess) HostJSON {
	sshRules := make([]string, 0, len(h.SSH.Rules))
	for _, r := range h.SSH.Rules {
		sshRules = append(sshRules, r.Rule)
	}
	sudoRules := make([]string, 0, len(h.Sudo.Rules))
	for _, r := range h.Sudo.Rules {
		sudoRules = append(sudoRules, r.Rule)
	}
	return HostJSON{
		FQDN:        h.FQDN,
		SSH:         SSHJSON{Allowed: h.SSH.Allowed, Rules: sshRules},
		Sudo:        SudoJSON{Scope: h.Sudo.Scope, AllowCommands: h.Sudo.AllowCommands, DenyCommands: h.Sudo.DenyCommands, Rules: sudoRules},
		Annotations: h.Annotations,
	}
}
