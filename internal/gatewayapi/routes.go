package gatewayapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/ingesttoken"
)

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/identity", s.handleIdentity)
	mux.HandleFunc("GET /v1/access", s.handleAccess)
	mux.HandleFunc("GET /v1/access/{fqdn}", s.handleAccessHost)
	mux.HandleFunc("POST /v1/connect/authorize", s.handleConnectAuthorize)
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
	writeJSON(w, http.StatusOK, toAccessResponse(peer.Username, s.gatewayInfo(), access, s.RecordingPolicy.DefaultMode))
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
			writeJSON(w, http.StatusOK, toHostJSON(h, s.RecordingPolicy.DefaultMode))
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
//
// Allowed is set only after the target passes HBAC/scope AND its recording
// policy resolves AND, for a recording mode, the recording backend and
// session id are usable (per-host recording spec §15.2). Only terminal
// modes receive session-store coordinates and a per-session ingest token.
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
	target := accessportal.CanonicalizeFQDN(req.Target)
	resp := ConnectAuthorizeResponse{
		Target: target, Username: peer.Username,
		GatewayID: s.Gateway.ID, GatewayScope: s.Gateway.Scope,
		CheckedAt: time.Now().UTC(),
	}
	access, err := s.Resolver.LoadUserAccess(r.Context(), peer.Username)
	if err != nil {
		s.Logger.Error("connect authorize: resolve failed, denying", "user", peer.Username, "target", target, "error", err)
		writeJSON(w, http.StatusOK, resp) // Allowed stays false.
		return
	}
	var host *accessportal.HostAccess
	for i := range access.Hosts {
		if access.Hosts[i].FQDN == target && access.Hosts[i].SSH.Allowed {
			host = &access.Hosts[i]
			break
		}
	}
	if host == nil {
		writeJSON(w, http.StatusOK, resp) // HBAC/scope deny: Allowed stays false.
		return
	}

	deny := func(reason string) {
		resp.DenyReason = reason
		s.Logger.Info("connect authorize denied", "user", peer.Username, "target", target,
			"gateway_id", s.Gateway.ID, "reason_code", reason, "policy_reason", host.SSHRecording.Reason)
		writeJSON(w, http.StatusOK, resp)
	}
	mode, source, err := ResolveRecordingMode(s.RecordingPolicy.DefaultMode, host.SSHRecording)
	switch {
	case errors.Is(err, ErrRecordingPolicyUnknown):
		deny(DenyReasonRecordingPolicyUnavailable)
		return
	case err != nil:
		deny(DenyReasonRecordingPolicyInvalid)
		return
	}

	pol := s.RecordingPolicy
	if isTerminalRecording(mode) {
		if pol.SessionStoreURL == "" || pol.Signer == nil {
			deny(DenyReasonRecordingBackend)
			return
		}
		if !validSessionID(req.SessionID) {
			deny(DenyReasonRecordingSessionID)
			return
		}
		token, err := pol.Signer.Mint(ingesttoken.Claims{
			SessionID: req.SessionID, User: peer.Username, Gateway: s.Gateway.ID, Scope: s.Gateway.Scope,
			Target: target, Mode: mode, Source: source,
		}, pol.MaxSessionDuration)
		if err != nil {
			s.Logger.Error("connect authorize: mint ingest token failed", "user", peer.Username, "target", target, "error", err)
			deny(DenyReasonRecordingBackend)
			return
		}
		resp.RecordingFailurePolicy = pol.FailurePolicy
		resp.RecordingQueueEvents = pol.QueueEvents
		resp.RecordingFlushIntervalMS = pol.FlushIntervalMS
		resp.RecordingFailureGraceMS = pol.FailureGraceMS
		resp.RecordingSessionStoreURL = pol.SessionStoreURL
		resp.RecordingSessionStoreCAFile = pol.SessionStoreCAFile
		resp.RecordingSessionStoreIngestToken = token
	}

	resp.Allowed = true
	for _, rs := range host.SSH.Rules {
		resp.Rules = append(resp.Rules, rs.Rule)
	}
	resp.RecordingMode = mode
	resp.RecordingPolicySource = source
	writeJSON(w, http.StatusOK, resp)
}

// validSessionID reports whether id is a canonical UUID (the only form
// the one-shot and interactive connect paths generate).
func validSessionID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil && len(id) == 36
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

func toAccessResponse(username string, gw GatewayInfo, access accessportal.UserAccess, recordingDefault string) AccessResponse {
	resp := AccessResponse{User: username, Gateway: gw, GeneratedAt: access.GeneratedAt, Hosts: []HostJSON{}}
	resp.RecordingDefault = recordingDefault
	if resp.RecordingDefault == "" {
		resp.RecordingDefault = recordingModeMetadata
	}
	for _, h := range access.Hosts {
		resp.Hosts = append(resp.Hosts, toHostJSON(h, recordingDefault))
	}
	return resp
}

func toHostJSON(h accessportal.HostAccess, recordingDefault string) HostJSON {
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
		Recording:   toRecordingJSON(h.SSHRecording, recordingDefault),
	}
}

// toRecordingJSON reports the host's policy status and, when it resolves,
// the effective mode a connect would use right now.
func toRecordingJSON(p accessportal.SSHRecordingAccessPolicy, recordingDefault string) RecordingJSON {
	out := RecordingJSON{Status: p.Status()}
	if mode, _, err := ResolveRecordingMode(recordingDefault, p); err == nil {
		out.Effective = mode
	}
	return out
}
