package gatewayapi

import (
	"context"
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
// fresh, per-request authorization decision (no cache, so resolver
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
	d := s.authorizeConnect(r.Context(), peer, req.Target)
	resp := d.resp
	deny := func(reason string) {
		resp = d.denied(reason)
		s.Metrics.authorizeDenied(reason)
		s.Logger.Info("connect authorize denied", "user", peer.Username, "target", resp.Target,
			"gateway_id", s.Gateway.ID, "reason_code", reason, "policy_reason", d.policyReason)
		writeJSON(w, http.StatusOK, resp)
	}
	switch {
	case d.metricReason == metricsReasonError || d.metricReason == metricsReasonAccessDenied:
		s.Metrics.authorizeDenied(d.metricReason)
		writeJSON(w, http.StatusOK, resp) // Allowed stays false.
		return
	case d.metricReason != "":
		deny(d.metricReason)
		return
	}

	pol := s.RecordingPolicy
	if isTerminalRecording(resp.RecordingMode) {
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
			Target: resp.Target, Mode: resp.RecordingMode, Source: resp.RecordingPolicySource,
		}, pol.MaxSessionDuration)
		if err != nil {
			s.Logger.Error("connect authorize: mint ingest token failed", "user", peer.Username, "target", resp.Target, "error", err)
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
	s.Metrics.authorizeAllowed(resp.RecordingMode, resp.RecordingPolicySource)
	writeJSON(w, http.StatusOK, resp)
}

// connectDecision is authorizeConnect's result. metricReason is "" when
// the connect is allowed so far, metricsReasonError / metricsReasonAccessDenied
// for a resolve failure / HBAC-scope deny, or a DenyReasonRecording* code
// when the target's recording policy cannot be resolved.
type connectDecision struct {
	resp         ConnectAuthorizeResponse
	metricReason string
	policyReason string
}

// denied is the response for a connect refused after authorizeConnect let
// it through (or for a recording-policy refusal): Allowed, rules, recording
// and transport fields all back to zero, with reason as DenyReason.
func (d connectDecision) denied(reason string) ConnectAuthorizeResponse {
	r := d.resp
	return ConnectAuthorizeResponse{
		Target: r.Target, Username: r.Username, GatewayID: r.GatewayID, GatewayScope: r.GatewayScope,
		CheckedAt: r.CheckedAt, DenyReason: reason,
	}
}

// authorizeConnect is the one HBAC ∩ gateway-scope decision every connect
// path shares — /v1/connect/authorize and /v1/transport/host-keys both
// call it, so there is exactly one authorization semantics
// (captive-transport spec §8.2), never a second ACL. It also resolves the
// target's effective recording mode (per-host recording spec §4), which the
// transport path's recording allowlist (captive-transport spec D8) reads.
// It never mints an ingest token and never counts metrics: only the
// connect path does.
func (s *Server) authorizeConnect(ctx context.Context, peer Peer, rawTarget string) connectDecision {
	target := accessportal.CanonicalizeFQDN(rawTarget)
	d := connectDecision{resp: ConnectAuthorizeResponse{
		Target: target, Username: peer.Username,
		GatewayID: s.Gateway.ID, GatewayScope: s.Gateway.Scope,
		CheckedAt: time.Now().UTC(),
	}}
	access, err := s.Resolver.LoadUserAccess(ctx, peer.Username)
	if err != nil {
		s.Logger.Error("connect authorize: resolve failed, denying", "user", peer.Username, "target", target, "error", err)
		d.metricReason = metricsReasonError
		return d // Allowed stays false.
	}
	var host *accessportal.HostAccess
	for i := range access.Hosts {
		if access.Hosts[i].FQDN == target && access.Hosts[i].SSH.Allowed {
			host = &access.Hosts[i]
			break
		}
	}
	if host == nil {
		d.metricReason = metricsReasonAccessDenied
		return d // HBAC/scope deny: Allowed stays false.
	}
	mode, source, err := ResolveRecordingMode(s.RecordingPolicy.DefaultMode, host.SSHRecording)
	switch {
	case errors.Is(err, ErrRecordingPolicyUnknown):
		d.metricReason, d.policyReason = DenyReasonRecordingPolicyUnavailable, host.SSHRecording.Reason
		d.resp = d.denied(d.metricReason)
		return d
	case err != nil:
		d.metricReason, d.policyReason = DenyReasonRecordingPolicyInvalid, host.SSHRecording.Reason
		d.resp = d.denied(d.metricReason)
		return d
	}
	d.resp.Allowed = true
	for _, rs := range host.SSH.Rules {
		d.resp.Rules = append(d.resp.Rules, rs.Rule)
	}
	d.resp.RecordingMode = mode
	d.resp.RecordingPolicySource = source
	s.applyTransportGate(ctx, &d.resp)
	return d
}

// applyTransportGate sets TransportAllowed only when this gateway enables
// transport AND the (already authorized) target is a member of
// TransportReadyHostgroup, direct or nested. Any lookup failure fails
// closed. Disabled gateways never touch FreeIPA for this.
func (s *Server) applyTransportGate(ctx context.Context, resp *ConnectAuthorizeResponse) {
	if !s.Transport.Enabled {
		resp.TransportDenyReason = TransportDenyDisabled
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
	d := s.authorizeConnect(r.Context(), peer, req.Target)
	if d.metricReason == DenyReasonRecordingPolicyUnavailable {
		// The target's FreeIPA host entry could not be read, so neither its
		// recording policy nor its keys are known: the same 503 as a failed
		// host_show below, not a denial.
		s.Logger.Error("transport host keys: host policy unreadable", "user", peer.Username, "target", d.resp.Target, "policy_reason", d.policyReason)
		writeError(w, http.StatusServiceUnavailable, "access service unavailable")
		return
	}
	authz := d.resp
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
