package directoryapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/user"
	"testing"
)

// TestHandleIdentity_PortalUserGroupUnsetAllowsAnyone confirms the
// default (no PortalUserGroup configured) behavior: any resolved peer is
// served.
func TestHandleIdentity_PortalUserGroupUnsetAllowsAnyone(t *testing.T) {
	client, base := testServer(t, currentUsername(t))
	resp, err := client.Get(base + "/v1/identity")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 when PortalUserGroup is unset", resp.StatusCode)
	}
}

// TestHandleIdentity_PortalUserGroupUnknownGroupDenies proves the
// group-gate fails closed: a configured group that doesn't even resolve
// must deny access, not silently allow it — mirrors
// internal/gatewayapi's identically-named test and the hazard its
// PortalUserGroup doc comment describes (a same-named local group
// silently shadowing a real FreeIPA one).
func TestHandleIdentity_PortalUserGroupUnknownGroupDenies(t *testing.T) {
	client, base := testServerWithConfig(t, currentUsername(t), func(s *Server) {
		s.PortalUserGroup = "this-group-does-not-exist-98765"
	})
	resp, err := client.Get(base + "/v1/identity")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 when the configured group doesn't resolve", resp.StatusCode)
	}
}

// TestHandleAccess_PortalUserGroupUnknownGroupDenies is the same
// fail-closed check against /v1/access (not just /v1/identity).
func TestHandleAccess_PortalUserGroupUnknownGroupDenies(t *testing.T) {
	client, base := testServerWithConfig(t, currentUsername(t), func(s *Server) {
		s.PortalUserGroup = "this-group-does-not-exist-98765"
	})
	resp, err := client.Get(base + "/v1/access")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// TestHandleConnectResolve_PortalUserGroupUnknownGroupDenies is the same
// fail-closed check against POST /v1/connect/resolve — a valid,
// otherwise-would-succeed request must still be denied before it ever
// reaches the resolve logic.
func TestHandleConnectResolve_PortalUserGroupUnknownGroupDenies(t *testing.T) {
	client, base := testServerWithConfig(t, currentUsername(t), func(s *Server) {
		s.PortalUserGroup = "this-group-does-not-exist-98765"
	})
	body, _ := json.Marshal(ConnectResolveRequest{Target: "gpu-a.example.com"})
	resp, err := client.Post(base+"/v1/connect/resolve", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// TestHandleHealth_IgnoresPortalUserGroup proves /v1/health is never
// gated by PortalUserGroup — it is an ops probe with no per-user concept.
func TestHandleHealth_IgnoresPortalUserGroup(t *testing.T) {
	client, base := testServerWithConfig(t, currentUsername(t), func(s *Server) {
		s.PortalUserGroup = "this-group-does-not-exist-98765"
	})
	resp, err := client.Get(base + "/v1/health")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (health is never portal-user-group gated)", resp.StatusCode)
	}
	var got HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != "ok" {
		t.Fatalf("Status = %q", got.Status)
	}
}

// TestHandleIdentity_PortalUserGroupHeldByPeerAllows: the peer process
// carries the configured group (its own primary group) in its kernel
// credentials, so it is served (identity.PeerInGroup).
func TestHandleIdentity_PortalUserGroupHeldByPeerAllows(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current unavailable: %v", err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("LookupGroupId unavailable: %v", err)
	}
	client, base := testServerWithConfig(t, currentUsername(t), func(s *Server) { s.PortalUserGroup = g.Name })
	resp, err := client.Get(base + "/v1/identity")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 when the peer holds %s", resp.StatusCode, g.Name)
	}
}
