package gatewayapi

import (
	"encoding/json"
	"net/http"
	"os/user"
	"testing"
)

// TestHandleIdentity_PortalUserGroupUnsetAllowsAnyone confirms the
// default (no PortalUserGroup configured) behavior is unchanged: any
// resolved peer is served, matching Phase 3's original contract.
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
// must deny access, not silently allow it — this is the defense-in-depth
// property Server.PortalUserGroup's doc comment describes (compensating
// for a same-named local group silently shadowing a real FreeIPA one,
// found via live vm-target testing — not a systemd limitation).
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

// TestHandleHealth_IgnoresPortalUserGroup proves /v1/health is never
// gated by PortalUserGroup — it is an ops probe with no per-user concept
// (spec.md §22.5), and Phase 7's own apply playbook calls it as root,
// which is never expected to be a portal_user_group member.
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

// TestHandleIdentity_PortalUserGroupHeldByPeerAllows is the positive case
// the old member-list check could not express: the peer process carries
// the configured group (here, its own primary group) in its kernel
// credentials, so it is served — the same fact SocketGroup= honors.
func TestHandleIdentity_PortalUserGroupHeldByPeerAllows(t *testing.T) {
	g := currentPrimaryGroupName(t)
	client, base := testServerWithConfig(t, currentUsername(t), func(s *Server) { s.PortalUserGroup = g })
	resp, err := client.Get(base + "/v1/identity")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 when the peer holds %s", resp.StatusCode, g)
	}
}

func currentPrimaryGroupName(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current unavailable: %v", err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("LookupGroupId unavailable: %v", err)
	}
	return g.Name
}
