package accessportal

import (
	"context"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// TestResolveScopeAccess_SharesHostShowAcrossScopes proves the fix
// docs/tmp/now/spec.md §9.3 requires: a host that belongs to more than
// one gateway's target hostgroup must only be HostShow'd once for the
// whole PolicySnapshot's lifetime, no matter how many times
// ResolveScopeAccess is called against it — the multi-scope case
// pilot-access-directory needs and internal/accessportal's own
// single-scope Resolver never exercised before this refactor.
func TestResolveScopeAccess_SharesHostShowAcrossScopes(t *testing.T) {
	p := &fakeProvider{
		users: map[string]freeipaaccess.User{
			"alice": {Username: "alice", Enabled: true, DirectGroups: []string{"ipausers"}},
		},
		hostgroups: map[string]freeipaaccess.Hostgroup{
			"hg-a": {Name: "hg-a", MemberHosts: []string{"shared.ipa.pilot.internal", "a-only.ipa.pilot.internal"}},
			"hg-b": {Name: "hg-b", MemberHosts: []string{"shared.ipa.pilot.internal", "b-only.ipa.pilot.internal"}},
		},
		hbacRules: []freeipaaccess.HBACRule{
			{Name: "allow-all-test", Enabled: true, UserCategoryAll: true, HostCategoryAll: true, ServiceCategoryAll: true},
		},
		hosts: map[string]freeipaaccess.Host{
			"shared.ipa.pilot.internal": {FQDN: "shared.ipa.pilot.internal", Annotations: map[string]string{"owner": "platform"}},
		},
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	snapshot, err := LoadPolicySnapshot(context.Background(), p, "alice", now)
	if err != nil {
		t.Fatalf("LoadPolicySnapshot: %v", err)
	}

	accessA, err := ResolveScopeAccess(context.Background(), p, snapshot, GatewayConfig{ID: "gw-a", Scope: "a", TargetHostgroup: "hg-a"})
	if err != nil {
		t.Fatalf("ResolveScopeAccess(hg-a): %v", err)
	}
	accessB, err := ResolveScopeAccess(context.Background(), p, snapshot, GatewayConfig{ID: "gw-b", Scope: "b", TargetHostgroup: "hg-b"})
	if err != nil {
		t.Fatalf("ResolveScopeAccess(hg-b): %v", err)
	}

	if len(accessA.Hosts) != 2 || len(accessB.Hosts) != 2 {
		t.Fatalf("accessA.Hosts=%+v accessB.Hosts=%+v, want 2 hosts each", accessA.Hosts, accessB.Hosts)
	}
	if got := p.hostShowCalls["shared.ipa.pilot.internal"]; got != 1 {
		t.Fatalf("HostShow(shared.ipa.pilot.internal) called %d times across two scopes, want exactly 1 (snapshot-level dedup)", got)
	}
	if got := p.hostShowCalls["a-only.ipa.pilot.internal"]; got != 1 {
		t.Fatalf("HostShow(a-only) called %d times, want 1", got)
	}
	if got := p.hostShowCalls["b-only.ipa.pilot.internal"]; got != 1 {
		t.Fatalf("HostShow(b-only) called %d times, want 1", got)
	}

	// The cached annotation must still be the real one, not lost by dedup.
	for _, h := range accessB.Hosts {
		if h.FQDN == "shared.ipa.pilot.internal" && h.Annotations["owner"] != "platform" {
			t.Fatalf("shared host Annotations = %v, want owner=platform to survive the cache", h.Annotations)
		}
	}

	// Every call must reuse the exact same HBAC/sudo-find results — no
	// second full LoadUserAccess-style resolve happened for scope b.
	if len(p.hbacRules) != 1 {
		t.Fatalf("sanity: fixture drifted, expected exactly 1 hbac rule")
	}
}
