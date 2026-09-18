package accessdirectory

import (
	"context"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// multiScopeProvider builds a fixture with four scopes:
//   - gpu: pilot-target-gpu={gpu-a,gpu-b,shared-a}, pilot-gateway-gpu={gw-gpu-01}
//   - dmz: pilot-target-dmz={dmz-a,shared-a}, pilot-gateway-dmz={gw-dmz-01}
//   - nogw: pilot-target-nogw={nogw-a}, NO matching pilot-gateway-nogw
//   - broken: pilot-target-broken exists for hostgroup_find but hostgroup_show
//     fails (simulates deletion between catalog load and per-scope resolve)
//
// alice is a member of gpu-users, dmz-users and nogw-users (sees all three
// working scopes, including shared-a via BOTH gpu and dmz); bob is only a
// member of gpu-users (sees gpu-a/gpu-b/shared-a, nothing else).
func multiScopeProvider() *fakeProvider {
	return &fakeProvider{
		users: map[string]freeipaaccess.User{
			"alice": {Username: "alice", Enabled: true, DirectGroups: []string{"ipausers", "gpu-users", "dmz-users", "nogw-users"}},
			"bob":   {Username: "bob", Enabled: true, DirectGroups: []string{"ipausers", "gpu-users"}},
		},
		hostgroups: map[string]freeipaaccess.Hostgroup{
			"pilot-target-gpu":    {Name: "pilot-target-gpu", MemberHosts: []string{"gpu-a.ipa.pilot.internal", "gpu-b.ipa.pilot.internal", "shared-a.ipa.pilot.internal"}},
			"pilot-target-dmz":    {Name: "pilot-target-dmz", MemberHosts: []string{"dmz-a.ipa.pilot.internal", "shared-a.ipa.pilot.internal"}},
			"pilot-target-nogw":   {Name: "pilot-target-nogw", MemberHosts: []string{"nogw-a.ipa.pilot.internal"}},
			"pilot-target-broken": {Name: "pilot-target-broken", MemberHosts: []string{"broken-a.ipa.pilot.internal"}},
			"pilot-gateway-gpu":   {Name: "pilot-gateway-gpu", MemberHosts: []string{"gw-gpu-01.ipa.pilot.internal"}},
			"pilot-gateway-dmz":   {Name: "pilot-gateway-dmz", MemberHosts: []string{"gw-dmz-01.ipa.pilot.internal"}},
		},
		hostgroupShowErr: map[string]error{
			"pilot-target-broken": &freeipaaccess.RPCError{Name: "NotFound", Message: "deleted mid-resolve"},
		},
		hbacRules: []freeipaaccess.HBACRule{
			{Name: "pilot-grant-login-gpu-test", Enabled: true, Groups: []string{"gpu-users"}, Hostgroups: []string{"pilot-target-gpu"}, Services: []string{"sshd"}},
			{Name: "pilot-grant-login-dmz-test", Enabled: true, Groups: []string{"dmz-users"}, Hostgroups: []string{"pilot-target-dmz"}, Services: []string{"sshd"}},
			{Name: "pilot-grant-login-nogw-test", Enabled: true, Groups: []string{"nogw-users"}, Hostgroups: []string{"pilot-target-nogw"}, Services: []string{"sshd"}},
			// Deliberately no rule references pilot-target-broken via
			// Hostgroups: accessportal.LoadPolicySnapshot eagerly expands
			// every hostgroup ANY HBAC/sudo rule references (global, not
			// per-scope), so a rule naming it would fail the shared
			// snapshot load itself rather than exercising what this
			// fixture is actually for — one scope's own
			// ResolveGatewayScope (target_hostgroup) lookup failing
			// inside the per-scope loop, via hostgroupShowErr below.
		},
	}
}

func TestLoadDirectoryAccess_MultiScopeUserSeesAllWorkingScopes(t *testing.T) {
	p := multiScopeProvider()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	access, err := LoadDirectoryAccess(context.Background(), p, p, "alice", "pilot-target-", "pilot-gateway-", now)
	if err != nil {
		t.Fatalf("LoadDirectoryAccess: %v", err)
	}

	byFQDN := map[string]DirectoryTarget{}
	for _, target := range access.Targets {
		byFQDN[target.FQDN] = target
	}

	for _, fqdn := range []string{"gpu-a.ipa.pilot.internal", "gpu-b.ipa.pilot.internal", "dmz-a.ipa.pilot.internal", "nogw-a.ipa.pilot.internal", "shared-a.ipa.pilot.internal"} {
		if _, ok := byFQDN[fqdn]; !ok {
			t.Errorf("expected alice to see %s, got targets %v", fqdn, byFQDN)
		}
	}
	// broken-a's scope failed to resolve — must not appear, and must not
	// have taken down the other three working scopes above.
	if _, ok := byFQDN["broken-a.ipa.pilot.internal"]; ok {
		t.Errorf("broken-a should not appear: its scope failed to resolve")
	}
}

func TestLoadDirectoryAccess_SharedTargetMergesIntoOneEntryWithTwoRoutes(t *testing.T) {
	p := multiScopeProvider()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	access, err := LoadDirectoryAccess(context.Background(), p, p, "alice", "pilot-target-", "pilot-gateway-", now)
	if err != nil {
		t.Fatalf("LoadDirectoryAccess: %v", err)
	}

	var shared *DirectoryTarget
	count := 0
	for i, target := range access.Targets {
		if target.FQDN == "shared-a.ipa.pilot.internal" {
			shared = &access.Targets[i]
			count++
		}
	}
	if count != 1 {
		t.Fatalf("shared-a.ipa.pilot.internal appeared %d times in Targets, want exactly 1 merged entry", count)
	}
	if len(shared.Routes) != 2 {
		t.Fatalf("shared-a Routes = %+v, want 2 (gpu and dmz)", shared.Routes)
	}
	if shared.Routes[0].Scope != "dmz" || shared.Routes[1].Scope != "gpu" {
		t.Fatalf("shared-a Routes = %+v, want sorted [dmz, gpu]", shared.Routes)
	}
	if !shared.SSH.Allowed {
		t.Fatalf("shared-a SSH.Allowed = false, want true")
	}

	// The shared host must only be HostShow'd once across both scopes'
	// resolves — the whole point of Phase 1's shared PolicySnapshot
	// (docs/tmp/now/spec.md §9.3).
	if got := p.hostShowCalls["shared-a.ipa.pilot.internal"]; got != 1 {
		t.Fatalf("HostShow(shared-a) called %d times across 2 scopes, want exactly 1", got)
	}
}

func TestLoadDirectoryAccess_NoGatewayScopeSurfacesRouteStatus(t *testing.T) {
	p := multiScopeProvider()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	access, err := LoadDirectoryAccess(context.Background(), p, p, "alice", "pilot-target-", "pilot-gateway-", now)
	if err != nil {
		t.Fatalf("LoadDirectoryAccess: %v", err)
	}

	var nogw *DirectoryTarget
	for i, target := range access.Targets {
		if target.FQDN == "nogw-a.ipa.pilot.internal" {
			nogw = &access.Targets[i]
		}
	}
	if nogw == nil {
		t.Fatalf("expected nogw-a.ipa.pilot.internal to appear (alice has HBAC access) even with no gateway")
	}
	if len(nogw.Routes) != 1 {
		t.Fatalf("nogw-a Routes = %+v, want exactly 1", nogw.Routes)
	}
	route := nogw.Routes[0]
	if route.RouteStatus != "no_gateway" {
		t.Fatalf("nogw-a RouteStatus = %q, want no_gateway", route.RouteStatus)
	}
	if len(route.GatewayCandidates) != 0 {
		t.Fatalf("nogw-a GatewayCandidates = %v, want empty", route.GatewayCandidates)
	}
	if route.GatewayHostgroup != "pilot-gateway-nogw" {
		t.Fatalf("nogw-a GatewayHostgroup = %q, want the expected-but-nonexistent pilot-gateway-nogw", route.GatewayHostgroup)
	}
}

func TestLoadDirectoryAccess_UserWithOnlyOneScopeSeesOnlyThatScope(t *testing.T) {
	p := multiScopeProvider()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	access, err := LoadDirectoryAccess(context.Background(), p, p, "bob", "pilot-target-", "pilot-gateway-", now)
	if err != nil {
		t.Fatalf("LoadDirectoryAccess: %v", err)
	}

	byFQDN := map[string]DirectoryTarget{}
	for _, target := range access.Targets {
		byFQDN[target.FQDN] = target
	}
	for _, fqdn := range []string{"gpu-a.ipa.pilot.internal", "gpu-b.ipa.pilot.internal", "shared-a.ipa.pilot.internal"} {
		if _, ok := byFQDN[fqdn]; !ok {
			t.Errorf("expected bob to see %s", fqdn)
		}
	}
	// bob is not in dmz-users/nogw-users — a target he has no HBAC access
	// to under EITHER scope must not appear at all (accessportal's
	// existing "My Hosts only lists SSH-allowed hosts" rule, inherited
	// for free from reusing ResolveScopeAccess).
	for _, fqdn := range []string{"dmz-a.ipa.pilot.internal", "nogw-a.ipa.pilot.internal"} {
		if _, ok := byFQDN[fqdn]; ok {
			t.Errorf("bob should not see %s (no HBAC access under any scope)", fqdn)
		}
	}
	// shared-a is a member of BOTH pilot-target-gpu and pilot-target-dmz
	// (dual-homed), and HBAC rules are global — bob's gpu-users rule
	// grants him shared-a regardless of which scope's host-set walk is
	// checking it, so it legitimately resolves as reachable via BOTH
	// scope routes even though bob is not a dmz-users member (this is an
	// existing accessportal property this package inherits unchanged,
	// not something Phase 3 introduces: a rule's Hostgroups only decides
	// which hosts a rule COULD apply to, never which "scope" invoked the
	// check).
	if got := len(byFQDN["shared-a.ipa.pilot.internal"].Routes); got != 2 {
		t.Fatalf("bob's shared-a Routes = %d, want 2 (dual-homed host, reachable via both scope walks)", got)
	}
}

// TestLoadDirectoryAccess_SharedSnapshotAcrossScopes proves spec.md §9.3's
// core requirement: LoadPolicySnapshot's own calls (UserShow,
// hbacrule_find, sudorule_find) happen exactly once per LoadDirectoryAccess
// call, no matter how many scopes are discovered and resolved against —
// never "M scopes × a full policy resolve".
func TestLoadDirectoryAccess_SharedSnapshotAcrossScopes(t *testing.T) {
	p := multiScopeProvider()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	if _, err := LoadDirectoryAccess(context.Background(), p, p, "alice", "pilot-target-", "pilot-gateway-", now); err != nil {
		t.Fatalf("LoadDirectoryAccess: %v", err)
	}

	if got := p.userShowCalls["alice"]; got != 1 {
		t.Errorf("UserShow(alice) called %d times, want exactly 1", got)
	}
	if p.hbacRuleFindCalls != 1 {
		t.Errorf("hbacrule_find called %d times, want exactly 1", p.hbacRuleFindCalls)
	}
	if p.sudoRuleFindCalls != 1 {
		t.Errorf("sudorule_find called %d times, want exactly 1", p.sudoRuleFindCalls)
	}
	// Every hostgroup's own HostgroupShow count must be a small FIXED
	// number, independent of how many total scopes exist (4 here) — never
	// "N scopes × a full resolve". A target hostgroup that some HBAC
	// rule's Hostgroups also names (gpu/dmz/nogw here) is legitimately
	// HostgroupShow'd twice: once by accessportal.LoadPolicySnapshot's
	// global expandReferencedHostgroups (building the rule-matching
	// HostgroupHosts map, shared across every scope) and once by that
	// one scope's own accessportal.ResolveGatewayScope (walking its
	// target_hostgroup's host set) — this pre-existing accessportal
	// double-fetch-of-the-same-name is not a Phase 3 regression (it
	// already happened for a single gateway before this package existed
	// whenever an HBAC rule's Hostgroups named that gateway's own
	// target_hostgroup, which is the normal way such rules are written);
	// it does NOT scale with the number of OTHER scopes in the catalog,
	// which is the property that actually matters here. Gateway-instance
	// hostgroups (never referenced by any HBAC rule) and a target
	// hostgroup no rule happens to reference (pilot-target-broken) are
	// HostgroupShow'd exactly once.
	want := map[string]int{
		"pilot-target-gpu":    2,
		"pilot-target-dmz":    2,
		"pilot-target-nogw":   2,
		"pilot-target-broken": 1,
		"pilot-gateway-gpu":   1,
		"pilot-gateway-dmz":   1,
	}
	for name, wantCount := range want {
		if got := p.hostgroupShowCalls[name]; got != wantCount {
			t.Errorf("HostgroupShow(%s) called %d times, want exactly %d", name, got, wantCount)
		}
	}
}

func TestLoadDirectoryAccess_OneBrokenScopeDoesNotFailTheWholeCall(t *testing.T) {
	p := multiScopeProvider()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	access, err := LoadDirectoryAccess(context.Background(), p, p, "alice", "pilot-target-", "pilot-gateway-", now)
	if err != nil {
		t.Fatalf("LoadDirectoryAccess returned an error because ONE scope (broken) failed: %v — other scopes must still resolve", err)
	}
	if len(access.Targets) == 0 {
		t.Fatalf("expected alice's working scopes (gpu/dmz/nogw) to still produce targets")
	}
}

func TestLoadDirectoryAccess_EveryScopeFailingIsAnError(t *testing.T) {
	p := &fakeProvider{
		users: map[string]freeipaaccess.User{
			"alice": {Username: "alice", Enabled: true, DirectGroups: []string{"gpu-users"}},
		},
		hostgroups: map[string]freeipaaccess.Hostgroup{
			"pilot-target-gpu": {Name: "pilot-target-gpu"},
		},
		hostgroupShowErr: map[string]error{
			"pilot-target-gpu": &freeipaaccess.RPCError{Name: "NotFound", Message: "gone"},
		},
		hbacRules: []freeipaaccess.HBACRule{
			{Name: "r", Enabled: true, Groups: []string{"gpu-users"}, Hostgroups: []string{"pilot-target-gpu"}, Services: []string{"sshd"}},
		},
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	_, err := LoadDirectoryAccess(context.Background(), p, p, "alice", "pilot-target-", "pilot-gateway-", now)
	if err == nil {
		t.Fatalf("expected an error when every discovered scope fails to resolve")
	}
}

func TestLoadDirectoryAccess_NoScopesIsEmptyNotError(t *testing.T) {
	p := &fakeProvider{
		users: map[string]freeipaaccess.User{
			"alice": {Username: "alice", Enabled: true},
		},
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	access, err := LoadDirectoryAccess(context.Background(), p, p, "alice", "pilot-target-", "pilot-gateway-", now)
	if err != nil {
		t.Fatalf("LoadDirectoryAccess with zero scopes: %v, want a valid empty result", err)
	}
	if len(access.Targets) != 0 {
		t.Fatalf("Targets = %+v, want empty", access.Targets)
	}
}

// TestLoadScopeCatalog_BrokenGatewayHostgroupDegradesOnlyThatScope proves
// LoadScopeCatalog isolates a gateway-instance hostgroup that
// HostgroupFind discovers but then fails to HostgroupShow (e.g. deleted
// concurrently) to that ONE scope's route degrading to "no_gateway" —
// it must NOT fail the whole catalog load and take every other scope's
// routing down with it (the same per-scope isolation principle
// LoadDirectoryAccess already applies to a broken TARGET hostgroup).
func TestLoadScopeCatalog_BrokenGatewayHostgroupDegradesOnlyThatScope(t *testing.T) {
	p := &fakeProvider{
		hostgroups: map[string]freeipaaccess.Hostgroup{
			"pilot-target-gpu": {Name: "pilot-target-gpu", MemberHosts: []string{"gpu-a.ipa.pilot.internal"}},
			"pilot-target-dmz": {Name: "pilot-target-dmz", MemberHosts: []string{"dmz-a.ipa.pilot.internal"}},
			// pilot-gateway-gpu is discoverable via HostgroupFind (present
			// in this map) but its HostgroupShow is forced to fail below —
			// simulating deletion between the find and the show.
			"pilot-gateway-gpu": {Name: "pilot-gateway-gpu", MemberHosts: []string{"gw-gpu-01.ipa.pilot.internal"}},
			"pilot-gateway-dmz": {Name: "pilot-gateway-dmz", MemberHosts: []string{"gw-dmz-01.ipa.pilot.internal"}},
		},
		hostgroupShowErr: map[string]error{
			"pilot-gateway-gpu": &freeipaaccess.RPCError{Name: "NotFound", Message: "deleted mid-resolve"},
		},
	}

	routes, err := LoadScopeCatalog(context.Background(), p, p, "pilot-target-", "pilot-gateway-")
	if err != nil {
		t.Fatalf("LoadScopeCatalog: %v, want no error — only the gpu scope's gateway lookup failed", err)
	}
	if len(routes) != 2 {
		t.Fatalf("routes = %+v, want 2 (gpu and dmz both still present)", routes)
	}

	byScope := map[string]ScopeRoute{}
	for _, r := range routes {
		byScope[r.Scope] = r
	}
	gpu, ok := byScope["gpu"]
	if !ok {
		t.Fatalf("expected a gpu route even though its gateway hostgroup failed to resolve")
	}
	if len(gpu.GatewayFQDNs) != 0 {
		t.Fatalf("gpu.GatewayFQDNs = %v, want empty (gateway hostgroup_show failed)", gpu.GatewayFQDNs)
	}
	if routeStatus(gpu) != "no_gateway" {
		t.Fatalf("routeStatus(gpu) = %q, want no_gateway", routeStatus(gpu))
	}

	dmz, ok := byScope["dmz"]
	if !ok {
		t.Fatalf("expected the dmz scope to be entirely unaffected by gpu's failure")
	}
	if len(dmz.GatewayFQDNs) != 1 || dmz.GatewayFQDNs[0] != "gw-dmz-01.ipa.pilot.internal" {
		t.Fatalf("dmz.GatewayFQDNs = %v, want [gw-dmz-01.ipa.pilot.internal]", dmz.GatewayFQDNs)
	}
}
