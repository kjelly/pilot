package accessportal

import (
	"context"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// --- Managed hosts: nested hostgroup, duplicate, cycle, trailing dot ---
// Values below are the real captures from the deliberately cyclic
// hg-parent ⊂ hg-child ⊂ hg-parent pair (docs/evidence/pilot-access-gateway/
// 2026-09-14-phase2-accessportal.md), not invented.

func TestResolveGatewayScope_NestedAndCycle(t *testing.T) {
	p := &fakeProvider{
		hostgroups: map[string]freeipaaccess.Hostgroup{
			"hg-parent": {
				Name:             "hg-parent",
				MemberHostgroups: []string{"hg-child"},
				// FreeIPA's own server-side transitive closure, verified
				// live to terminate correctly despite the cycle.
				IndirectMemberHosts: []string{"leaf-host.ipa.pilot.internal", "leaf-host.ipa.pilot.internal", "Leaf-Host.IPA.PILOT.INTERNAL."},
			},
		},
	}
	r := NewResolver(p, GatewayConfig{ID: "t-01", Scope: "t", TargetHostgroup: "hg-parent"})
	scope, err := r.ResolveGatewayScope(context.Background())
	if err != nil {
		t.Fatalf("ResolveGatewayScope: %v", err)
	}
	// duplicate + a differently-cased/trailing-dot variant of the same
	// host must collapse to exactly one canonical entry (spec.md §14).
	if len(scope.Hosts) != 1 {
		t.Fatalf("Hosts = %v, want exactly 1 canonicalized entry", scope.Hosts)
	}
	if _, ok := scope.Hosts["leaf-host.ipa.pilot.internal"]; !ok {
		t.Fatalf("Hosts = %v, want leaf-host.ipa.pilot.internal", scope.Hosts)
	}
}

func TestResolveGatewayScope_MissingHostgroupFailsClosed(t *testing.T) {
	p := &fakeProvider{hostgroups: map[string]freeipaaccess.Hostgroup{}}
	r := NewResolver(p, GatewayConfig{ID: "t-01", Scope: "t", TargetHostgroup: "does-not-exist"})
	if _, err := r.ResolveGatewayScope(context.Background()); err == nil {
		t.Fatalf("expected an error for a missing target_hostgroup (spec.md §9.5 fail closed)")
	}
}

// --- User groups: direct, nested (multi-level), duplicate, cycle ---
// bob's real captured membership: direct=[ipausers,group-c],
// indirect=[group-b,group-a] via group-c ⊂ group-b ⊂ group-a, with a
// deliberate cycle (group-a re-nested under group-c) that FreeIPA's
// memberof plugin absorbed without corrupting the result.

func TestResolveUserContext_NestedGroupsAndCycle(t *testing.T) {
	p := &fakeProvider{
		users: map[string]freeipaaccess.User{
			"bob": {
				Username:       "bob",
				Enabled:        true,
				DirectGroups:   []string{"ipausers", "group-c"},
				IndirectGroups: []string{"group-b", "group-a"},
			},
		},
	}
	r := NewResolver(p, GatewayConfig{ID: "t-01", Scope: "t", TargetHostgroup: "irrelevant"})
	uc, err := r.ResolveUserContext(context.Background(), "bob")
	if err != nil {
		t.Fatalf("ResolveUserContext: %v", err)
	}
	want := map[string]bool{"ipausers": true, "group-c": true, "group-b": true, "group-a": true}
	if len(uc.EffectiveGroups) != len(want) {
		t.Fatalf("EffectiveGroups = %v, want %v", uc.EffectiveGroups, want)
	}
	for _, g := range uc.EffectiveGroups {
		if !want[g] {
			t.Fatalf("unexpected group %q in EffectiveGroups %v", g, uc.EffectiveGroups)
		}
	}
}

// --- End-to-end scenario using the real gpu/alice fixtures ---
// (docs/evidence/pilot-access-gateway/2026-09-14-phase1-freeipaaccess.md,
// 2026-09-14-phase2-accessportal.md): alice ∈ gpu-users; pilot-target-gpu
// = {gpu-a, gpu-b}; pilot-grant-login-gpu-test grants gpu-users→
// pilot-target-gpu→sshd; pilot-grant-sudo-gpu-test grants gpu-users→
// pilot-target-gpu limited sudo (allow: systemctl status nginx + a command
// group, deny: reboot), active 2026-01-01..2027-01-01.

func gpuScenarioProvider() *fakeProvider {
	return &fakeProvider{
		users: map[string]freeipaaccess.User{
			"alice": {Username: "alice", Enabled: true, DirectGroups: []string{"ipausers", "gpu-users"}},
		},
		hostgroups: map[string]freeipaaccess.Hostgroup{
			"pilot-target-gpu": {Name: "pilot-target-gpu", MemberHosts: []string{"gpu-a.ipa.pilot.internal", "gpu-b.ipa.pilot.internal"}},
		},
		hbacRules: []freeipaaccess.HBACRule{
			{
				Name: "pilot-grant-login-gpu-test", Enabled: true,
				Groups: []string{"gpu-users"}, Hostgroups: []string{"pilot-target-gpu"},
				Services: []string{"sshd"},
			},
		},
		sudoRules: []freeipaaccess.SudoRule{
			{
				Name: "pilot-grant-sudo-gpu-test", Enabled: true,
				Groups: []string{"gpu-users"}, Hostgroups: []string{"pilot-target-gpu"},
				AllowCommands:      []string{"/usr/bin/systemctl status nginx"},
				AllowCommandGroups: []string{"test-sudocmdgroup"},
				DenyCommands:       []string{"/usr/bin/reboot"},
				NotBefore:          timePtr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
				NotAfter:           timePtr(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
		},
		sudoCommandGroups: map[string]freeipaaccess.SudoCommandGroup{
			"test-sudocmdgroup": {Name: "test-sudocmdgroup", Commands: []string{"/usr/bin/systemctl status nginx"}},
		},
	}
}

func timePtr(t time.Time) *time.Time { return &t }

func TestLoadUserAccess_GPUScenario(t *testing.T) {
	p := gpuScenarioProvider()
	r := &Resolver{
		Provider: p,
		Gateway:  GatewayConfig{ID: "gpu-01", Scope: "gpu", TargetHostgroup: "pilot-target-gpu"},
		Now:      func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) },
	}
	access, err := r.LoadUserAccess(context.Background(), "alice")
	if err != nil {
		t.Fatalf("LoadUserAccess: %v", err)
	}
	if len(access.Hosts) != 2 {
		t.Fatalf("Hosts = %+v, want 2", access.Hosts)
	}
	for _, h := range access.Hosts {
		if !h.SSH.Allowed {
			t.Fatalf("host %s: SSH not allowed, want allowed via gpu-users", h.FQDN)
		}
		if h.SSH.Rules[0].Rule != "pilot-grant-login-gpu-test" || len(h.SSH.Rules[0].ViaGroups) != 1 || h.SSH.Rules[0].ViaGroups[0] != "gpu-users" {
			t.Fatalf("host %s: SSH.Rules = %+v", h.FQDN, h.SSH.Rules)
		}
		if h.Sudo.Scope != "limited" {
			t.Fatalf("host %s: Sudo.Scope = %q, want limited", h.FQDN, h.Sudo.Scope)
		}
		wantAllow := map[string]bool{"/usr/bin/systemctl status nginx": true}
		if len(h.Sudo.AllowCommands) != len(wantAllow) || !wantAllow[h.Sudo.AllowCommands[0]] {
			t.Fatalf("host %s: AllowCommands = %v", h.FQDN, h.Sudo.AllowCommands)
		}
		if len(h.Sudo.DenyCommands) != 1 || h.Sudo.DenyCommands[0] != "/usr/bin/reboot" {
			t.Fatalf("host %s: DenyCommands = %v", h.FQDN, h.Sudo.DenyCommands)
		}
	}
}

// unmanagedHost is deliberately NOT a member of pilot-target-gpu — spec.md
// §14: "任何 host不在此 expansion中: 不可顯示/不可 detail/不可 Connect，
// 即使 FreeIPA HBAC對該 host為 allow". Simulated by widening the HBAC rule
// to hostcategory=all (which would match literally any host) while the
// gateway's own target hostgroup still only contains gpu-a/gpu-b: the
// unmanaged host must still never appear.
// TestLoadUserAccess_Annotations proves LoadUserAccess enriches each
// allowed host with its host_show-derived annotations (docs/superpowers/
// specs/2026-09-09-host-annotations-freeipa-sync-spec.md), and that a host
// with none gets a nil map rather than an error.
func TestLoadUserAccess_Annotations(t *testing.T) {
	p := gpuScenarioProvider()
	p.hosts = map[string]freeipaaccess.Host{
		"gpu-a.ipa.pilot.internal": {
			FQDN:         "gpu-a.ipa.pilot.internal",
			Annotations:  map[string]string{"owner": "ai-platform-team", "project": "alpha"},
			SSHRecording: freeipaaccess.HostRecordingPolicy{Valid: true},
		},
	}
	r := &Resolver{
		Provider: p,
		Gateway:  GatewayConfig{ID: "gpu-01", Scope: "gpu", TargetHostgroup: "pilot-target-gpu"},
		Now:      func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) },
	}
	access, err := r.LoadUserAccess(context.Background(), "alice")
	if err != nil {
		t.Fatalf("LoadUserAccess: %v", err)
	}
	byFQDN := map[string]HostAccess{}
	for _, h := range access.Hosts {
		byFQDN[h.FQDN] = h
	}
	gotA := byFQDN["gpu-a.ipa.pilot.internal"].Annotations
	wantA := map[string]string{"owner": "ai-platform-team", "project": "alpha"}
	if len(gotA) != len(wantA) || gotA["owner"] != wantA["owner"] || gotA["project"] != wantA["project"] {
		t.Fatalf("gpu-a Annotations = %v, want %v", gotA, wantA)
	}
	if got := byFQDN["gpu-b.ipa.pilot.internal"].Annotations; len(got) != 0 {
		t.Fatalf("gpu-b Annotations = %v, want none (host_show returned no userclass)", got)
	}
}

// TestLoadUserAccess_HostShowFailureDoesNotBreakListing proves annotations
// are enrichment, not an authorization input: a host_show error for one
// host must not take down the whole My Hosts listing the way an HBAC/sudo
// resolution failure would (host still appears, SSH/Sudo access intact,
// simply no Annotations).
func TestLoadUserAccess_HostShowFailureDoesNotBreakListing(t *testing.T) {
	p := gpuScenarioProvider()
	p.hostShowErr = map[string]error{
		"gpu-a.ipa.pilot.internal": &freeipaaccess.RPCError{Name: "NotFound", Message: "transient"},
	}
	r := &Resolver{
		Provider: p,
		Gateway:  GatewayConfig{ID: "gpu-01", Scope: "gpu", TargetHostgroup: "pilot-target-gpu"},
		Now:      func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) },
	}
	access, err := r.LoadUserAccess(context.Background(), "alice")
	if err != nil {
		t.Fatalf("LoadUserAccess: %v, want no error despite host_show failing for one host", err)
	}
	if len(access.Hosts) != 2 {
		t.Fatalf("Hosts = %+v, want 2 (host_show failure must not drop the host)", access.Hosts)
	}
	for _, h := range access.Hosts {
		if h.FQDN == "gpu-a.ipa.pilot.internal" {
			if len(h.Annotations) != 0 {
				t.Fatalf("gpu-a Annotations = %v, want none after host_show error", h.Annotations)
			}
			if !h.SSH.Allowed {
				t.Fatalf("gpu-a SSH.Allowed = false, want true — host_show failure must not affect authorization")
			}
		}
	}
}

func TestLoadUserAccess_UnmanagedHostExcludedEvenWithHostCategoryAll(t *testing.T) {
	p := gpuScenarioProvider()
	p.hbacRules[0].HostCategoryAll = true
	p.hbacRules[0].Hostgroups = nil
	r := &Resolver{Provider: p, Gateway: GatewayConfig{ID: "gpu-01", Scope: "gpu", TargetHostgroup: "pilot-target-gpu"}}
	access, err := r.LoadUserAccess(context.Background(), "alice")
	if err != nil {
		t.Fatalf("LoadUserAccess: %v", err)
	}
	for _, h := range access.Hosts {
		if h.FQDN != "gpu-a.ipa.pilot.internal" && h.FQDN != "gpu-b.ipa.pilot.internal" {
			t.Fatalf("unmanaged host %q leaked into access result", h.FQDN)
		}
	}
	if len(access.Hosts) != 2 {
		t.Fatalf("Hosts = %+v, want exactly the 2 gateway-scoped hosts", access.Hosts)
	}
}

// --- Focused HBAC matrix cells not covered by the scenario above ---

func TestHBACRuleGrants_Matrix(t *testing.T) {
	hostgroupHosts := map[string]map[string]struct{}{
		"hg1": {"h1.example.com": {}},
	}
	serviceGroupServices := map[string]map[string]struct{}{
		"svcgrp1": {"sshd": {}},
	}
	effectiveGroups := map[string]struct{}{"g1": {}}

	cases := []struct {
		name string
		rule freeipaaccess.HBACRule
		want bool
	}{
		{"direct user", freeipaaccess.HBACRule{Enabled: true, Users: []string{"alice"}, Hosts: []string{"h1.example.com"}, Services: []string{"sshd"}}, true},
		{"user group", freeipaaccess.HBACRule{Enabled: true, Groups: []string{"g1"}, Hosts: []string{"h1.example.com"}, Services: []string{"sshd"}}, true},
		{"usercategory all", freeipaaccess.HBACRule{Enabled: true, UserCategoryAll: true, Hosts: []string{"h1.example.com"}, Services: []string{"sshd"}}, true},
		{"hostgroup", freeipaaccess.HBACRule{Enabled: true, Users: []string{"alice"}, Hostgroups: []string{"hg1"}, Services: []string{"sshd"}}, true},
		{"hostcategory all", freeipaaccess.HBACRule{Enabled: true, Users: []string{"alice"}, HostCategoryAll: true, Services: []string{"sshd"}}, true},
		{"servicecategory all", freeipaaccess.HBACRule{Enabled: true, Users: []string{"alice"}, Hosts: []string{"h1.example.com"}, ServiceCategoryAll: true}, true},
		{"service group", freeipaaccess.HBACRule{Enabled: true, Users: []string{"alice"}, Hosts: []string{"h1.example.com"}, ServiceGroups: []string{"svcgrp1"}}, true},
		{"disabled rule never grants", freeipaaccess.HBACRule{Enabled: false, UserCategoryAll: true, HostCategoryAll: true, ServiceCategoryAll: true}, false},
		{"no matching user", freeipaaccess.HBACRule{Enabled: true, Users: []string{"someone-else"}, Hosts: []string{"h1.example.com"}, Services: []string{"sshd"}}, false},
		{"no matching host", freeipaaccess.HBACRule{Enabled: true, Users: []string{"alice"}, Hosts: []string{"other-host.example.com"}, Services: []string{"sshd"}}, false},
		{"no matching service", freeipaaccess.HBACRule{Enabled: true, Users: []string{"alice"}, Hosts: []string{"h1.example.com"}, Services: []string{"ftp"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := hbacRuleGrants(c.rule, "alice", effectiveGroups, "h1.example.com", hostgroupHosts, "sshd", serviceGroupServices)
			if got != c.want {
				t.Fatalf("hbacRuleGrants = %v, want %v", got, c.want)
			}
		})
	}
}

// --- Focused sudo matrix cells: time window + no-rule + cmdcategory all ---

func TestSudoRuleActive_TimeWindow(t *testing.T) {
	base := freeipaaccess.SudoRule{Enabled: true}
	cases := []struct {
		name string
		rule freeipaaccess.SudoRule
		now  time.Time
		want bool
	}{
		{"no window, active", base, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"disabled", freeipaaccess.SudoRule{Enabled: false}, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{"notBefore future", withWindow(base, ptrTime(2027, 1, 1), nil), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{"notAfter expired", withWindow(base, nil, ptrTime(2025, 1, 1)), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{"active window", withWindow(base, ptrTime(2026, 1, 1), ptrTime(2027, 1, 1)), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sudoRuleActive(c.rule, c.now); got != c.want {
				t.Fatalf("sudoRuleActive = %v, want %v", got, c.want)
			}
		})
	}
}

func ptrTime(y, m, d int) *time.Time {
	t := time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC)
	return &t
}

func withWindow(r freeipaaccess.SudoRule, before, after *time.Time) freeipaaccess.SudoRule {
	r.NotBefore = before
	r.NotAfter = after
	return r
}

func TestSudoDisplayScope(t *testing.T) {
	cases := []struct {
		name                                       string
		hasAnyRule, anyCommandCategoryAll, anyDeny bool
		want                                       string
	}{
		{"no rule", false, false, false, "none"},
		{"limited", true, false, false, "limited"},
		{"all", true, true, false, "all"},
		{"all with deny", true, true, true, "all_with_deny"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sudoDisplayScope(c.hasAnyRule, c.anyCommandCategoryAll, c.anyDeny); got != c.want {
				t.Fatalf("sudoDisplayScope = %q, want %q", got, c.want)
			}
		})
	}
}
