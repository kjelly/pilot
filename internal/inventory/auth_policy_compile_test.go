package inventory

import (
	"reflect"
	"testing"
)

func TestCompileAuthPolicies_ResolvesHostgroupToHosts(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: production-strong-auth
    targets: {hosts: [], hostgroups: [production-db]}
    require_any: [otp, pkinit]
`)
	// grantsRosterBase's production-db hostgroup has no membership.hosts
	// declared by default — populate it here so this test exercises real
	// hostgroup->host resolution rather than an always-empty set.
	hostgroups := listField(root, "hostgroups")
	productionDB := asMap(hostgroups[0])
	productionDB["membership"] = map[string]any{"hosts": []any{"db-special.ipa.pilot.internal"}}

	got := CompileAuthPolicies(root)
	want := []CompiledAuthPolicyHost{
		{Host: "db-special.ipa.pilot.internal", Indicators: []string{"otp", "pkinit"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestCompileAuthPolicies_UnionsMultiplePoliciesOnSameHost(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: policy-a
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    require_any: [otp]
  - name: policy-b
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    require_any: [pkinit]
`)
	got := CompileAuthPolicies(root)
	want := []CompiledAuthPolicyHost{
		{Host: "db-special.ipa.pilot.internal", Indicators: []string{"otp", "pkinit"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// §9.2's "no silent downgrade" (v3.1): removing one of two policies that
// both reach the same host must shrink the compiled union to exactly the
// remaining policy's indicators — neither leaving a stale indicator behind
// (too permissive) nor dropping the host entirely (too strict, and
// indistinguishable from "nothing requires strong auth here" — see
// CompileAuthPolicies' Present/Indicators shape, mirrored by
// pilot_compiled_account_expirations' explicit-clear convention).
func TestCompileAuthPolicies_RemovingOnePolicyShrinksUnionWithoutDroppingHost(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: policy-a
    state: absent
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    require_any: [otp]
  - name: policy-b
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    require_any: [pkinit]
`)
	got := CompileAuthPolicies(root)
	want := []CompiledAuthPolicyHost{
		{Host: "db-special.ipa.pilot.internal", Indicators: []string{"pkinit"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestCompileAuthPolicies_IgnoresAbsentPolicy(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: retired-policy
    state: absent
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    require_any: [otp]
`)
	if got := CompileAuthPolicies(root); len(got) != 0 {
		t.Fatalf("expected an absent policy to contribute nothing, got: %+v", got)
	}
}

func TestCompileAuthPolicies_NoPoliciesYieldsEmpty(t *testing.T) {
	root := grantsRoster(t, "")
	if got := CompileAuthPolicies(root); len(got) != 0 {
		t.Fatalf("expected no compiled hosts when there are no auth_policies, got: %+v", got)
	}
}
