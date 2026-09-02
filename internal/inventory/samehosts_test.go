package inventory

import (
	"reflect"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

func TestSameHostsDependencyRoles(t *testing.T) {
	contracts := []contract.Contract{
		{ID: "wazuh-manager", Role: "wazuh-manager", Dependencies: []contract.Dependency{
			{Component: "docker", Required: true, Relation: "sameHosts"},
			{Component: "log-server", Required: false, Relation: "providerEndpoint"},
		}},
		{ID: "docker", Role: "docker"},
		{ID: "log-server", Role: "log-server"},
		{ID: "freeipa-client", Role: "freeipa-client", Dependencies: []contract.Dependency{
			{Component: "freeipa-server", Required: true, Relation: "providerEndpoint"},
		}},
		{ID: "freeipa-server", Role: "freeipa-server"},
	}

	got := SameHostsDependencyRoles(contracts)
	want := map[string][]string{"wazuh-manager": {"docker"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SameHostsDependencyRoles() = %#v, want %#v", got, want)
	}
}

func TestSameHostsDependencyRoles_IgnoresOptionalAndUnknownDependency(t *testing.T) {
	contracts := []contract.Contract{
		{ID: "a", Role: "a", Dependencies: []contract.Dependency{
			{Component: "b", Required: false, Relation: "sameHosts"},
			{Component: "missing", Required: true, Relation: "sameHosts"},
		}},
		{ID: "b", Role: "b"},
	}
	if got := SameHostsDependencyRoles(contracts); len(got) != 0 {
		t.Fatalf("SameHostsDependencyRoles() = %#v, want empty", got)
	}
}

func TestExpandSameHostsRoles_DirectAndTransitiveClosure(t *testing.T) {
	deps := map[string][]string{
		"wazuh-manager": {"docker"},
		"dashboard":     {"docker", "reverse-proxy"},
	}
	hosts := []Host{
		{Name: "a", Roles: []string{"wazuh-manager"}},
		{Name: "b", Roles: []string{"dashboard"}},
		{Name: "c", Roles: []string{"dns"}},
	}

	got := ExpandSameHostsRoles(hosts, deps)

	want := map[string][]string{
		"a": {"wazuh-manager", "docker"},
		"b": {"dashboard", "docker", "reverse-proxy"},
		"c": {"dns"},
	}
	for _, h := range got {
		if !reflect.DeepEqual(h.Roles, want[h.Name]) {
			t.Errorf("host %s Roles = %v, want %v", h.Name, h.Roles, want[h.Name])
		}
	}
}

func TestExpandSameHostsRoles_TransitiveChainAndDedup(t *testing.T) {
	deps := map[string][]string{
		"a": {"b"},
		"b": {"c"},
	}
	hosts := []Host{{Name: "h", Roles: []string{"a", "b"}}}

	got := ExpandSameHostsRoles(hosts, deps)

	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got[0].Roles, want) {
		t.Fatalf("Roles = %v, want %v", got[0].Roles, want)
	}
}

func TestExpandSameHostsRoles_DoesNotMutateInput(t *testing.T) {
	deps := map[string][]string{"wazuh-manager": {"docker"}}
	original := []string{"wazuh-manager"}
	hosts := []Host{{Name: "a", Roles: original}}

	ExpandSameHostsRoles(hosts, deps)

	if !reflect.DeepEqual(hosts[0].Roles, original) || len(original) != 1 {
		t.Fatalf("input host Roles mutated: %v", hosts[0].Roles)
	}
}

func TestExpandSameHostsRoles_NoDepsReturnsInputUnchanged(t *testing.T) {
	hosts := []Host{{Name: "a", Roles: []string{"docker"}}}
	got := ExpandSameHostsRoles(hosts, nil)
	if !reflect.DeepEqual(got, hosts) {
		t.Fatalf("got = %#v, want unchanged %#v", got, hosts)
	}
}
