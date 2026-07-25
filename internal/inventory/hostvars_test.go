package inventory

import (
	"strings"
	"testing"
)

func TestExpectedHostVarsKeysForRoles_KnownRole(t *testing.T) {
	got := ExpectedHostVarsKeysForRoles([]string{"prometheus"})
	want := []string{"prometheus_site_label"}
	if len(got) != len(want) {
		t.Fatalf("ExpectedHostVarsKeysForRoles() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ExpectedHostVarsKeysForRoles() = %v, want %v", got, want)
		}
	}
}

func TestExpectedHostVarsKeysForRoles_UnknownRoleIsEmpty(t *testing.T) {
	got := ExpectedHostVarsKeysForRoles([]string{"docker", "wazuh-fim"})
	if len(got) != 0 {
		t.Fatalf("ExpectedHostVarsKeysForRoles() = %v, want empty", got)
	}
}

func TestGenerateHostVarsSkeleton_HasRequiredKeys(t *testing.T) {
	h := Host{Name: "nexus", Roles: []string{"docker", "prometheus", "thanos-query"}}

	got, ok := GenerateHostVarsSkeleton(h)
	if !ok {
		t.Fatalf("GenerateHostVarsSkeleton() ok = false, want true")
	}
	for _, want := range []string{
		`prometheus_site_label: ""`,
		"host_vars/nexus.yml skeleton",
		"必填、沒有預設值",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("GenerateHostVarsSkeleton() missing %q:\n%s", want, got)
		}
	}
}

func TestGenerateHostVarsSkeleton_NoKeysReturnsFalse(t *testing.T) {
	h := Host{Name: "client-vm", Roles: []string{"docker", "freeipa-client", "wazuh-fim"}}

	got, ok := GenerateHostVarsSkeleton(h)
	if ok || got != "" {
		t.Fatalf("GenerateHostVarsSkeleton() = (%q, %v), want (\"\", false)", got, ok)
	}
}

func TestHostVarsKeysForRoles_DedupesAcrossRoles(t *testing.T) {
	// prometheus is the only role contributing prometheus_site_label today;
	// this guards against a future second contributor silently duplicating it.
	got := HostVarsKeysForRoles([]string{"prometheus", "prometheus"})
	if len(got) != 1 || got[0] != "prometheus_site_label" {
		t.Fatalf("HostVarsKeysForRoles() = %v, want [prometheus_site_label]", got)
	}
}

// TestGenerateHostVarsSkeleton_ListKindRendersFlowList exercises the
// hostVarsKindList render branch — no shipped catalog entry uses it yet,
// but the type exists specifically so a future list-shaped host_vars key
// doesn't need another catalog redesign; this proves that branch actually
// renders valid YAML before anything depends on it.
func TestGenerateHostVarsSkeleton_ListKindRendersFlowList(t *testing.T) {
	const testKey = "zz_test_list_key"
	origCatalog := hostVarsKeyCatalog
	origOrder := hostVarsKeyOrder
	origContracts := roleContracts
	t.Cleanup(func() {
		hostVarsKeyCatalog = origCatalog
		hostVarsKeyOrder = origOrder
		roleContracts = origContracts
	})

	hostVarsKeyCatalog = map[string]hostVarsKey{
		testKey: {Name: testKey, Kind: hostVarsKindList, Values: nil, Comment: "test-only list key"},
	}
	hostVarsKeyOrder = []string{testKey}
	roleContracts = append(append([]roleContract{}, origContracts...), roleContract{
		Name: "zz-test-role", HostVarsKeys: []string{testKey},
	})

	h := Host{Name: "test-host", Roles: []string{"zz-test-role"}}
	got, ok := GenerateHostVarsSkeleton(h)
	if !ok {
		t.Fatalf("GenerateHostVarsSkeleton() ok = false, want true")
	}
	if !strings.Contains(got, testKey+": []") {
		t.Fatalf("GenerateHostVarsSkeleton() = %q, want %q rendered as a bare empty flow list", got, testKey+": []")
	}
}
