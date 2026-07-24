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
