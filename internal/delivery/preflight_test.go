package delivery

import (
	"reflect"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

func TestValidatePreflightCardinalityAndSameHosts(t *testing.T) {
	server := contract.Contract{ID: "server", Role: "server", HostCardinality: "exactly-one"}
	client := contract.Contract{ID: "client", Role: "client", HostCardinality: "one-or-more", Dependencies: []contract.Dependency{{Component: "server", Required: true, Relation: "sameHosts"}}}
	err := ValidatePreflight([]contract.Contract{server, client}, Scope{HostsByRole: map[string][]string{"server": {"a"}, "client": {"a", "b"}}})
	if err == nil || !strings.Contains(err.Error(), "same hosts") {
		t.Fatalf("err=%v", err)
	}
	err = ValidatePreflight([]contract.Contract{server}, Scope{HostsByRole: map[string][]string{"server": {"a", "b"}}})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("err=%v", err)
	}
}

// A sameHosts dependency only requires the dependent's own hosts to also
// carry the dependency — the dependency is free to additionally cover hosts
// the dependent doesn't run on (e.g. "docker" wired to more hosts than any
// single docker-based component). See COMPONENT_CONTRACT_RFC.md §5.1.
func TestValidatePreflightSameHostsAllowsProviderSuperset(t *testing.T) {
	docker := contract.Contract{ID: "docker", Role: "docker", HostCardinality: "one-or-more"}
	dashboard := contract.Contract{ID: "dashboard", Role: "dashboard", HostCardinality: "exactly-one", Dependencies: []contract.Dependency{{Component: "docker", Required: true, Relation: "sameHosts"}}}
	scope := Scope{HostsByRole: map[string][]string{"docker": {"client-vm", "nexus"}, "dashboard": {"nexus"}}}
	if err := ValidatePreflight([]contract.Contract{docker, dashboard}, scope); err != nil {
		t.Fatalf("expected pass, got err=%v", err)
	}
}

func TestValidatePreflightRequiresDependencySelection(t *testing.T) {
	client := contract.Contract{ID: "client", Role: "client", HostCardinality: "one-or-more", Dependencies: []contract.Dependency{{Component: "server", Required: true, Relation: "planOnly"}}}
	err := ValidatePreflight([]contract.Contract{client}, Scope{HostsByRole: map[string][]string{"client": {"a"}}})
	if err == nil || !strings.Contains(err.Error(), "requires selected dependency") {
		t.Fatalf("err=%v", err)
	}
}

func TestValidateContractPreflightRequiresInputsAndEvaluatesRules(t *testing.T) {
	component := contract.Contract{
		ID: "backup", Role: "backup", HostCardinality: "one-or-more",
		GroupVars: []contract.GroupVar{
			{Name: "password", Type: "string", Required: true},
			{Name: "endpoint", Type: "string"},
		},
		InputRules: []contract.InputRule{{
			Any:    []contract.InputCondition{{Input: "endpoint", Operator: "nonEmpty"}},
			Reason: "endpoint required",
		}},
	}
	request := PreflightRequest{Selected: []contract.Contract{component}, Scope: Scope{HostsByRole: map[string][]string{"backup": {"a"}}}}
	if _, err := ValidateContractPreflight(request); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("err=%v", err)
	}
	request.Inputs = map[string]map[string]any{"backup": {"password": "secret"}}
	if _, err := ValidateContractPreflight(request); err == nil || !strings.Contains(err.Error(), "endpoint required") {
		t.Fatalf("err=%v", err)
	}
}

func TestValidateContractPreflightRejectsAmbiguousProviderAndLowResources(t *testing.T) {
	provider := contract.Contract{ID: "provider", Role: "provider", HostCardinality: "one-or-more"}
	client := contract.Contract{
		ID: "client", Role: "client", HostCardinality: "one-or-more",
		Dependencies: []contract.Dependency{{Component: "provider", Required: true, Relation: "providerEndpoint"}},
		Bindings:     []contract.Binding{{Input: "endpoint", SourceSelection: "exactlyOne", From: contract.BindingFrom{Component: "provider", Endpoint: "api"}}},
		Resources:    contract.Resources{MinCPU: 2},
	}
	request := PreflightRequest{
		Selected: []contract.Contract{provider, client},
		Scope: Scope{HostsByRole: map[string][]string{
			"provider": {"p1", "p2"}, "client": {"c1"},
		}},
		Facts: map[string]HostFacts{"c1": {Available: true, CPU: 1}},
	}
	if _, err := ValidateContractPreflight(request); err == nil || !strings.Contains(err.Error(), "below minimum") {
		t.Fatalf("err=%v", err)
	}
	request.Facts["c1"] = HostFacts{Available: true, CPU: 2}
	if _, err := ValidateContractPreflight(request); err == nil || !strings.Contains(err.Error(), "exactly one explicit") {
		t.Fatalf("err=%v", err)
	}
	request.ProviderSelection = map[string][]string{"client.endpoint": {"p1"}}
	if _, err := ValidateContractPreflight(request); err != nil {
		t.Fatalf("err=%v", err)
	}
}

func TestValidateContractPreflightWarnsWhenFactsUnavailable(t *testing.T) {
	component := contract.Contract{ID: "a", Role: "a", HostCardinality: "one-or-more", Resources: contract.Resources{MinCPU: 8}}
	result, err := ValidateContractPreflight(PreflightRequest{
		Selected: []contract.Contract{component},
		Scope:    Scope{HostsByRole: map[string][]string{"a": {"host-a"}}},
	})
	if err != nil || len(result.Warnings) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestValidateContractPreflightMeasuresDiskPathsInsteadOfRoot(t *testing.T) {
	component := contract.Contract{
		ID: "wazuh-manager", Role: "wazuh-manager", HostCardinality: "one-or-more",
		Resources: contract.Resources{MinDiskGiB: 50, DiskPaths: []string{"/var/lib/docker"}},
	}
	request := PreflightRequest{
		Selected: []contract.Contract{component},
		Scope:    Scope{HostsByRole: map[string][]string{"wazuh-manager": {"nexus"}}},
	}

	// / is short, but the data directory sits on a larger filesystem.
	request.Facts = map[string]HostFacts{"nexus": {Available: true, DiskGiB: 38, DiskGiBByPath: map[string]int{"/var/lib/docker": 467}}}
	if result, err := ValidateContractPreflight(request); err != nil || len(result.Warnings) != 0 {
		t.Fatalf("data directory with room: result=%+v err=%v", result, err)
	}

	// / has room, but the data directory's filesystem does not.
	request.Facts = map[string]HostFacts{"nexus": {Available: true, DiskGiB: 400, DiskGiBByPath: map[string]int{"/var/lib/docker": 10}}}
	if _, err := ValidateContractPreflight(request); err == nil || !strings.Contains(err.Error(), "diskGiB=10 (available on /var/lib/docker) are below minimum") {
		t.Fatalf("full data directory: err=%v", err)
	}

	// Without diskPaths the minimum still applies to /.
	request.Selected[0].Resources.DiskPaths = nil
	request.Facts = map[string]HostFacts{"nexus": {Available: true, DiskGiB: 38, DiskGiBByPath: map[string]int{"/var/lib/docker": 467}}}
	if _, err := ValidateContractPreflight(request); err == nil || !strings.Contains(err.Error(), "diskGiB=38 (available on /) are below minimum") {
		t.Fatalf("no diskPaths: err=%v", err)
	}
}

func TestValidateContractPreflightChecksEveryDiskPath(t *testing.T) {
	component := contract.Contract{
		ID: "thanos", Role: "thanos", HostCardinality: "one-or-more",
		Resources: contract.Resources{MinDiskGiB: 10, DiskPaths: []string{"/srv/store", "/srv/compact"}},
	}
	request := PreflightRequest{
		Selected: []contract.Contract{component},
		Scope:    Scope{HostsByRole: map[string][]string{"thanos": {"h"}}},
		Facts:    map[string]HostFacts{"h": {Available: true, DiskGiB: 100, DiskGiBByPath: map[string]int{"/srv/store": 50, "/srv/compact": 5}}},
	}
	if _, err := ValidateContractPreflight(request); err == nil || !strings.Contains(err.Error(), "diskGiB=5 (available on /srv/compact)") {
		t.Fatalf("err=%v", err)
	}
}

func TestValidateContractPreflightWarnsWhenDiskPathUnmeasured(t *testing.T) {
	component := contract.Contract{
		ID: "a", Role: "a", HostCardinality: "one-or-more",
		Resources: contract.Resources{MinDiskGiB: 50, DiskPaths: []string{"/var/lib/docker"}},
	}
	request := PreflightRequest{
		Selected: []contract.Contract{component},
		Scope:    Scope{HostsByRole: map[string][]string{"a": {"h"}}},
		Facts:    map[string]HostFacts{"h": {Available: true, DiskGiB: 1}},
	}
	result, err := ValidateContractPreflight(request)
	if err != nil || len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "disk space on /var/lib/docker not measured") {
		t.Fatalf("result=%+v err=%v", result, err)
	}

	// An unmeasured disk does not hide a known CPU deficit.
	request.Selected[0].Resources.MinCPU = 4
	if _, err := ValidateContractPreflight(request); err == nil || !strings.Contains(err.Error(), "diskGiB=not measured") {
		t.Fatalf("err=%v", err)
	}
}

func TestDiskPathsByHost(t *testing.T) {
	selected := []contract.Contract{
		{ID: "wazuh-manager", Role: "wazuh-manager", Resources: contract.Resources{MinDiskGiB: 50, DiskPaths: []string{"/var/lib/docker"}}},
		{ID: "prometheus", Role: "prometheus", Resources: contract.Resources{MinDiskGiB: 20, DiskPaths: []string{"/var/lib/pilot/prometheus"}}},
		{ID: "docker", Role: "docker", Resources: contract.Resources{MinDiskGiB: 10, DiskPaths: []string{"/var/lib/docker"}}},
		{ID: "host-monitoring", Role: "host-monitoring", Resources: contract.Resources{MinDiskGiB: 1}},
	}
	scope := Scope{HostsByRole: map[string][]string{
		"wazuh-manager":   {"nexus"},
		"prometheus":      {"nexus"},
		"docker":          {"nexus", "nexus", "edge"},
		"host-monitoring": {"nexus", "edge", "ipa"},
	}}
	want := map[string][]string{
		"nexus": {"/var/lib/docker", "/var/lib/pilot/prometheus"},
		"edge":  {"/var/lib/docker"},
	}
	if got := DiskPathsByHost(selected, scope); !reflect.DeepEqual(got, want) {
		t.Fatalf("DiskPathsByHost = %v, want %v", got, want)
	}
}
