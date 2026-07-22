package delivery

import (
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
