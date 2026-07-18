package delivery

import (
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/contract"
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

func TestValidatePreflightRequiresDependencySelection(t *testing.T) {
	client := contract.Contract{ID: "client", Role: "client", HostCardinality: "one-or-more", Dependencies: []contract.Dependency{{Component: "server", Required: true, Relation: "planOnly"}}}
	err := ValidatePreflight([]contract.Contract{client}, Scope{HostsByRole: map[string][]string{"client": {"a"}}})
	if err == nil || !strings.Contains(err.Error(), "requires selected dependency") {
		t.Fatalf("err=%v", err)
	}
}
