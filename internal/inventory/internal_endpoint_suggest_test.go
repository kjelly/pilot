package inventory

import (
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

func eligibleEndpoint(name, scheme string, port int, subdomain string) contract.Endpoint {
	return contract.Endpoint{
		Name:   name,
		Scheme: scheme,
		Port:   port,
		AutoPublish: &contract.AutoPublish{
			Eligible:  true,
			Subdomain: subdomain,
		},
	}
}

func ineligibleEndpoint(name, scheme string, port int) contract.Endpoint {
	return contract.Endpoint{Name: name, Scheme: scheme, Port: port}
}

func TestSuggestInternalEndpoints_HappyPath(t *testing.T) {
	contracts := []contract.Contract{
		{ID: "dashboard", Role: "dashboard", Endpoints: []contract.Endpoint{
			eligibleEndpoint("grafana", "http", 3000, "grafana"),
			ineligibleEndpoint("loki", "http", 3100),
		}},
		{ID: "reverse-proxy", Role: "reverse-proxy"},
	}
	groups := map[string][]string{
		"dashboard":     {"nexus"},
		"reverse-proxy": {"nexus"},
	}

	result := SuggestInternalEndpoints(contracts, groups, "nexus", "it.pilot.internal.", nil)

	if len(result.Skipped) != 0 {
		t.Fatalf("unexpected skips: %+v", result.Skipped)
	}
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates = %d, want 1: %+v", len(result.Candidates), result.Candidates)
	}
	c := result.Candidates[0]
	if c.Component != "dashboard" || c.Endpoint != "grafana" || c.FQDN != "grafana.it.pilot.internal" {
		t.Fatalf("unexpected candidate: %+v", c)
	}
	route := mapField(c.Manifest, "route")
	if stringField(route, "mode") != "reverse_proxy" {
		t.Fatalf("route.mode = %q, want reverse_proxy", stringField(route, "mode"))
	}
	proxy := mapField(route, "proxy")
	if stringField(proxy, "inventory_host") != "nexus" {
		t.Fatalf("route.proxy.inventory_host = %q, want nexus", stringField(proxy, "inventory_host"))
	}
	upstream := mapField(route, "upstream")
	if stringField(upstream, "inventory_host") != "nexus" {
		t.Fatalf("route.upstream.inventory_host = %q, want nexus", stringField(upstream, "inventory_host"))
	}
	if port, _ := toInt(upstream["port"]); port != 3000 {
		t.Fatalf("route.upstream.port = %v, want 3000", upstream["port"])
	}
	tls := mapField(c.Manifest, "tls")
	if stringField(tls, "mode") != "freeipa" {
		t.Fatalf("tls.mode = %q, want freeipa", stringField(tls, "mode"))
	}
}

func TestSuggestInternalEndpoints_SkipsIneligibleEndpoints(t *testing.T) {
	contracts := []contract.Contract{
		{ID: "prometheus", Role: "prometheus", Endpoints: []contract.Endpoint{
			ineligibleEndpoint("prometheus", "http", 9090),
		}},
	}
	groups := map[string][]string{"prometheus": {"nexus"}, "reverse-proxy": {"nexus"}}

	result := SuggestInternalEndpoints(contracts, groups, "nexus", "it.pilot.internal.", nil)
	if len(result.Candidates) != 0 || len(result.Skipped) != 0 {
		t.Fatalf("expected no candidates and no skip rows for an ineligible endpoint, got candidates=%+v skipped=%+v", result.Candidates, result.Skipped)
	}
}

func TestSuggestInternalEndpoints_SkipsWhenComponentNotPresent(t *testing.T) {
	contracts := []contract.Contract{
		{ID: "dashboard", Role: "dashboard", Endpoints: []contract.Endpoint{
			eligibleEndpoint("grafana", "http", 3000, "grafana"),
		}},
	}
	groups := map[string][]string{"reverse-proxy": {"nexus"}}

	result := SuggestInternalEndpoints(contracts, groups, "nexus", "it.pilot.internal.", nil)
	if len(result.Candidates) != 0 {
		t.Fatalf("expected no candidates, got %+v", result.Candidates)
	}
	if len(result.Skipped) != 1 || result.Skipped[0].Component != "dashboard" {
		t.Fatalf("expected one skip for dashboard, got %+v", result.Skipped)
	}
}

func TestSuggestInternalEndpoints_SkipsAmbiguousHostCardinality(t *testing.T) {
	contracts := []contract.Contract{
		{ID: "dashboard", Role: "dashboard", Endpoints: []contract.Endpoint{
			eligibleEndpoint("grafana", "http", 3000, "grafana"),
		}},
	}
	groups := map[string][]string{
		"dashboard":     {"nexus", "nexus2"},
		"reverse-proxy": {"nexus"},
	}

	result := SuggestInternalEndpoints(contracts, groups, "nexus", "it.pilot.internal.", nil)
	if len(result.Candidates) != 0 {
		t.Fatalf("expected no candidates for ambiguous host cardinality, got %+v", result.Candidates)
	}
	if len(result.Skipped) != 1 {
		t.Fatalf("expected one skip row, got %+v", result.Skipped)
	}
}

func TestSuggestInternalEndpoints_SkipsAlreadyPublishedUpstream(t *testing.T) {
	contracts := []contract.Contract{
		{ID: "dashboard", Role: "dashboard", Endpoints: []contract.Endpoint{
			eligibleEndpoint("grafana", "http", 3000, "grafana"),
		}},
	}
	groups := map[string][]string{"dashboard": {"nexus"}, "reverse-proxy": {"nexus"}}
	existing := map[string]any{
		"endpoints": []any{
			map[string]any{
				"fqdn":  "already-here.it.pilot.internal",
				"state": "present",
				"route": map[string]any{
					"mode":     "reverse_proxy",
					"upstream": map[string]any{"inventory_host": "nexus", "port": 3000},
				},
			},
		},
	}

	result := SuggestInternalEndpoints(contracts, groups, "nexus", "it.pilot.internal.", existing)
	if len(result.Candidates) != 0 {
		t.Fatalf("expected no candidates for an already-published upstream, got %+v", result.Candidates)
	}
	if len(result.Skipped) != 1 {
		t.Fatalf("expected one skip row, got %+v", result.Skipped)
	}
}

func TestSuggestInternalEndpoints_SkipsSubdomainCollision(t *testing.T) {
	contracts := []contract.Contract{
		{ID: "dashboard", Role: "dashboard", Endpoints: []contract.Endpoint{
			eligibleEndpoint("grafana", "http", 3000, "shared"),
		}},
		{ID: "keycloak", Role: "keycloak", Endpoints: []contract.Endpoint{
			eligibleEndpoint("oidc", "http", 8080, "shared"),
		}},
	}
	groups := map[string][]string{
		"dashboard":     {"nexus"},
		"keycloak":      {"nexus"},
		"reverse-proxy": {"nexus"},
	}

	result := SuggestInternalEndpoints(contracts, groups, "nexus", "it.pilot.internal.", nil)
	if len(result.Candidates) != 1 {
		t.Fatalf("expected exactly one candidate to win the subdomain, got %+v", result.Candidates)
	}
	if len(result.Skipped) != 1 {
		t.Fatalf("expected one collision skip, got %+v", result.Skipped)
	}
}

func TestSuggestInternalEndpoints_HTTPSUpstreamGetsTLSVerifyFalse(t *testing.T) {
	contracts := []contract.Contract{
		{ID: "wazuh-manager", Role: "wazuh-manager", Endpoints: []contract.Endpoint{
			eligibleEndpoint("dashboard", "https", 8443, "wazuh"),
		}},
	}
	groups := map[string][]string{"wazuh-manager": {"nexus"}, "reverse-proxy": {"nexus"}}

	result := SuggestInternalEndpoints(contracts, groups, "nexus", "it.pilot.internal.", nil)
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(result.Candidates))
	}
	upstream := mapField(mapField(result.Candidates[0].Manifest, "route"), "upstream")
	tls := mapField(upstream, "tls")
	if verify, ok := tls["verify"].(bool); !ok || verify {
		t.Fatalf("https upstream tls.verify = %v, want false", tls["verify"])
	}
}
