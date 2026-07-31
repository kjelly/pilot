package networkcheck

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func loadRealCatalog(t *testing.T) contract.Catalog {
	t.Helper()
	loader, err := contract.NewLoader(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func endpointNames(edges []Edge) []string {
	seen := make(map[string]bool)
	var out []string
	for _, e := range edges {
		if !seen[e.EndpointName] {
			seen[e.EndpointName] = true
			out = append(out, e.EndpointName)
		}
	}
	sort.Strings(out)
	return out
}

func TestPlan_FreeipaClientToFreeipaServer_ExpandsNarrowedEndpointSet(t *testing.T) {
	catalog := loadRealCatalog(t)
	inv := ResolvedInventory{
		GroupHosts: map[string][]string{
			"freeipa-client": {"dt-port6000"},
			"freeipa-server": {"freeipa1"},
		},
		HostVars: map[string]map[string]any{
			"dt-port6000": {"ansible_host": "192.168.110.35"},
			"freeipa1":    {"ansible_host": "10.1.58.11"},
		},
	}

	edges, err := Plan(catalog, inv, PlanOptions{Components: []string{"freeipa-client"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 5 {
		t.Fatalf("got %d edges, want 5 (one per narrowed endpoint): %+v", len(edges), edges)
	}
	got := endpointNames(edges)
	want := []string{"httpBootstrap", "kerberosTcp", "kerberosUdp", "kpasswdUdp", "ldap"}
	if len(got) != len(want) {
		t.Fatalf("endpoint names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("endpoint names = %v, want %v", got, want)
		}
	}
	for _, e := range edges {
		if e.ConsumerComponent != "freeipa-client" || e.ProviderComponent != "freeipa-server" {
			t.Fatalf("unexpected components on edge: %+v", e)
		}
		if e.SourceAddr != "192.168.110.35" {
			t.Fatalf("SourceAddr = %q, want the resolved ansible_host", e.SourceAddr)
		}
		if e.TargetKind != TargetInventory || e.TargetHost != "10.1.58.11" {
			t.Fatalf("target not resolved from inventory: %+v", e)
		}
		if e.EndpointName == "ldaps" || e.EndpointName == "https" {
			t.Fatalf("narrowed dependency must exclude %s: %+v", e.EndpointName, e)
		}
	}
}

func TestPlan_ResticBackupToSeaweedfsS3_SingleTCP8333Edge(t *testing.T) {
	catalog := loadRealCatalog(t)
	inv := ResolvedInventory{
		GroupHosts: map[string][]string{
			"restic-backup": {"dt-port6000"},
			"seaweedfs-s3":  {"it-core"},
		},
		HostVars: map[string]map[string]any{
			"dt-port6000": {"ansible_host": "192.168.110.35"},
			"it-core":     {"ansible_host": "10.1.58.12"},
		},
	}

	edges, err := Plan(catalog, inv, PlanOptions{Components: []string{"restic-backup"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1: %+v", len(edges), edges)
	}
	e := edges[0]
	if e.EndpointName != "s3" || e.Protocol != "tcp" || e.Port != 8333 {
		t.Fatalf("unexpected edge: %+v", e)
	}
	if e.TargetKind != TargetInventory || e.TargetHost != "10.1.58.12" {
		t.Fatalf("target not resolved from inventory: %+v", e)
	}
}

func TestPlan_MultiHostCartesianExpansionIsSortedAndDeterministic(t *testing.T) {
	catalog := syntheticCatalog(t)
	inv := ResolvedInventory{
		GroupHosts: map[string][]string{
			"consumer": {"c2", "c1"},
			"provider": {"p2", "p1"},
		},
	}

	edges, err := Plan(catalog, inv, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 4 {
		t.Fatalf("got %d edges, want 2x2 cartesian = 4: %+v", len(edges), edges)
	}
	edgesAgain, err := Plan(catalog, inv, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range edges {
		if edges[i] != edgesAgain[i] {
			t.Fatalf("plan is not deterministic across identical calls at index %d: %+v vs %+v", i, edges[i], edgesAgain[i])
		}
	}
	if edges[0].SourceHost != "c1" || edges[0].TargetHost != "p1" {
		t.Fatalf("edges not sorted by source/target host: %+v", edges[0])
	}
}

func TestPlan_UnixEndpointsAreExcluded(t *testing.T) {
	catalog, err := contract.NewCatalog([]contract.Contract{
		{
			ID: "provider", Role: "provider",
			Endpoints: []contract.Endpoint{
				{Name: "socket", Scheme: "unix", Path: "/var/run/x.sock"},
				{Name: "api", Scheme: "http", Port: 8080},
			},
		},
		{
			ID: "consumer", Role: "consumer",
			Dependencies: []contract.Dependency{{Component: "provider", Required: true, Relation: "providerEndpoint"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	inv := ResolvedInventory{GroupHosts: map[string][]string{
		"consumer": {"c1"},
		"provider": {"p1"},
	}}

	edges, err := Plan(catalog, inv, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || edges[0].EndpointName != "api" {
		t.Fatalf("unix endpoint leaked into plan: %+v", edges)
	}
}

func TestPlan_ProviderNotInInventory_NonSecretOverrideResolvesExternal(t *testing.T) {
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "provider", Role: "provider", Endpoints: []contract.Endpoint{{Name: "s3", Scheme: "http", Port: 8333}}},
		{
			ID: "consumer", Role: "consumer",
			Dependencies: []contract.Dependency{{Component: "provider", Required: true, Relation: "providerEndpoint"}},
			Bindings:     []contract.Binding{{Input: "target_host", From: contract.BindingFrom{Component: "provider", Endpoint: "s3"}}},
			GroupVars:    []contract.GroupVar{{Name: "target_host", Type: "string", Secret: false}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	inv := ResolvedInventory{
		GroupHosts: map[string][]string{"consumer": {"c1"}, "provider": {}},
		HostVars:   map[string]map[string]any{"c1": {"target_host": "s3.external.example"}},
	}

	edges, err := Plan(catalog, inv, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1: %+v", len(edges), edges)
	}
	if edges[0].TargetKind != TargetExternal || edges[0].TargetHost != "s3.external.example" {
		t.Fatalf("external override not resolved: %+v", edges[0])
	}
}

func TestPlan_ProviderNotInInventory_SecretInputNeverResolvedAsTarget(t *testing.T) {
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "provider", Role: "provider", Endpoints: []contract.Endpoint{{Name: "s3", Scheme: "http", Port: 8333}}},
		{
			ID: "consumer", Role: "consumer",
			Dependencies: []contract.Dependency{{Component: "provider", Required: true, Relation: "providerEndpoint"}},
			Bindings:     []contract.Binding{{Input: "target_host", From: contract.BindingFrom{Component: "provider", Endpoint: "s3"}}},
			GroupVars:    []contract.GroupVar{{Name: "target_host", Type: "string", Secret: true}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	inv := ResolvedInventory{
		GroupHosts: map[string][]string{"consumer": {"c1"}, "provider": {}},
		HostVars:   map[string]map[string]any{"c1": {"target_host": "should-never-appear"}},
	}

	edges, err := Plan(catalog, inv, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1: %+v", len(edges), edges)
	}
	e := edges[0]
	if e.TargetKind != TargetSkip || e.TargetHost != "" {
		t.Fatalf("secret input leaked into a resolved target: %+v", e)
	}
	if e.SkipReason == "" {
		t.Fatalf("skip must carry a reason")
	}
}

func TestPlan_SourceHostFilterNarrowsExpansion(t *testing.T) {
	catalog := syntheticCatalog(t)
	inv := ResolvedInventory{GroupHosts: map[string][]string{
		"consumer": {"c1", "c2"},
		"provider": {"p1"},
	}}

	edges, err := Plan(catalog, inv, PlanOptions{SourceHosts: []string{"c1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || edges[0].SourceHost != "c1" {
		t.Fatalf("source host filter not applied: %+v", edges)
	}
}

func TestPlan_UnknownComponentFilterErrors(t *testing.T) {
	catalog := syntheticCatalog(t)
	if _, err := Plan(catalog, ResolvedInventory{}, PlanOptions{Components: []string{"does-not-exist"}}); err == nil {
		t.Fatal("unknown component filter accepted")
	}
}

func syntheticCatalog(t *testing.T) contract.Catalog {
	t.Helper()
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "provider", Role: "provider", Endpoints: []contract.Endpoint{{Name: "api", Scheme: "tcp", Port: 9999}}},
		{
			ID: "consumer", Role: "consumer",
			Dependencies: []contract.Dependency{{Component: "provider", Required: true, Relation: "providerEndpoint"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}
