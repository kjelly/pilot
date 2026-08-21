package delivery

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/inventory"
)

// loadFreeIPAContracts loads the repository's real freeipa-client and
// freeipa-server contracts (not hand-rolled fixtures) so these tests prove
// dependency-availability gating against the actual providerEndpoint
// relation/binding shape declared in contracts/freeipa-client.yaml and
// contracts/freeipa-server.yaml: a required dependency with relation
// providerEndpoint, satisfied by an exactlyOne sourceSelection binding to
// freeipa-server's "https" endpoint.
func loadFreeIPAContracts(t *testing.T) (client, server contract.Contract) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	client, ok := catalog.Component("freeipa-client")
	if !ok {
		t.Fatal("freeipa-client contract not found")
	}
	server, ok = catalog.Component("freeipa-server")
	if !ok {
		t.Fatal("freeipa-server contract not found")
	}
	return client, server
}

func freeipaScope(clientHosts, serverHosts []string) Scope {
	return Scope{HostsByRole: map[string][]string{
		"freeipa-client": clientHosts,
		"freeipa-server": serverHosts,
	}}
}

func TestResolveExecutionScopeWithDependencies_ProviderReachable(t *testing.T) {
	client, server := loadFreeIPAContracts(t)
	req := DependencyAvailabilityRequest{
		Candidates: []CandidateHost{
			{Host: "dev-vm-02", Policy: inventory.DeploymentAvailabilityOptional, Reachable: true},
		},
		Selected:  []contract.Contract{client, server},
		Scope:     freeipaScope([]string{"dev-vm-02"}, []string{"ipa-1"}),
		Reachable: map[string]bool{"dev-vm-02": true, "ipa-1": true},
	}
	got := ResolveExecutionScopeWithDependencies(req)
	if len(got.Deferred) != 0 || len(got.Blocking) != 0 {
		t.Fatalf("expected no deferral/blocking, got deferred=%v blocking=%v", got.Deferred, got.Blocking)
	}
	if !containsHost(got.Included, "dev-vm-02") {
		t.Fatalf("expected dev-vm-02 included, got %v", got.Included)
	}
	if containsHost(got.Included, "ipa-1") {
		t.Fatalf("ipa-1 was never a mutation candidate and must not appear in Included: %v", got.Included)
	}
}

func TestResolveExecutionScopeWithDependencies_OptionalConsumerDeferredOnUnavailableProvider(t *testing.T) {
	client, server := loadFreeIPAContracts(t)
	req := DependencyAvailabilityRequest{
		Candidates: []CandidateHost{
			{Host: "dev-vm-02", Policy: inventory.DeploymentAvailabilityOptional, Reachable: true},
		},
		Selected:  []contract.Contract{client, server},
		Scope:     freeipaScope([]string{"dev-vm-02"}, []string{"ipa-1"}),
		Reachable: map[string]bool{"dev-vm-02": true, "ipa-1": false},
	}
	got := ResolveExecutionScopeWithDependencies(req)
	if containsHost(got.Included, "dev-vm-02") {
		t.Fatalf("dev-vm-02 must not remain included when its required provider is unreachable: %v", got.Included)
	}
	if len(got.Blocking) != 0 {
		t.Fatalf("optional consumer must defer, not block: %v", got.Blocking)
	}
	if len(got.Deferred) != 1 || got.Deferred[0].Host != "dev-vm-02" {
		t.Fatalf("expected dev-vm-02 deferred, got %v", got.Deferred)
	}
	deferred := got.Deferred[0]
	if deferred.Reason != DeferredDependencyUnavailable {
		t.Fatalf("reason = %q, want %q", deferred.Reason, DeferredDependencyUnavailable)
	}
	if deferred.Dependency != "freeipa-server@ipa-1" {
		t.Fatalf("dependency label = %q, want %q", deferred.Dependency, "freeipa-server@ipa-1")
	}
	// ipa-1 is a support host only: it was probed (via Reachable) but must
	// never appear in the mutation scope's Included/Deferred/Blocking sets.
	if containsHost(got.Included, "ipa-1") || containsHost(got.Blocking, "ipa-1") {
		t.Fatalf("ipa-1 must remain support-only, got included=%v blocking=%v", got.Included, got.Blocking)
	}
}

func TestResolveExecutionScopeWithDependencies_RequiredConsumerBlocksOnUnavailableProvider(t *testing.T) {
	client, server := loadFreeIPAContracts(t)
	req := DependencyAvailabilityRequest{
		Candidates: []CandidateHost{
			{Host: "dev-vm-02", Policy: inventory.DeploymentAvailabilityRequired, Reachable: true},
		},
		Selected:  []contract.Contract{client, server},
		Scope:     freeipaScope([]string{"dev-vm-02"}, []string{"ipa-1"}),
		Reachable: map[string]bool{"dev-vm-02": true, "ipa-1": false},
	}
	got := ResolveExecutionScopeWithDependencies(req)
	if len(got.Deferred) != 0 {
		t.Fatalf("required consumer must block, not defer: %v", got.Deferred)
	}
	if !containsHost(got.Blocking, "dev-vm-02") {
		t.Fatalf("expected dev-vm-02 blocking, got %v", got.Blocking)
	}
	if containsHost(got.Included, "dev-vm-02") {
		t.Fatalf("blocked host must not remain included: %v", got.Included)
	}
}

func TestDependencySupportHosts_IncludesUnselectedMutationTarget(t *testing.T) {
	client, server := loadFreeIPAContracts(t)
	got := DependencySupportHosts([]contract.Contract{client, server}, freeipaScope([]string{"dev-vm-02"}, []string{"ipa-1"}), nil)
	if !containsHost(got, "ipa-1") {
		t.Fatalf("expected ipa-1 reported as a support host to probe, got %v", got)
	}
}

func TestResolveExecutionScopeWithDependencies_UnrelatedOfflineProviderDoesNotBlock(t *testing.T) {
	// "other" has no providerEndpoint dependency at all; freeipa-server's
	// only host is offline, but nothing selected depends on it, so it must
	// never surface in Blocking/Deferred.
	other := contract.Contract{ID: "other", Role: "other-role"}
	_, server := loadFreeIPAContracts(t)
	req := DependencyAvailabilityRequest{
		Candidates: []CandidateHost{
			{Host: "other-host", Policy: inventory.DeploymentAvailabilityRequired, Reachable: true},
		},
		Selected:  []contract.Contract{other},
		Scope:     freeipaScope(nil, []string{"ipa-1"}),
		Reachable: map[string]bool{"other-host": true, "ipa-1": false},
	}
	got := ResolveExecutionScopeWithDependencies(req)
	if len(got.Blocking) != 0 || len(got.Deferred) != 0 {
		t.Fatalf("unrelated offline provider must not affect an unrelated component: blocking=%v deferred=%v", got.Blocking, got.Deferred)
	}
	if !containsHost(got.Included, "other-host") {
		t.Fatalf("expected other-host included, got %v", got.Included)
	}
	_ = server // server contract intentionally excluded from Selected in this case.
}

func TestResolveExecutionScopeWithDependencies_MultipleProvidersOneDownOneUpSatisfies(t *testing.T) {
	client, server := loadFreeIPAContracts(t)
	req := DependencyAvailabilityRequest{
		Candidates: []CandidateHost{
			{Host: "dev-vm-02", Policy: inventory.DeploymentAvailabilityOptional, Reachable: true},
		},
		Selected:  []contract.Contract{client, server},
		Scope:     freeipaScope([]string{"dev-vm-02"}, []string{"ipa-1", "ipa-2"}),
		Reachable: map[string]bool{"dev-vm-02": true, "ipa-1": false, "ipa-2": true},
	}
	got := ResolveExecutionScopeWithDependencies(req)
	if len(got.Deferred) != 0 || len(got.Blocking) != 0 {
		t.Fatalf("a reachable alternate provider must satisfy the dependency: deferred=%v blocking=%v", got.Deferred, got.Blocking)
	}
	if !containsHost(got.Included, "dev-vm-02") {
		t.Fatalf("expected dev-vm-02 included, got %v", got.Included)
	}
	support := DependencySupportHosts([]contract.Contract{client, server}, req.Scope, nil)
	sort.Strings(support)
	if len(support) != 2 || support[0] != "ipa-1" || support[1] != "ipa-2" {
		t.Fatalf("expected both provider candidates reported as support hosts, got %v", support)
	}
}
