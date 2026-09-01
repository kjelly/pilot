package repair

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/networkcheck"
)

func fakeStdoutRunner(byModuleArgs map[string]string) func(ctx context.Context, args []string, timeoutSeconds int) (string, int, error) {
	return func(ctx context.Context, args []string, timeoutSeconds int) (string, int, error) {
		host := args[0]
		// args = [host, -i, inv, -T, timeout, -m, module, -a, command]
		command := args[len(args)-1]
		stdout := byModuleArgs[command]
		doc := map[string]any{"plays": []any{map[string]any{"tasks": []any{map[string]any{"hosts": map[string]any{
			host: map[string]any{"stdout": stdout, "rc": 0, "failed": false, "unreachable": false},
		}}}}}}
		b, _ := json.Marshal(doc)
		return string(b), 0, nil
	}
}

func preflightTestCatalog(t *testing.T) contract.Catalog {
	t.Helper()
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "docker", Diagnostics: contract.Diagnostics{Runtime: contract.DiagnosticsRuntime{Kind: "systemd", Name: "docker.service"}}},
		{ID: "alertmanager", Endpoints: []contract.Endpoint{{Name: "api", Port: 9093}}},
		{ID: "prometheus", Dependencies: []contract.Dependency{
			{Component: "docker", Required: true, Relation: "sameHosts"},
			{Component: "alertmanager", Required: true, Relation: "providerEndpoint", Endpoints: []string{"api"}},
		}, Bindings: []contract.Binding{
			{Input: "alertmanager_target_host", From: contract.BindingFrom{Component: "alertmanager", Endpoint: "api"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	return catalog
}

func TestPreflightDependencies_AllHealthy(t *testing.T) {
	catalog := preflightTestCatalog(t)
	resolved := networkcheck.ResolvedInventory{HostVars: map[string]map[string]any{
		"web-1": {"alertmanager_target_host": "10.0.0.5"},
	}}
	fake := fakeStdoutRunner(map[string]string{
		"systemctl is-active docker.service": "active",
		// dependency-0 command varies by port/host in the real command
		// string, so match by substring instead of exact key below.
	})
	// wrap to match dependency-N's dynamic /dev/tcp command by substring
	runner := func(ctx context.Context, args []string, timeoutSeconds int) (string, int, error) {
		cmd := args[len(args)-1]
		if cmd == "systemctl is-active docker.service" {
			return fake(ctx, args, timeoutSeconds)
		}
		host := args[0]
		doc := map[string]any{"plays": []any{map[string]any{"tasks": []any{map[string]any{"hosts": map[string]any{
			host: map[string]any{"stdout": "reachable", "rc": 0, "failed": false, "unreachable": false},
		}}}}}}
		b, _ := json.Marshal(doc)
		return string(b), 0, nil
	}

	statuses, err := PreflightDependencies(context.Background(), runner, "/tmp/inv.yml", catalog, resolved, "web-1", "prometheus", 5*time.Second)
	if err != nil {
		t.Fatalf("PreflightDependencies: %v", err)
	}
	if len(statuses) != 2 {
		t.Fatalf("got %d statuses, want 2: %+v", len(statuses), statuses)
	}
	ok, failing := AllRequiredHealthy(statuses)
	if !ok {
		t.Fatalf("AllRequiredHealthy = false, failing=%v, statuses=%+v", failing, statuses)
	}
}

func TestPreflightDependencies_SameHostUnhealthyBlocks(t *testing.T) {
	catalog := preflightTestCatalog(t)
	resolved := networkcheck.ResolvedInventory{HostVars: map[string]map[string]any{
		"web-1": {"alertmanager_target_host": "10.0.0.5"},
	}}
	runner := func(ctx context.Context, args []string, timeoutSeconds int) (string, int, error) {
		host := args[0]
		cmd := args[len(args)-1]
		stdout := "reachable"
		if cmd == "systemctl is-active docker.service" {
			stdout = "inactive"
		}
		doc := map[string]any{"plays": []any{map[string]any{"tasks": []any{map[string]any{"hosts": map[string]any{
			host: map[string]any{"stdout": stdout, "rc": 0, "failed": false, "unreachable": false},
		}}}}}}
		b, _ := json.Marshal(doc)
		return string(b), 0, nil
	}

	statuses, err := PreflightDependencies(context.Background(), runner, "/tmp/inv.yml", catalog, resolved, "web-1", "prometheus", 5*time.Second)
	if err != nil {
		t.Fatalf("PreflightDependencies: %v", err)
	}
	ok, failing := AllRequiredHealthy(statuses)
	if ok {
		t.Fatalf("AllRequiredHealthy = true, want false (docker.service is inactive): %+v", statuses)
	}
	if len(failing) != 1 || failing[0] != "docker" {
		t.Errorf("failing = %v, want [docker]", failing)
	}
}

func TestPreflightDependencies_UnresolvedBindingIsUnhealthyNotSkipped(t *testing.T) {
	catalog := preflightTestCatalog(t)
	// No alertmanager_target_host resolved for this host at all.
	resolved := networkcheck.ResolvedInventory{HostVars: map[string]map[string]any{"web-1": {}}}
	runner := fakeStdoutRunner(map[string]string{"systemctl is-active docker.service": "active"})

	statuses, err := PreflightDependencies(context.Background(), runner, "/tmp/inv.yml", catalog, resolved, "web-1", "prometheus", 5*time.Second)
	if err != nil {
		t.Fatalf("PreflightDependencies: %v", err)
	}
	ok, failing := AllRequiredHealthy(statuses)
	if ok {
		t.Fatalf("AllRequiredHealthy = true, want false (alertmanager has no resolved binding): %+v", statuses)
	}
	if len(failing) != 1 || failing[0] != "alertmanager" {
		t.Errorf("failing = %v, want [alertmanager]", failing)
	}
}

func TestPreflightDependencies_UnknownComponentErrors(t *testing.T) {
	catalog := preflightTestCatalog(t)
	resolved := networkcheck.ResolvedInventory{}
	runner := fakeStdoutRunner(nil)
	if _, err := PreflightDependencies(context.Background(), runner, "/tmp/inv.yml", catalog, resolved, "web-1", "not-a-component", 5*time.Second); err == nil {
		t.Fatal("expected an error for an unknown component")
	}
}
