package diagnose

import (
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/networkcheck"
)

func TestComponentSteps_DockerWithReadinessAndDependency(t *testing.T) {
	steps := ComponentSteps("docker", "pilot-prometheus", "http://127.0.0.1:9090/-/ready", "docker", "pilot-prometheus",
		[]DependencyEndpointCheck{{Component: "alertmanager", Host: "10.0.0.5", Port: 9093}})
	byID := map[string]Step{}
	for _, s := range steps {
		byID[s.ID] = s
	}
	if byID["runtime-state"].Command == "" {
		t.Fatal("missing runtime-state step")
	}
	if byID["readiness"].Command == "" {
		t.Fatal("missing readiness step")
	}
	if byID["recent-errors"].Command == "" {
		t.Fatal("missing recent-errors step")
	}
	dep, ok := byID["dependency-0"]
	if !ok || dep.Command == "" {
		t.Fatal("missing dependency-0 step")
	}
}

func TestComponentSteps_NoneRuntimeHasNoRuntimeStep(t *testing.T) {
	steps := ComponentSteps("none", "", "", "", "", nil)
	for _, s := range steps {
		if s.ID == "runtime-state" {
			t.Fatal("runtime:none must not produce a runtime-state step")
		}
	}
}

func TestResolveDependencyChecks_ResolvesFromBindingAndSkipsUnconfigured(t *testing.T) {
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "alertmanager", Endpoints: []contract.Endpoint{{Name: "api", Port: 9093}}},
		{ID: "prometheus", Bindings: []contract.Binding{
			{Input: "alertmanager_target_host", From: contract.BindingFrom{Component: "alertmanager", Endpoint: "api"}},
			{Input: "unresolved_target_host", From: contract.BindingFrom{Component: "alertmanager", Endpoint: "no-such-endpoint"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	comp, _ := catalog.Component("prometheus")
	resolved := networkcheck.ResolvedInventory{HostVars: map[string]map[string]any{
		"web-1": {"alertmanager_target_host": "10.0.0.5"},
	}}

	got := ResolveDependencyChecks(catalog, resolved, "web-1", comp)
	if len(got) != 1 {
		t.Fatalf("got %d checks, want exactly 1 (the unmatched endpoint binding must be skipped): %+v", len(got), got)
	}
	if got[0] != (DependencyEndpointCheck{Component: "alertmanager", Host: "10.0.0.5", Port: 9093}) {
		t.Errorf("got %+v", got[0])
	}
}

func TestResolveDependencyChecks_NoHostValueYieldsNoChecks(t *testing.T) {
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "alertmanager", Endpoints: []contract.Endpoint{{Name: "api", Port: 9093}}},
		{ID: "prometheus", Bindings: []contract.Binding{
			{Input: "alertmanager_target_host", From: contract.BindingFrom{Component: "alertmanager", Endpoint: "api"}},
		}},
	})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	comp, _ := catalog.Component("prometheus")
	resolved := networkcheck.ResolvedInventory{HostVars: map[string]map[string]any{"web-1": {}}}

	got := ResolveDependencyChecks(catalog, resolved, "web-1", comp)
	if len(got) != 0 {
		t.Fatalf("got %+v, want no checks — the dependency has no resolved host value", got)
	}
}

func TestBuildComponentOutput_HealthyDocker(t *testing.T) {
	results := []StepResult{
		stepResult("runtime-state", 0, "running"),
		stepResult("readiness", 0, "{}\nHTTP_STATUS:200"),
		stepResult("recent-errors", 0, ""),
		stepResult("dependency-0", 0, "reachable"),
	}
	out := BuildComponentOutput("docker", "docs/verification/prometheus.md",
		[]DependencyEndpointCheck{{Component: "alertmanager", Host: "10.0.0.5", Port: 9093}}, true, results)
	if out.Verdict != "healthy" {
		t.Fatalf("verdict = %q, want healthy; out=%+v", out.Verdict, out)
	}
	if !out.RuntimePresent || !out.RuntimeRunning {
		t.Errorf("runtime present/running = %v/%v, want true/true", out.RuntimePresent, out.RuntimeRunning)
	}
	if out.ReadinessHTTPStatus != 200 || !out.ReadinessOK {
		t.Errorf("readiness = %d/%v, want 200/true", out.ReadinessHTTPStatus, out.ReadinessOK)
	}
	if len(out.DependencyResults) != 1 || !out.DependencyResults[0].Reachable {
		t.Errorf("dependency results = %+v", out.DependencyResults)
	}
}

func TestBuildComponentOutput_DegradedOnContainerAbsent(t *testing.T) {
	results := []StepResult{stepResult("runtime-state", 0, "absent")}
	out := BuildComponentOutput("docker", "", nil, true, results)
	if out.Verdict != "degraded" {
		t.Fatalf("verdict = %q, want degraded (container absent is confident down-evidence)", out.Verdict)
	}
	if out.RuntimePresent {
		t.Error("RuntimePresent = true, want false")
	}
}

func TestBuildComponentOutput_DegradedOnUnreachableDependency(t *testing.T) {
	results := []StepResult{
		stepResult("runtime-state", 0, "running"),
		stepResult("dependency-0", 0, "unreachable"),
	}
	out := BuildComponentOutput("docker", "", []DependencyEndpointCheck{{Component: "x", Host: "h", Port: 1}}, true, results)
	if out.Verdict != "degraded" {
		t.Fatalf("verdict = %q, want degraded", out.Verdict)
	}
}

func TestBuildComponentOutput_Unreachable(t *testing.T) {
	out := BuildComponentOutput("docker", "", nil, false, nil)
	if out.Verdict != "unreachable" {
		t.Fatalf("verdict = %q, want unreachable", out.Verdict)
	}
}
