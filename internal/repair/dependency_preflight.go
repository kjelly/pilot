package repair

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/kjelly/pilot/internal/networkcheck"
)

// DependencyStatus is one dependency's resolved health at plan/preflight
// time (design doc §6/§10) — part of a ReapplyPlan's Resolved.
// DependencySnapshot, and hashed into PlanHash so a dependency snapshot
// that changes between plan and apply invalidates the plan like any
// other executable field.
type DependencyStatus struct {
	Component string
	Required  bool
	Healthy   bool
	Detail    string
}

// PreflightDependencies resolves component's declared
// `contracts/*.yaml` `dependencies:` into real health checks against
// host's actual current state — reusing Phase 2's own diagnostic
// primitives (RuntimeStateStep, ResolveDependencyChecks, RunSteps)
// rather than a second ad-hoc probing mechanism. Two dependency shapes
// exist (design doc §10's own Prometheus example):
//
//   - relation "sameHosts" (e.g. docker): health = the DEPENDENCY
//     component's own runtime-state check, run on THIS SAME host — not
//     the reapply target's own runtime.
//   - relation "providerEndpoint" (e.g. S3, Alertmanager): health = TCP
//     reachability to the binding-resolved host:port
//     (diagnose.ResolveDependencyChecks already does this resolution,
//     the exact mechanism pilot_diagnose_component uses).
//
// An unresolvable or unsupported dependency is reported unhealthy with
// an explanatory Detail, never silently dropped — "unknown = not
// eligible" (design doc §3) applies here too.
func PreflightDependencies(ctx context.Context, runner diagnose.AdHocRunner, inventory string, catalog contract.Catalog, resolved networkcheck.ResolvedInventory, host, component string, timeout time.Duration) ([]DependencyStatus, error) {
	comp, ok := catalog.Component(component)
	if !ok {
		return nil, fmt.Errorf("unknown component %q", component)
	}

	var out []DependencyStatus
	for _, dep := range comp.Dependencies {
		switch dep.Relation {
		case "sameHosts":
			out = append(out, preflightSameHostDependency(ctx, runner, inventory, catalog, host, dep, timeout))
		case "providerEndpoint":
			out = append(out, preflightProviderEndpointDependency(ctx, runner, inventory, catalog, resolved, host, comp, dep, timeout)...)
		default:
			out = append(out, DependencyStatus{Component: dep.Component, Required: dep.Required, Healthy: false,
				Detail: fmt.Sprintf("unsupported dependency relation %q", dep.Relation)})
		}
	}
	return out, nil
}

func preflightSameHostDependency(ctx context.Context, runner diagnose.AdHocRunner, inventory string, catalog contract.Catalog, host string, dep contract.Dependency, timeout time.Duration) DependencyStatus {
	depComp, ok := catalog.Component(dep.Component)
	if !ok {
		return DependencyStatus{Component: dep.Component, Required: dep.Required, Healthy: false, Detail: "dependency component not found in catalog"}
	}
	step := diagnose.RuntimeStateStep(depComp.Diagnostics.Runtime.Kind, depComp.Diagnostics.Runtime.Name)
	if step == nil {
		return DependencyStatus{Component: dep.Component, Required: dep.Required, Healthy: false, Detail: "dependency has no diagnostics.runtime configured — health unknown"}
	}
	results := diagnose.RunSteps(ctx, runner, inventory, host, []diagnose.Step{*step}, timeout)
	r := results[0].Result
	if r.RunErr != nil || r.Unreachable {
		return DependencyStatus{Component: dep.Component, Required: dep.Required, Healthy: false, Detail: "runtime-state check did not run: " + errString(r)}
	}
	state := strings.TrimSpace(r.Stdout)
	healthy := state == "running" || state == "active"
	return DependencyStatus{Component: dep.Component, Required: dep.Required, Healthy: healthy, Detail: "runtime state: " + state}
}

func preflightProviderEndpointDependency(ctx context.Context, runner diagnose.AdHocRunner, inventory string, catalog contract.Catalog, resolved networkcheck.ResolvedInventory, host string, comp contract.Contract, dep contract.Dependency, timeout time.Duration) []DependencyStatus {
	var out []DependencyStatus
	checks := diagnose.ResolveDependencyChecks(catalog, resolved, host, comp)
	found := false
	for _, c := range checks {
		if c.Component != dep.Component {
			continue
		}
		found = true
		steps := diagnose.ComponentSteps("", "", "", "", "", []diagnose.DependencyEndpointCheck{c})
		results := diagnose.RunSteps(ctx, runner, inventory, host, steps, timeout)
		r := results[0].Result
		healthy := r.RunErr == nil && !r.Unreachable && strings.TrimSpace(r.Stdout) == "reachable"
		detail := fmt.Sprintf("%s:%d", c.Host, c.Port)
		if !healthy {
			detail += " unreachable"
			if r.RunErr != nil || r.Unreachable {
				detail += ": " + errString(r)
			}
		}
		out = append(out, DependencyStatus{Component: dep.Component, Required: dep.Required, Healthy: healthy, Detail: detail})
	}
	if !found {
		out = append(out, DependencyStatus{Component: dep.Component, Required: dep.Required, Healthy: false,
			Detail: "no resolved binding for this host — cannot determine target"})
	}
	return out
}

func errString(r diagnose.AdHocResult) string {
	if r.RunErr != nil {
		return r.RunErr.Error()
	}
	if r.Unreachable {
		return "host unreachable"
	}
	return ""
}

// AllRequiredHealthy reports whether every REQUIRED dependency in
// statuses is healthy — an optional dependency's failure never blocks a
// reapply (design doc §10's own Prometheus example: "host-monitoring
// target set is optional according to contract").
func AllRequiredHealthy(statuses []DependencyStatus) (ok bool, failing []string) {
	for _, s := range statuses {
		if s.Required && !s.Healthy {
			failing = append(failing, s.Component)
		}
	}
	return len(failing) == 0, failing
}
