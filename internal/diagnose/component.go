package diagnose

import (
	"fmt"
	"strings"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/networkcheck"
)

// DependencyEndpointCheck is one TCP-reachability probe for a
// providerEndpoint dependency the caller has already resolved from the
// target host's OWN configured hostvar (e.g. alertmanager_target_host) —
// never a caller-supplied host/port (Agent Monitoring Phase 2 §2: "no
// composite accepts... arbitrary host:port").
type DependencyEndpointCheck struct {
	Component string
	Host      string
	Port      int
}

// ComponentSteps returns the fixed, read-only ad-hoc commands for
// pilot_diagnose_component (Agent Monitoring Phase 2 §4), built entirely
// from a component's own contracts/*.yaml `diagnostics` block plus its
// resolved dependency bindings — there is no `command:`/`shell:` field
// anywhere in that source data, so this function can never be handed an
// arbitrary command to run.
func ComponentSteps(runtimeKind, runtimeName, readinessURL, logsSource, logsRuntimeName string, dependencyChecks []DependencyEndpointCheck) []Step {
	var steps []Step
	if rs := RuntimeStateStep(runtimeKind, runtimeName); rs != nil {
		steps = append(steps, *rs)
	}

	if readinessURL != "" {
		steps = append(steps, Step{ID: "readiness", Description: "readiness endpoint status", Module: "command",
			Command: curlQueryCommand(readinessURL, nil)})
	}

	switch logsSource {
	case "docker":
		steps = append(steps, Step{ID: "recent-errors", Description: "bounded recent container log tail", Module: "shell",
			Command: fmt.Sprintf("docker logs --tail 30 %s 2>&1", shlexQuote(logsRuntimeName))})
	case "systemd":
		steps = append(steps, Step{ID: "recent-errors", Description: "bounded recent journal tail", Module: "command",
			Command: fmt.Sprintf("journalctl -u %s --no-pager -n 30", logsRuntimeName)})
	}

	for i, dep := range dependencyChecks {
		steps = append(steps, Step{
			ID:          fmt.Sprintf("dependency-%d", i),
			Description: fmt.Sprintf("TCP reachability to dependency %s (%s:%d)", dep.Component, dep.Host, dep.Port),
			Module:      "shell",
			// exec 3<>/dev/tcp/... (open, don't read) rather than
			// `cat < /dev/tcp/...` — a plain read blocks waiting for the
			// SERVER to send data first, which no HTTP-like server ever
			// does before it sees a request; that produced a false
			// "unreachable" on every real HTTP endpoint (confirmed
			// against a live container 2026-09-01), timing out instead
			// of confirming the TCP handshake it actually needs to check.
			Command: fmt.Sprintf("timeout 2 bash -c 'exec 3<>/dev/tcp/%s/%d' 2>/dev/null && echo reachable || echo unreachable", dep.Host, dep.Port),
		})
	}
	return steps
}

// RuntimeStateStep builds the single "is this runtime up" ad-hoc step
// for a docker/systemd runtime, or nil for any other kind (including
// "none" or unrecognized). Extracted out of ComponentSteps so Agent
// Monitoring Phase 5's dependency preflight (internal/repair) can run
// this SAME check against a DEPENDENCY's own runtime — e.g. "is the
// same-host docker.service healthy" ahead of a canonical_apply reapply
// — not just a component's own runtime the way pilot_diagnose_component
// uses it.
func RuntimeStateStep(runtimeKind, runtimeName string) *Step {
	switch runtimeKind {
	case "docker":
		return &Step{ID: "runtime-state", Description: "docker container present/running state", Module: "shell",
			Command: fmt.Sprintf("docker inspect -f '{{.State.Status}}' %s 2>/dev/null || echo absent", shlexQuote(runtimeName))}
	case "systemd":
		return &Step{ID: "runtime-state", Description: "systemd unit active state", Module: "command",
			Command: fmt.Sprintf("systemctl is-active %s", runtimeName)}
	default:
		return nil
	}
}

// ResolveDependencyChecks resolves component's declared `bindings` on
// host into concrete TCP-reachability checks — extracted from
// `pilot_diagnose_component`'s own inline resolution (originally only in
// cmd/pilot/cmd) so Agent Monitoring Phase 5's dependency preflight
// (internal/repair) can reuse the EXACT SAME resolution instead of a
// second, potentially-drifting copy: for each binding, find the
// provider's own declared endpoint by name, then read the resolved
// value the CURRENT host actually has for that binding's input hostvar
// — never a caller-supplied host/port (same "no arbitrary host:port"
// rule every other diagnostic composite follows). A binding with no
// endpoint match or no resolved hostvar value is silently skipped, not
// an error — an optional/unconfigured dependency is a valid state.
func ResolveDependencyChecks(catalog contract.Catalog, resolved networkcheck.ResolvedInventory, host string, comp contract.Contract) []DependencyEndpointCheck {
	var depChecks []DependencyEndpointCheck
	hostVars := resolved.HostVars[host]
	for _, binding := range comp.Bindings {
		depComp, ok := catalog.Component(binding.From.Component)
		if !ok {
			continue
		}
		var depEndpoint contract.Endpoint
		found := false
		for _, e := range depComp.Endpoints {
			if e.Name == binding.From.Endpoint {
				depEndpoint = e
				found = true
			}
		}
		if !found {
			continue
		}
		hostValue, hasHostValue := hostVars[binding.Input]
		hostStr, isStr := hostValue.(string)
		if !hasHostValue || !isStr || hostStr == "" {
			continue
		}
		depChecks = append(depChecks, DependencyEndpointCheck{Component: binding.From.Component, Host: hostStr, Port: depEndpoint.Port})
	}
	return depChecks
}

// DependencyEndpointResult pairs one DependencyEndpointCheck with its
// observed outcome.
type DependencyEndpointResult struct {
	Component string
	Host      string
	Port      int
	Reachable bool
}

// ComponentOutput is pilot_diagnose_component's synthesized result.
type ComponentOutput struct {
	RuntimeConfigured   bool
	RuntimePresent      bool
	RuntimeRunning      bool
	ReadinessConfigured bool
	ReadinessHTTPStatus int
	ReadinessOK         bool
	RecentErrorLines    []string
	DependencyResults   []DependencyEndpointResult
	VerifySpec          string
	Verdict             string // healthy | degraded | unreachable | insufficient_evidence
	Steps               []StepResult
}

// BuildComponentOutput synthesizes ComponentOutput from ComponentSteps'
// results. results must be in the exact order ComponentSteps(...)
// returned them for the SAME dependencyChecks slice.
func BuildComponentOutput(runtimeKind, verifySpec string, dependencyChecks []DependencyEndpointCheck, reachable bool, results []StepResult) ComponentOutput {
	out := ComponentOutput{VerifySpec: verifySpec, Steps: results}
	if !reachable {
		out.Verdict = "unreachable"
		return out
	}

	find := func(id string) (StepResult, bool) {
		for _, r := range results {
			if r.Step.ID == id {
				return r, true
			}
		}
		return StepResult{}, false
	}
	ok := func(r StepResult) bool { return r.Result.RunErr == nil && !r.Result.Unreachable }

	out.RuntimeConfigured = runtimeKind == "docker" || runtimeKind == "systemd"
	if out.RuntimeConfigured {
		if r, found := find("runtime-state"); found && ok(r) {
			state := strings.TrimSpace(r.Result.Stdout)
			switch runtimeKind {
			case "docker":
				out.RuntimePresent = state != "absent" && state != ""
				out.RuntimeRunning = state == "running"
			case "systemd":
				out.RuntimePresent = true // a systemd unit always "exists" enough to query is-active
				out.RuntimeRunning = r.Result.RC == 0
			}
		}
	}

	if r, found := find("readiness"); found && ok(r) {
		out.ReadinessConfigured = true
		if _, status, split := SplitHTTPStatus(r.Result.Stdout); split {
			out.ReadinessHTTPStatus = status
			out.ReadinessOK = status >= 200 && status < 300
		}
	}

	if r, found := find("recent-errors"); found && ok(r) {
		out.RecentErrorLines = truncateLines(nonEmptyLines(r.Result.Stdout), 30)
	}

	for i, dep := range dependencyChecks {
		res := DependencyEndpointResult{Component: dep.Component, Host: dep.Host, Port: dep.Port}
		if r, found := find(fmt.Sprintf("dependency-%d", i)); found && ok(r) {
			res.Reachable = strings.TrimSpace(r.Result.Stdout) == "reachable"
		}
		out.DependencyResults = append(out.DependencyResults, res)
	}

	out.Verdict = classifyComponentHealth(out)
	return out
}

func classifyComponentHealth(out ComponentOutput) string {
	degraded := false
	// A runtime that doesn't exist at all (docker container never
	// created/removed) is confident evidence of "down", not a gap in
	// evidence — RuntimePresent=false implies RuntimeRunning=false too,
	// so this single check covers both.
	if out.RuntimeConfigured && !out.RuntimePresent {
		degraded = true
	}
	if out.RuntimeConfigured && out.RuntimePresent && !out.RuntimeRunning {
		degraded = true
	}
	if out.ReadinessConfigured && !out.ReadinessOK {
		degraded = true
	}
	for _, dep := range out.DependencyResults {
		if !dep.Reachable {
			degraded = true
		}
	}
	if degraded {
		return "degraded"
	}
	return "healthy"
}
