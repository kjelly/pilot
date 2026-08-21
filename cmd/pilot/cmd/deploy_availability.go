// deploy_availability.go wires internal/availability's transport probing and
// internal/delivery's execution-scope resolver into executeRecordedDeployment
// — the single funnel every deploy/reconcile/site/single-component path
// shares — so an optional host that an external operator has intentionally
// powered off does not fail a deployment (see spec.md, "Pilot Optional-Host
// Deployment Availability Specification"). This file never manages VM power
// state and never invokes ansible-playbook itself; it only classifies
// transport reachability before executeRecordedDeployment's existing apply
// path runs.
package cmd

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/availability"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/inventory"
)

// deployAvailabilityProber is the internal/availability.Prober used by
// resolveDeploymentAvailability. Production always uses a real TCP prober;
// tests that fake ansible/ansible-inventory binaries with host names that
// resolve to nothing real override this (see stubDeploymentAvailabilityAllReachable
// in deploy_availability_test.go) so the availability gate does not depend
// on those names being genuinely dialable.
var deployAvailabilityProber availability.Prober = availability.TCPProber{}

// resolveDeploymentAvailability probes every host in hosts, plus any
// contract dependency support host outside that set (spec §16.2), and
// applies the required/optional deployment-availability decision table
// (spec §12) together with contract provider-dependency gating (spec §16).
// It resolves hostvars through the existing resolveInventoryVariables path
// (spec §7.6/§22) rather than a second inventory reader. localhost — the
// playbooks/site.yml controller-side safety play — is never a policy-bearing
// candidate; it is always left for Ansible's own targeting, unchanged.
func resolveDeploymentAvailability(ctx context.Context, inv string, hosts []string, selected []contract.Contract, scope delivery.Scope, extraVars []string, vault vaultInput) (delivery.ExecutionScope, map[string]string, map[string]bool, error) {
	hostVars, err := resolveInventoryVariables(ctx, inv, extraVars, vault)
	if err != nil {
		return delivery.ExecutionScope{}, nil, nil, fmt.Errorf("resolve deployment availability: %w", err)
	}

	supportHosts := delivery.DependencySupportHosts(selected, scope, nil)
	probeSet := uniqueSortedHosts(append(append([]string{}, hosts...), supportHosts...))

	runtimeByHost := make(map[string]availability.RuntimeHost, len(probeSet))
	invalidReasons := make(map[string]string)
	var endpoints []availability.Endpoint
	for _, host := range probeSet {
		if host == "localhost" {
			continue
		}
		rh := availability.ResolveRuntimeHost(host, hostVars[host])
		runtimeByHost[host] = rh
		if !rh.DeploymentAvailability.Valid() {
			// spec §7.6/§12.1: an unrecognized deployment_availability value
			// must fail validation before mutation regardless of
			// reachability — a policy typo on a host that happens to be up
			// right now must never silently pass as if it were valid.
			invalidReasons[host] = fmt.Sprintf("invalid deployment_availability value %q", string(rh.DeploymentAvailability))
			continue
		}
		support := availability.ClassifyConnectionSupport(rh)
		if support.Fatal {
			invalidReasons[host] = support.Reason
			continue
		}
		if ep, ok := availability.ResolveEndpoint(rh); ok {
			endpoints = append(endpoints, ep)
		}
	}

	results := availability.ProbeAll(ctx, deployAvailabilityProber, endpoints, availability.DefaultMaxConcurrentProbes)
	reachable := make(map[string]bool, len(results))
	for _, r := range results {
		reachable[r.Host] = r.State == availability.ProbeReachable
	}

	candidates := make([]delivery.CandidateHost, 0, len(hosts))
	// optionalHosts records, for every candidate mutation host, whether its
	// effective deployment_availability policy is optional. Phase 6's
	// mid-run shutdown-race classifier (internal/ansible.ClassifyDeploymentOutcome)
	// needs exactly this set to decide whether a host that disappears
	// *during* the apply run may be excused (spec §17.5) — recomputing it
	// from scratch there would mean a second, possibly-drifting read of the
	// same policy this function already resolved.
	optionalHosts := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		if host == "localhost" {
			continue
		}
		if _, invalid := invalidReasons[host]; invalid {
			candidates = append(candidates, delivery.CandidateHost{Host: host, Invalid: true})
			continue
		}
		rh := runtimeByHost[host]
		optionalHosts[host] = rh.DeploymentAvailability.Effective() == inventory.DeploymentAvailabilityOptional
		isReachable := reachable[host]
		if !availability.ClassifyConnectionSupport(rh).Probable {
			// Local controller plays (spec §9.3) and non-SSH connections
			// left at required policy are never gated by this feature —
			// Ansible's own connection handling stays authoritative,
			// exactly as it was before this feature existed.
			isReachable = true
		}
		candidates = append(candidates, delivery.CandidateHost{
			Host:      host,
			Policy:    rh.DeploymentAvailability,
			Reachable: isReachable,
		})
	}

	execScope := delivery.ResolveExecutionScopeWithDependencies(delivery.DependencyAvailabilityRequest{
		Candidates:        candidates,
		Selected:          selected,
		Scope:             scope,
		ProviderSelection: nil,
		Reachable:         reachable,
	})
	return execScope, invalidReasons, optionalHosts, nil
}

// effectiveDeploymentLimit returns limit unchanged whenever every candidate
// host stayed included — the common case where nothing is offline — so a
// run with no optional-offline hosts produces byte-identical
// ansible-playbook argv to before this feature existed. Only when
// includedHosts is a strict subset of candidateHosts does it synthesize a
// fresh --limit value via delivery.BuildEffectiveLimit.
func effectiveDeploymentLimit(playbook, limit string, candidateHosts, includedHosts []string) string {
	if len(includedHosts) == len(candidateHosts) {
		return limit
	}
	return delivery.BuildEffectiveLimit(playbook, includedHosts)
}

// uniqueSortedHosts dedupes and sorts host, used to build one probe set from
// mutation candidates plus dependency support hosts that may overlap.
func uniqueSortedHosts(hosts []string) []string {
	seen := make(map[string]bool, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// printAvailabilityBlocked reports required hosts that were unavailable
// before any mutation occurred (spec §19 "Deployment blocked before
// mutation").
func printAvailabilityBlocked(out io.Writer, blocking []string, invalidReasons map[string]string) {
	fmt.Fprintln(out, "❌ 部署在套用前中止 — 以下必要主機目前無法連線：")
	for _, host := range blocking {
		if reason, ok := invalidReasons[host]; ok {
			fmt.Fprintf(out, "  - %s（%s）\n", host, reason)
			continue
		}
		fmt.Fprintf(out, "  - %s\n", host)
	}
}

// printAvailabilityNoOp reports a successful no-op deployment: every
// candidate host was optional and currently unavailable (spec §12.2/§29
// Scenario J), so no apply playbook was invoked.
func printAvailabilityNoOp(out io.Writer, deferred []delivery.DeferredHost) {
	fmt.Fprintln(out, "沒有可佈署的主機 — 所有選定主機皆為 optional 且目前無法連線，不會執行 apply：")
	printDeferredHosts(out, deferred)
}

// printAvailabilitySummary reports the effective scope and any deferred
// hosts before the apply path runs (spec §19).
func printAvailabilitySummary(out io.Writer, scope delivery.ExecutionScope) {
	fmt.Fprintln(out, "═══ Deployment availability ═══")
	fmt.Fprintf(out, "Effective deployment scope: %d 台主機\n", len(scope.Included))
	if len(scope.Deferred) == 0 {
		return
	}
	fmt.Fprintln(out, "Deferred:")
	printDeferredHosts(out, scope.Deferred)
}

func printDeferredHosts(out io.Writer, deferred []delivery.DeferredHost) {
	for _, d := range deferred {
		if d.Dependency != "" {
			fmt.Fprintf(out, "  ○ %s — deferred（%s: %s）\n", d.Host, d.Reason, d.Dependency)
			continue
		}
		fmt.Fprintf(out, "  ○ %s — deferred（%s）\n", d.Host, d.Reason)
	}
}

// deferredHostsMetadata renders deferred into deploymentMetadata's
// non-sensitive audit map (spec §32) as "<host>:<reason>[:<dependency>]"
// entries, sorted for deterministic evidence.
func deferredHostsMetadata(deferred []delivery.DeferredHost) []string {
	if len(deferred) == 0 {
		return nil
	}
	entries := make([]string, 0, len(deferred))
	for _, d := range deferred {
		if d.Dependency != "" {
			entries = append(entries, fmt.Sprintf("%s:%s:%s", d.Host, d.Reason, d.Dependency))
			continue
		}
		entries = append(entries, fmt.Sprintf("%s:%s", d.Host, d.Reason))
	}
	sort.Strings(entries)
	return entries
}

// deploymentBlockedError formats the non-zero error returned when a
// required host in the selected deployment scope is unavailable before
// mutation (spec §19/§29 Scenario B).
func deploymentBlockedError(blocking []string, invalidReasons map[string]string) error {
	details := make([]string, 0, len(blocking))
	for _, host := range blocking {
		if reason, ok := invalidReasons[host]; ok {
			details = append(details, fmt.Sprintf("%s（%s）", host, reason))
			continue
		}
		details = append(details, host)
	}
	return fmt.Errorf("部署在套用前中止：必要主機無法連線：%s", strings.Join(details, ", "))
}
