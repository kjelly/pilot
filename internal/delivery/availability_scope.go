package delivery

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/inventory"
)

// DeferredReason explains why a host was excluded from the effective
// execution scope for the current run. Deferred is never the same as
// successfully converged (spec §6).
type DeferredReason string

const (
	// DeferredUnavailable: the host itself was transport-unreachable at
	// the pre-run availability probe.
	DeferredUnavailable DeferredReason = "unavailable"
	// DeferredDependencyUnavailable: the host is itself reachable, but a
	// required provider endpoint it depends on is not (spec §16).
	DeferredDependencyUnavailable DeferredReason = "dependency_unavailable"
	// DeferredRuntimeUnreachable: the host was reachable at the pre-run
	// probe but became transport-unreachable during Ansible execution —
	// the mid-run shutdown race (spec §17).
	DeferredRuntimeUnreachable DeferredReason = "runtime_unreachable"
)

// DeferredHost is one host excluded from the effective execution scope.
type DeferredHost struct {
	Host   string
	Policy inventory.DeploymentAvailability
	Reason DeferredReason
	// Dependency names the unavailable provider endpoint/component that
	// caused a DeferredDependencyUnavailable deferral. Empty otherwise.
	Dependency string
}

// ExecutionScope is the result of applying deployment-availability policy
// to a candidate host list: which hosts remain in scope for the current
// Ansible run, which were deferred, and which block deployment outright.
// All fields are deterministically sorted and free of duplicate host
// names.
type ExecutionScope struct {
	Candidates []string
	Included   []string
	Deferred   []DeferredHost
	Blocking   []string
}

// HasManagedHosts reports whether Included contains at least one host
// other than the site-wide "localhost" controller safety play. Callers use
// this to decide whether a run is a genuine no-op — e.g. every selected
// host was optional and unavailable (spec §12.2/§21) — rather than
// launching an apply that would only ever touch localhost.
func (s ExecutionScope) HasManagedHosts() bool {
	for _, h := range s.Included {
		if h != "localhost" {
			return true
		}
	}
	return false
}

// CandidateHost is one host under consideration for the effective
// execution scope, carrying the policy/reachability facts the §12
// decision table needs.
type CandidateHost struct {
	Host string
	// Policy is the host's raw deployment_availability value; empty
	// defaults to required (inventory.DeploymentAvailability.Effective).
	Policy inventory.DeploymentAvailability
	// Reachable is the pre-run probe result for Host. Ignored when
	// Invalid is true.
	Reachable bool
	// Invalid marks a policy value that failed validation — e.g. an
	// unrecognized runtime hostvar that bypassed hosts.yml lint (spec
	// §7.6). An invalid policy always blocks, regardless of
	// reachability: "unknown policy value MUST fail before mutation
	// even if the input bypassed hosts.yml lint."
	Invalid bool
}

// ResolveExecutionScope applies spec §12's decision table to candidates.
// It is pure and network-free: all reachability facts must already be
// known (from an availability probe) before calling this.
//
// Decision table:
//   - Invalid policy                        -> Blocking, regardless of Reachable.
//   - reachable                              -> Included.
//   - unreachable + effective policy optional -> Deferred (DeferredUnavailable).
//   - unreachable + effective policy required (including missing/empty) -> Blocking.
//
// Duplicate Host entries in candidates collapse to their first occurrence.
// Output lists are sorted for deterministic evidence/output regardless of
// input order.
func ResolveExecutionScope(candidates []CandidateHost) ExecutionScope {
	var scope ExecutionScope
	seen := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		if seen[c.Host] {
			continue
		}
		seen[c.Host] = true
		scope.Candidates = append(scope.Candidates, c.Host)

		if c.Invalid {
			scope.Blocking = append(scope.Blocking, c.Host)
			continue
		}
		switch {
		case c.Reachable:
			scope.Included = append(scope.Included, c.Host)
		case c.Policy.Effective() == inventory.DeploymentAvailabilityOptional:
			scope.Deferred = append(scope.Deferred, DeferredHost{
				Host:   c.Host,
				Policy: inventory.DeploymentAvailabilityOptional,
				Reason: DeferredUnavailable,
			})
		default:
			scope.Blocking = append(scope.Blocking, c.Host)
		}
	}

	sort.Strings(scope.Candidates)
	sort.Strings(scope.Included)
	sort.Strings(scope.Blocking)
	sort.Slice(scope.Deferred, func(i, j int) bool { return scope.Deferred[i].Host < scope.Deferred[j].Host })
	return scope
}

// BuildEffectiveLimit renders includedHosts into a deterministic,
// deduplicated Ansible `--limit` value for playbook.
//
// playbooks/site.yml carries a controller-side safety play on localhost
// (spec §13); an effective limit built for it always includes "localhost"
// first, even if includedHosts does not already contain it, so an
// auto-generated limit can never accidentally exclude that play. No other
// playbook gets this treatment — a single-component playbook's own scope
// is unaffected.
func BuildEffectiveLimit(playbook string, includedHosts []string) string {
	seen := make(map[string]bool, len(includedHosts)+1)
	var hosts []string
	if isSiteYML(playbook) {
		hosts = append(hosts, "localhost")
		seen["localhost"] = true
	}
	sorted := append([]string(nil), includedHosts...)
	sort.Strings(sorted)
	for _, h := range sorted {
		if seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	return strings.Join(hosts, ",")
}

func isSiteYML(playbook string) bool {
	return filepath.Base(playbook) == "site.yml"
}
