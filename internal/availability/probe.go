// Package availability resolves and probes the transport reachability of
// hosts declared "optional" in pilot's deployment_availability policy (see
// spec.md), so an intentionally-offline on-demand VM can be deferred from a
// deployment run instead of failing it. It never manages VM power state —
// it only observes whether a host's SSH endpoint currently answers.
package availability

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/kjelly/pilot/internal/inventory"
)

// RuntimeHost is the subset of one host's resolved Ansible inventory
// hostvars that availability filtering needs. Callers build these from
// hostvars already fetched via the existing `ansible-inventory --list`
// path (spec §7.6/§22) — this package does not shell out or parse YAML
// itself, so there is exactly one inventory-reading mechanism in pilot.
type RuntimeHost struct {
	Name                   string
	AnsibleHost            string
	AnsiblePort            int
	AnsibleConnection      string
	DeploymentAvailability inventory.DeploymentAvailability
}

// ResolveRuntimeHost extracts availability-relevant fields from name's
// already-resolved hostvars (e.g. one entry of `_meta.hostvars` from
// `ansible-inventory --list`). Unset ansible_port/ansible_connection
// resolve to Ansible's own defaults (22/ssh) so callers can compare
// RuntimeHost values without re-deriving those defaults themselves.
func ResolveRuntimeHost(name string, vars map[string]any) RuntimeHost {
	rh := RuntimeHost{Name: name, AnsiblePort: 22, AnsibleConnection: "ssh"}
	if v, ok := vars["ansible_host"]; ok {
		rh.AnsibleHost = fmt.Sprint(v)
	}
	if v, ok := vars["ansible_port"]; ok {
		if p, err := strconv.Atoi(fmt.Sprint(v)); err == nil {
			rh.AnsiblePort = p
		}
	}
	if v, ok := vars["ansible_connection"]; ok {
		rh.AnsibleConnection = fmt.Sprint(v)
	}
	if v, ok := vars["deployment_availability"]; ok {
		rh.DeploymentAvailability = inventory.DeploymentAvailability(fmt.Sprint(v))
	}
	return rh
}

// Endpoint is a resolved TCP dial target for one host's Ansible SSH
// transport.
type Endpoint struct {
	Host string // pilot/Ansible inventory host name
	Addr string // "host:port" dial target
}

// ConnectionSupport reports whether rh's connection type can be safely
// probed for v1 optional-host availability filtering (spec §9.3), and
// whether an unsupported type is fatal for this host.
type ConnectionSupport struct {
	// Probable is true only for the implicit-or-explicit SSH case this
	// package can probe.
	Probable bool
	// Fatal is true when rh declared itself optional but uses a
	// connection type v1 has no safe prober for — optional policy must
	// not silently become "never checked" for a type pilot cannot
	// observe.
	Fatal bool
	// Reason explains the classification for error messages/logging.
	Reason string
}

// ClassifyConnectionSupport decides whether rh is eligible for TCP
// availability probing at all, per spec §9.3:
//   - implicit or explicit ansible_connection=ssh: probable.
//   - localhost / a local controller play: never remote-probed, not fatal.
//   - any other connection type declared optional: fatal — v1 has no safe
//     prober for it, so silently treating it as reachable/optional would
//     hide a real gap.
//   - any other connection type declared required (or left at its
//     default, which is also required): not probable, not fatal — normal
//     Ansible execution remains authoritative for that host, unchanged
//     from today's behavior.
func ClassifyConnectionSupport(rh RuntimeHost) ConnectionSupport {
	if rh.Name == "localhost" || rh.AnsibleConnection == "local" {
		return ConnectionSupport{Reason: "local controller play is never remote-probed"}
	}
	if rh.AnsibleConnection != "" && rh.AnsibleConnection != "ssh" {
		if rh.DeploymentAvailability.Effective() == inventory.DeploymentAvailabilityOptional {
			return ConnectionSupport{
				Fatal:  true,
				Reason: fmt.Sprintf("connection %q has no safe optional-host prober in v1", rh.AnsibleConnection),
			}
		}
		return ConnectionSupport{
			Reason: fmt.Sprintf("connection %q is not SSH; normal Ansible execution remains authoritative", rh.AnsibleConnection),
		}
	}
	return ConnectionSupport{Probable: true, Reason: "ssh"}
}

// ResolveEndpoint returns rh's TCP dial target and whether rh is eligible
// for probing at all (see ClassifyConnectionSupport). ok is false when
// probing does not apply — callers must not treat that as either reachable
// or unreachable.
func ResolveEndpoint(rh RuntimeHost) (Endpoint, bool) {
	if !ClassifyConnectionSupport(rh).Probable {
		return Endpoint{}, false
	}
	host := rh.AnsibleHost
	if host == "" {
		host = rh.Name
	}
	port := rh.AnsiblePort
	if port <= 0 {
		port = 22
	}
	return Endpoint{Host: rh.Name, Addr: net.JoinHostPort(host, strconv.Itoa(port))}, true
}

// ProbeState is the outcome of a single transport-reachability probe.
type ProbeState string

const (
	// ProbeReachable means a TCP connection to the endpoint succeeded.
	// This proves transport reachability only — Ansible remains the
	// authority on auth/module/privilege validity (spec §9.2).
	ProbeReachable ProbeState = "reachable"
	// ProbeUnreachable means the TCP connection failed or the probe was
	// cancelled/timed out.
	ProbeUnreachable ProbeState = "unreachable"
)

// ProbeResult is the outcome of probing one Endpoint.
type ProbeResult struct {
	Host     string
	Endpoint string
	State    ProbeState
	Err      error
}

// DialFunc dials network/addr and is the test seam that keeps unit tests
// off real network timing (spec §9.5): inject a fake DialFunc in tests
// instead of hard-wiring net.DialTimeout into orchestration logic.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Prober probes a single endpoint for transport reachability.
// Implementations must respect ctx cancellation/deadline.
type Prober interface {
	Probe(ctx context.Context, endpoint Endpoint) ProbeResult
}

const (
	// DefaultProbeTimeout is the per-endpoint dial timeout used when
	// TCPProber.Timeout is unset (spec §9.4).
	DefaultProbeTimeout = 2 * time.Second
	// DefaultMaxConcurrentProbes bounds how many probes ProbeAll runs at
	// once when its maxConcurrent argument is <= 0 (spec §9.4).
	DefaultMaxConcurrentProbes = 32
)

// TCPProber is the v1 Prober: a plain TCP-connect reachability check
// (spec §9.1 — not ICMP). A successful connect means only that Ansible can
// proceed to its own authoritative SSH/auth/module checks.
type TCPProber struct {
	// Dial defaults to a real net.Dialer when nil.
	Dial DialFunc
	// Timeout defaults to DefaultProbeTimeout when <= 0.
	Timeout time.Duration
}

// Probe dials endpoint.Addr and closes the connection immediately on
// success; it never blocks past ctx or p.Timeout, whichever is sooner.
func (p TCPProber) Probe(ctx context.Context, endpoint Endpoint) ProbeResult {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	dial := p.Dial
	if dial == nil {
		dial = dialTCP
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(dialCtx, "tcp", endpoint.Addr)
	if err != nil {
		return ProbeResult{Host: endpoint.Host, Endpoint: endpoint.Addr, State: ProbeUnreachable, Err: err}
	}
	conn.Close()
	return ProbeResult{Host: endpoint.Host, Endpoint: endpoint.Addr, State: ProbeReachable}
}

func dialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// ProbeAll probes every endpoint concurrently, bounded by maxConcurrent
// in-flight probes at a time (DefaultMaxConcurrentProbes when
// maxConcurrent <= 0). The returned results are sorted by Host, so output
// is deterministic regardless of which probe finishes first.
func ProbeAll(ctx context.Context, prober Prober, endpoints []Endpoint, maxConcurrent int) []ProbeResult {
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrentProbes
	}
	results := make([]ProbeResult, len(endpoints))
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for i, ep := range endpoints {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, ep Endpoint) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = prober.Probe(ctx, ep)
		}(i, ep)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Host < results[j].Host })
	return results
}
