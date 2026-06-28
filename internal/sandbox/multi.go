package sandbox

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// multiEnv is a MultiEnvironment composed of one Environment per
// HostSpec, with a name lookup for ansible inventory generation.
// All lifecycle calls (Start/Stop) fan out to the underlying hosts;
// per-host exec/read/write go through Host(name).X(...).
//
// Returned by NewMultiEnvironment; callers normally hold it as the
// MultiEnvironment interface.
type multiEnv struct {
	topo  Topology
	hosts map[string]Environment

	mu sync.Mutex
	// started is set true after Start; guarded by mu for use in
	// concurrent tool goroutines.
	started bool
}

// NewMultiEnvironment wraps one Environment per HostSpec. The
// returned MultiEnvironment has NOT been started; call Start() next.
//
// Returns the concrete *multiEnv (not the interface) so callers can
// also reach package-private helpers if needed. The Go community
// convention "accept interfaces, return concrete types" applies
// here — most callers store it as MultiEnvironment, tests can
// type-assert if they need internals.
func NewMultiEnvironment(topo Topology, hosts map[string]Environment) *multiEnv {
	return &multiEnv{topo: topo, hosts: hosts}
}

// Start brings every host up. If any one fails, the already-started
// ones are stopped before returning so we never leak containers.
func (m *multiEnv) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return nil
	}
	var started []Environment
	for name, env := range m.hosts {
		if err := env.Start(ctx); err != nil {
			for _, s := range started {
				_ = s.Stop(ctx)
			}
			return fmt.Errorf("start host %q: %w", name, err)
		}
		started = append(started, env)
	}
	m.started = true
	return nil
}

// Stop tears every host down. Idempotent.
func (m *multiEnv) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		return nil
	}
	var firstErr error
	for name, env := range m.hosts {
		if err := env.Stop(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("stop host %q: %w", name, err)
		}
	}
	m.started = false
	return firstErr
}

// Host returns the Environment for a named host. Empty string or
// unknown name returns nil. Use this when the tool has explicit
// per-host routing.
func (m *multiEnv) Host(name string) Environment {
	return m.hosts[name]
}

// Hosts returns the underlying hosts map (read-only copy).
func (m *multiEnv) Hosts() map[string]Environment {
	out := make(map[string]Environment, len(m.hosts))
	for k, v := range m.hosts {
		out[k] = v
	}
	return out
}

// ConnectionInfo returns the docker connection for the first host
// in topology order. Single-host semantics: the inventory generation
// in run_playbook.go treats MultiEnvironment as a single inventory
// target by collapsing all hosts to the first one. Use
// Host(name).ConnectionInfo() for per-host routing.
//
// Returns the zero AnsibleConnection (ConnectionType="") when the
// multi-host environment has no hosts; callers MUST check
// ConnectionType before using the result.
//
// We deliberately walk m.topo.Hosts (not the map) so the result is
// stable across calls — relying on Go map iteration order would mean
// the same playbook produces different inventories on every run.
func (m *multiEnv) ConnectionInfo() AnsibleConnection {
	for _, hs := range m.topo.Hosts {
		if env, ok := m.hosts[hs.Name]; ok {
			return env.ConnectionInfo()
		}
	}
	return AnsibleConnection{}
}

// IsAvailable checks every host's environment in turn.
func (m *multiEnv) IsAvailable(ctx context.Context) error {
	if len(m.hosts) == 0 {
		return fmt.Errorf("multi-host environment has no hosts")
	}
	for name, env := range m.hosts {
		if err := env.IsAvailable(ctx); err != nil {
			return fmt.Errorf("host %q: %w", name, err)
		}
	}
	return nil
}

// Name returns a short label of the form "docker:multi(<n> hosts)"
// where <n> is the host count. Used in banner / logs.
func (m *multiEnv) Name() string {
	if len(m.hosts) == 0 {
		return "docker:multi(<empty>)"
	}
	names := make([]string, 0, len(m.hosts))
	for _, hs := range m.topo.Hosts {
		if _, ok := m.hosts[hs.Name]; ok {
			names = append(names, hs.Name)
		}
	}
	return fmt.Sprintf("docker:multi(%d hosts: %s)",
		len(m.hosts), strings.Join(names, ","))
}

// Topology returns the topology this environment was built from.
func (m *multiEnv) Topology() Topology { return m.topo }
