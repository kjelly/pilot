package sandbox

import (
	"context"
	"os"
	"testing"
)

func TestMultiEnvironment_NameIncludesHosts(t *testing.T) {
	// Topology order matches map keys: callers usually populate both.
	topo := Topology{Hosts: []HostSpec{{Name: "web01"}, {Name: "db01"}}}
	hosts := map[string]Environment{
		"web01": NewLocalEnvironment(),
		"db01":  NewLocalEnvironment(),
	}
	m := NewMultiEnvironment(topo, hosts)
	if !contains(m.Name(), "2 hosts") {
		t.Errorf("Name should mention 2 hosts: %q", m.Name())
	}
	if !contains(m.Name(), "web01") || !contains(m.Name(), "db01") {
		t.Errorf("Name should list host names: %q", m.Name())
	}
}

func TestMultiEnvironment_NameFollowsTopologyOrder(t *testing.T) {
	// Name must list hosts in topology order, not map order.
	topo := Topology{Hosts: []HostSpec{
		{Name: "c"}, {Name: "a"}, {Name: "b"},
	}}
	hosts := map[string]Environment{
		"a": NewLocalEnvironment(),
		"b": NewLocalEnvironment(),
		"c": NewLocalEnvironment(),
	}
	m := NewMultiEnvironment(topo, hosts)
	// Expected order: c, a, b
	if got := m.Name(); got != "docker:multi(3 hosts: c,a,b)" {
		t.Errorf("Name = %q, want deterministic topology order", got)
	}
}

func TestMultiEnvironment_NameEmpty(t *testing.T) {
	m := NewMultiEnvironment(Topology{}, map[string]Environment{})
	if !contains(m.Name(), "empty") {
		t.Errorf("Name should signal empty: %q", m.Name())
	}
}

func TestMultiEnvironment_StartStop_NoDocker(t *testing.T) {
	topo := Topology{Hosts: []HostSpec{{Name: "web01"}, {Name: "db01"}}}
	hosts := map[string]Environment{
		"web01": NewLocalEnvironment(),
		"db01":  NewLocalEnvironment(),
	}
	m := NewMultiEnvironment(topo, hosts)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop again: %v", err)
	}
}

func TestMultiEnvironment_HostLookup(t *testing.T) {
	web := NewLocalEnvironment()
	db := NewLocalEnvironment()
	topo := Topology{Hosts: []HostSpec{{Name: "web01"}, {Name: "db01"}}}
	hosts := map[string]Environment{"web01": web, "db01": db}
	m := NewMultiEnvironment(topo, hosts)
	if m.Host("web01") != web {
		t.Errorf("Host(web01) mismatch")
	}
	if m.Host("db01") != db {
		t.Errorf("Host(db01) mismatch")
	}
	if m.Host("missing") != nil {
		t.Errorf("missing host should return nil")
	}
}

func TestMultiEnvironment_ConnectionInfo_FirstHost(t *testing.T) {
	topo := Topology{Hosts: []HostSpec{{Name: "web01"}}}
	m := NewMultiEnvironment(topo, map[string]Environment{
		"web01": NewLocalEnvironment(),
	})
	ci := m.ConnectionInfo()
	if ci.ConnectionType != "local" {
		t.Errorf("ConnectionInfo should use first host's: got %q", ci.ConnectionType)
	}
}

func TestMultiEnvironment_ConnectionInfo_FollowsTopologyOrder(t *testing.T) {
	// Reproduces C2: ConnectionInfo must pick the host by topology
	// order, NOT by Go's non-deterministic map iteration. We use a
	// docker-flavoured fake env that exposes ContainerID = its name,
	// so we can tell which one wins.
	topo := Topology{Hosts: []HostSpec{
		{Name: "c"}, {Name: "a"}, {Name: "b"},
	}}
	m := NewMultiEnvironment(topo, map[string]Environment{
		"a": &namedEnv{name: "a"},
		"b": &namedEnv{name: "b"},
		"c": &namedEnv{name: "c"},
	})
	ci := m.ConnectionInfo()
	if ci.ContainerID != "c" {
		t.Errorf("ConnectionInfo should pick topology[0]=c, got ContainerID=%q", ci.ContainerID)
	}
	// Determinism: re-call and verify identical result.
	ci2 := m.ConnectionInfo()
	if ci.ContainerID != ci2.ContainerID {
		t.Errorf("ConnectionInfo not deterministic: %q vs %q", ci.ContainerID, ci2.ContainerID)
	}
}

func TestMultiEnvironment_ConnectionInfo_EmptyHosts(t *testing.T) {
	m := NewMultiEnvironment(Topology{}, map[string]Environment{})
	ci := m.ConnectionInfo()
	// C2 fix: zero value, not a misleading "docker" fallback.
	if ci.ConnectionType != "" {
		t.Errorf("empty multi-env should return zero ConnectionInfo, got %q", ci.ConnectionType)
	}
}

func TestMultiEnvironment_IsAvailable_Empty(t *testing.T) {
	m := NewMultiEnvironment(Topology{}, map[string]Environment{})
	if err := m.IsAvailable(context.Background()); err == nil {
		t.Error("empty multi-env should fail IsAvailable")
	}
}

func TestMultiEnvironment_TopologyRoundTrip(t *testing.T) {
	topo, err := ParseTopology("web01:webservers, db01:dbservers")
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]Environment{
		"web01": NewLocalEnvironment(),
		"db01":  NewLocalEnvironment(),
	}
	m := NewMultiEnvironment(topo, hosts)
	if m.Topology().IsEmpty() {
		t.Error("topology lost")
	}
	if len(m.Topology().Groups()) != 2 {
		t.Errorf("groups lost: %v", m.Topology().Groups())
	}
}

func TestMultiEnvironment_HostsIsReadOnlyCopy(t *testing.T) {
	topo := Topology{Hosts: []HostSpec{{Name: "web01"}}}
	m := NewMultiEnvironment(topo, map[string]Environment{"web01": NewLocalEnvironment()})
	hosts := m.Hosts()
	if len(hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(hosts))
	}
	delete(hosts, "web01")
	if len(m.Hosts()) != 1 {
		t.Errorf("Hosts() should return a defensive copy")
	}
}

// namedEnv is a test stub that returns a ConnectionInfo whose
// ContainerID equals the env's name. Used to verify ConnectionInfo
// picks the topology-ordered host.
type namedEnv struct{ name string }

func (n *namedEnv) Start(_ context.Context) error                       { return nil }
func (n *namedEnv) Stop(_ context.Context) error                        { return nil }
func (n *namedEnv) Exec(_ context.Context, _ []string, _ ExecOptions) (*ExecResult, error) {
	return &ExecResult{}, nil
}
func (n *namedEnv) ReadFile(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (n *namedEnv) WriteFile(_ context.Context, _ string, _ []byte, _ os.FileMode) error {
	return nil
}
func (n *namedEnv) ConnectionInfo() AnsibleConnection {
	return AnsibleConnection{ConnectionType: "docker", ContainerID: n.name, Host: n.name}
}
func (n *namedEnv) IsAvailable(_ context.Context) error { return nil }
func (n *namedEnv) Name() string                        { return "named:" + n.name }
