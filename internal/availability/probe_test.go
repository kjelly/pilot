package availability

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/inventory"
)

// fakeConn is the minimal net.Conn a test dial needs to hand back; it
// records whether Close was called so tests can assert TCPProber closes
// successful sockets immediately (spec §9.4).
type fakeConn struct {
	net.Conn
	closed *atomic.Bool
}

func newFakeConn() (net.Conn, *atomic.Bool) {
	closed := &atomic.Bool{}
	return &fakeConn{closed: closed}, closed
}

func (f *fakeConn) Close() error {
	f.closed.Store(true)
	return nil
}

func TestTCPProber_ConnectionSucceeds(t *testing.T) {
	conn, closed := newFakeConn()
	prober := TCPProber{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return conn, nil
	}}
	got := prober.Probe(context.Background(), Endpoint{Host: "vm-01", Addr: "10.0.0.1:22"})
	if got.State != ProbeReachable {
		t.Fatalf("State = %q, want reachable", got.State)
	}
	if got.Err != nil {
		t.Fatalf("Err = %v, want nil", got.Err)
	}
	if !closed.Load() {
		t.Fatal("Probe did not close the successful connection")
	}
}

func TestTCPProber_ConnectionRefused(t *testing.T) {
	refused := errors.New("connect: connection refused")
	prober := TCPProber{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, refused
	}}
	got := prober.Probe(context.Background(), Endpoint{Host: "vm-01", Addr: "10.0.0.1:22"})
	if got.State != ProbeUnreachable {
		t.Fatalf("State = %q, want unreachable", got.State)
	}
	if !errors.Is(got.Err, refused) {
		t.Fatalf("Err = %v, want %v", got.Err, refused)
	}
}

func TestTCPProber_Timeout(t *testing.T) {
	prober := TCPProber{
		Timeout: 10 * time.Millisecond,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
				return nil, errors.New("should never get here")
			}
		},
	}
	start := time.Now()
	got := prober.Probe(context.Background(), Endpoint{Host: "vm-01", Addr: "10.0.0.1:22"})
	elapsed := time.Since(start)
	if got.State != ProbeUnreachable {
		t.Fatalf("State = %q, want unreachable", got.State)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Probe took %v, want it to respect the 10ms timeout, not the dial's 2s sleep", elapsed)
	}
}

func TestTCPProber_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	prober := TCPProber{
		Timeout: time.Second,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	start := time.Now()
	got := prober.Probe(ctx, Endpoint{Host: "vm-01", Addr: "10.0.0.1:22"})
	if got.State != ProbeUnreachable {
		t.Fatalf("State = %q, want unreachable", got.State)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("Probe did not return promptly on an already-cancelled context")
	}
}

func TestProbeAll_BoundedConcurrency(t *testing.T) {
	const maxConcurrent = 5
	var inFlight, peak int64
	endpoints := make([]Endpoint, 50)
	for i := range endpoints {
		endpoints[i] = Endpoint{Host: string(rune('a' + i)), Addr: "irrelevant"}
	}
	prober := probeFunc(func(ctx context.Context, ep Endpoint) ProbeResult {
		n := atomic.AddInt64(&inFlight, 1)
		for {
			p := atomic.LoadInt64(&peak)
			if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt64(&inFlight, -1)
		return ProbeResult{Host: ep.Host, State: ProbeReachable}
	})
	ProbeAll(context.Background(), prober, endpoints, maxConcurrent)
	if got := atomic.LoadInt64(&peak); got > maxConcurrent {
		t.Fatalf("peak concurrent probes = %d, want <= %d", got, maxConcurrent)
	}
}

func TestProbeAll_DeterministicOrderIndependentOfCompletionOrder(t *testing.T) {
	endpoints := []Endpoint{
		{Host: "vm-03", Addr: "a"},
		{Host: "vm-01", Addr: "b"},
		{Host: "vm-02", Addr: "c"},
	}
	// vm-03 finishes fastest, vm-01 slowest — completion order is the
	// reverse of alphabetical, but the result must still come back sorted.
	delay := map[string]time.Duration{
		"vm-03": 1 * time.Millisecond,
		"vm-02": 10 * time.Millisecond,
		"vm-01": 30 * time.Millisecond,
	}
	prober := probeFunc(func(ctx context.Context, ep Endpoint) ProbeResult {
		time.Sleep(delay[ep.Host])
		return ProbeResult{Host: ep.Host, State: ProbeReachable}
	})
	results := ProbeAll(context.Background(), prober, endpoints, 0)
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	want := []string{"vm-01", "vm-02", "vm-03"}
	for i, w := range want {
		if results[i].Host != w {
			t.Fatalf("results[%d].Host = %q, want %q (results: %+v)", i, results[i].Host, w, results)
		}
	}
}

func TestResolveEndpoint_NonDefaultPort(t *testing.T) {
	rh := RuntimeHost{Name: "vm-01", AnsibleHost: "10.0.0.5", AnsiblePort: 2222, AnsibleConnection: "ssh"}
	ep, ok := ResolveEndpoint(rh)
	if !ok {
		t.Fatal("ResolveEndpoint() ok = false, want true")
	}
	if ep.Addr != "10.0.0.5:2222" {
		t.Fatalf("Addr = %q, want 10.0.0.5:2222", ep.Addr)
	}
}

func TestResolveEndpoint_DefaultPortAndConnection(t *testing.T) {
	rh := RuntimeHost{Name: "vm-01", AnsibleHost: "10.0.0.5", AnsiblePort: 22, AnsibleConnection: "ssh"}
	ep, ok := ResolveEndpoint(rh)
	if !ok {
		t.Fatal("ResolveEndpoint() ok = false, want true")
	}
	if ep.Addr != "10.0.0.5:22" {
		t.Fatalf("Addr = %q, want 10.0.0.5:22", ep.Addr)
	}
}

func TestClassifyConnectionSupport_Localhost(t *testing.T) {
	got := ClassifyConnectionSupport(RuntimeHost{Name: "localhost", AnsibleConnection: "local"})
	if got.Probable || got.Fatal {
		t.Fatalf("localhost classification = %+v, want Probable=false Fatal=false", got)
	}
}

func TestClassifyConnectionSupport_UnsupportedOptionalIsFatal(t *testing.T) {
	got := ClassifyConnectionSupport(RuntimeHost{
		Name:                   "win-1",
		AnsibleConnection:      "winrm",
		DeploymentAvailability: inventory.DeploymentAvailabilityOptional,
	})
	if got.Probable {
		t.Fatalf("winrm+optional Probable = true, want false")
	}
	if !got.Fatal {
		t.Fatal("winrm+optional Fatal = false, want true (v1 has no safe prober for it)")
	}
}

func TestClassifyConnectionSupport_UnsupportedRequiredIsNotFatal(t *testing.T) {
	got := ClassifyConnectionSupport(RuntimeHost{Name: "win-1", AnsibleConnection: "winrm"})
	if got.Probable {
		t.Fatalf("winrm+required Probable = true, want false")
	}
	if got.Fatal {
		t.Fatal("winrm+required Fatal = true, want false — normal Ansible execution stays authoritative")
	}
}

func TestResolveRuntimeHost(t *testing.T) {
	rh := ResolveRuntimeHost("vm-01", map[string]any{
		"ansible_host":            "10.0.0.5",
		"ansible_port":            2222,
		"deployment_availability": "optional",
	})
	if rh.AnsibleHost != "10.0.0.5" || rh.AnsiblePort != 2222 || rh.AnsibleConnection != "ssh" {
		t.Fatalf("got %+v", rh)
	}
	if rh.DeploymentAvailability != inventory.DeploymentAvailabilityOptional {
		t.Fatalf("DeploymentAvailability = %q, want optional", rh.DeploymentAvailability)
	}
}

func TestResolveRuntimeHost_DefaultsWhenHostvarsOmitFields(t *testing.T) {
	rh := ResolveRuntimeHost("ipa-1", map[string]any{"ansible_host": "10.0.0.10"})
	if rh.AnsiblePort != 22 || rh.AnsibleConnection != "ssh" {
		t.Fatalf("got %+v, want default port 22 / connection ssh", rh)
	}
	if rh.DeploymentAvailability.Effective() != inventory.DeploymentAvailabilityRequired {
		t.Fatalf("effective policy = %q, want required", rh.DeploymentAvailability.Effective())
	}
}

// probeFunc adapts a plain function to the Prober interface for tests.
type probeFunc func(ctx context.Context, endpoint Endpoint) ProbeResult

func (f probeFunc) Probe(ctx context.Context, endpoint Endpoint) ProbeResult { return f(ctx, endpoint) }
