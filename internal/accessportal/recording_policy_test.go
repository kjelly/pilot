package accessportal

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/freeipaaccess"
)

var gpuGateway = GatewayConfig{ID: "gpu-01", Scope: "gpu", TargetHostgroup: "pilot-target-gpu"}

func resolveGPU(t *testing.T, p freeipaaccess.Provider) map[string]HostAccess {
	t.Helper()
	snapshot, err := LoadPolicySnapshot(context.Background(), p, "alice", time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("LoadPolicySnapshot: %v", err)
	}
	access, err := ResolveScopeAccess(context.Background(), p, snapshot, gpuGateway)
	if err != nil {
		t.Fatalf("ResolveScopeAccess: %v", err)
	}
	out := map[string]HostAccess{}
	for _, h := range access.Hosts {
		out[h.FQDN] = h
	}
	return out
}

func TestResolveScopeAccess_CarriesRecordingOverride(t *testing.T) {
	p := gpuScenarioProvider()
	p.hosts = map[string]freeipaaccess.Host{
		"gpu-a.ipa.pilot.internal": {FQDN: "gpu-a.ipa.pilot.internal", SSHRecording: freeipaaccess.HostRecordingPolicy{Present: true, Mode: "terminal_output", Valid: true}},
		"gpu-b.ipa.pilot.internal": {FQDN: "gpu-b.ipa.pilot.internal", SSHRecording: freeipaaccess.HostRecordingPolicy{Present: true, Mode: "off", Valid: true}},
	}
	hosts := resolveGPU(t, p)
	if got, want := hosts["gpu-a.ipa.pilot.internal"].SSHRecording, (SSHRecordingAccessPolicy{Override: "terminal_output", Known: true, Valid: true}); got != want {
		t.Errorf("gpu-a SSHRecording = %+v, want %+v", got, want)
	}
	if got := hosts["gpu-b.ipa.pilot.internal"].SSHRecording; got.Override != "off" || got.Status() != RecordingStatusOff {
		t.Errorf("gpu-b SSHRecording = %+v (status %s), want off", got, got.Status())
	}
}

func TestResolveScopeAccess_RecordingPolicyKnown(t *testing.T) {
	p := gpuScenarioProvider() // default fake hosts: absent-and-valid policy
	for fqdn, h := range resolveGPU(t, p) {
		if got := h.SSHRecording; got != (SSHRecordingAccessPolicy{Known: true, Valid: true}) || got.Status() != RecordingStatusInherit {
			t.Errorf("%s SSHRecording = %+v (status %s), want known/valid inherit", fqdn, got, got.Status())
		}
	}
}

func TestResolveScopeAccess_InvalidAndUnreadablePolicy(t *testing.T) {
	p := gpuScenarioProvider()
	p.hosts = map[string]freeipaaccess.Host{
		"gpu-a.ipa.pilot.internal": {FQDN: "gpu-a.ipa.pilot.internal", SSHRecording: freeipaaccess.HostRecordingPolicy{Present: true, Reason: "duplicate"}},
		"gpu-b.ipa.pilot.internal": {FQDN: "gpu-b.ipa.pilot.internal", SSHRecording: freeipaaccess.HostRecordingPolicy{Unreadable: true, Reason: "userclass_unreadable"}},
	}
	hosts := resolveGPU(t, p)
	if got := hosts["gpu-a.ipa.pilot.internal"].SSHRecording; got != (SSHRecordingAccessPolicy{Known: true, Reason: "duplicate"}) || got.Status() != RecordingStatusInvalid {
		t.Errorf("gpu-a SSHRecording = %+v (status %s), want known invalid duplicate", got, got.Status())
	}
	if got := hosts["gpu-b.ipa.pilot.internal"].SSHRecording; got != (SSHRecordingAccessPolicy{Reason: "userclass_unreadable"}) || got.Status() != RecordingStatusUnknown {
		t.Errorf("gpu-b SSHRecording = %+v (status %s), want unknown userclass_unreadable", got, got.Status())
	}
}

func TestResolveScopeAccess_HostShowFailureMarksPolicyUnknown(t *testing.T) {
	p := gpuScenarioProvider()
	p.hostShowErr = map[string]error{"gpu-a.ipa.pilot.internal": errors.New("transient host_show failure")}
	hosts := resolveGPU(t, p)
	a, ok := hosts["gpu-a.ipa.pilot.internal"]
	if !ok {
		t.Fatal("gpu-a must still be listed when only its host_show failed")
	}
	if a.SSHRecording != (SSHRecordingAccessPolicy{Reason: "host_show_failed"}) || a.SSHRecording.Status() != RecordingStatusUnknown {
		t.Fatalf("gpu-a SSHRecording = %+v, want unknown host_show_failed", a.SSHRecording)
	}
	if a.Annotations != nil {
		t.Fatalf("gpu-a annotations = %v, want none on failure", a.Annotations)
	}
}

func TestResolveScopeAccess_AnnotationsStillBestEffort(t *testing.T) {
	p := gpuScenarioProvider()
	p.hosts = map[string]freeipaaccess.Host{
		"gpu-b.ipa.pilot.internal": {FQDN: "gpu-b.ipa.pilot.internal", Annotations: map[string]string{"owner": "qa"}, SSHRecording: freeipaaccess.HostRecordingPolicy{Valid: true}},
	}
	p.hostShowErr = map[string]error{"gpu-a.ipa.pilot.internal": errors.New("boom")}
	hosts := resolveGPU(t, p)
	if len(hosts) != 2 {
		t.Fatalf("listing must keep both hosts despite one host_show failure, got %d", len(hosts))
	}
	if hosts["gpu-b.ipa.pilot.internal"].Annotations["owner"] != "qa" {
		t.Fatalf("gpu-b annotations lost: %+v", hosts["gpu-b.ipa.pilot.internal"])
	}
}

func TestSSHRecordingAccessPolicyStatus(t *testing.T) {
	cases := []struct {
		p    SSHRecordingAccessPolicy
		want string
	}{
		{SSHRecordingAccessPolicy{}, RecordingStatusUnknown},
		{SSHRecordingAccessPolicy{Known: true}, RecordingStatusInvalid},
		{SSHRecordingAccessPolicy{Known: true, Valid: true}, RecordingStatusInherit},
		{SSHRecordingAccessPolicy{Known: true, Valid: true, Override: "off"}, RecordingStatusOff},
		{SSHRecordingAccessPolicy{Known: true, Valid: true, Override: "terminal_output"}, RecordingStatusTerminalOutput},
		{SSHRecordingAccessPolicy{Known: true, Valid: true, Override: "terminal_io"}, RecordingStatusInvalid},
	}
	for _, c := range cases {
		if got := c.p.Status(); got != c.want {
			t.Errorf("Status(%+v) = %q, want %q", c.p, got, c.want)
		}
	}
}

// countingProvider is a concurrency-safe HostShow counter layered over a
// fakeProvider (whose own HostShow bookkeeping is not goroutine-safe).
type countingProvider struct {
	*fakeProvider
	mu    sync.Mutex
	calls map[string]int
	block map[string]chan struct{} // HostShow(fqdn) waits on this channel when set
}

func (c *countingProvider) HostShow(ctx context.Context, fqdn string) (freeipaaccess.Host, error) {
	c.mu.Lock()
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	c.calls[fqdn]++
	ch := c.block[fqdn]
	c.mu.Unlock()
	if ch != nil {
		select {
		case <-ch:
		case <-ctx.Done():
			return freeipaaccess.Host{}, ctx.Err()
		}
	}
	return freeipaaccess.NewHostWithoutPolicy(fqdn), nil
}

func TestResolveScopeAccess_OneHostShowPerFQDN(t *testing.T) {
	p := &countingProvider{fakeProvider: gpuScenarioProvider()}
	snapshot, err := LoadPolicySnapshot(context.Background(), p, "alice", time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ResolveScopeAccess(context.Background(), p, snapshot, gpuGateway); err != nil {
				t.Errorf("ResolveScopeAccess: %v", err)
			}
		}()
	}
	wg.Wait()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, fqdn := range []string{"gpu-a.ipa.pilot.internal", "gpu-b.ipa.pilot.internal"} {
		if p.calls[fqdn] != 1 {
			t.Errorf("HostShow(%s) called %d times across concurrent resolves, want exactly 1", fqdn, p.calls[fqdn])
		}
	}
}

// TestHostMetadataCache_NotHeldAcrossRPC proves one host's slow host_show
// does not serialize lookups of a different host behind a global lock.
func TestHostMetadataCache_NotHeldAcrossRPC(t *testing.T) {
	release := make(chan struct{})
	p := &countingProvider{fakeProvider: gpuScenarioProvider(), block: map[string]chan struct{}{"slow.example": release}}
	cache := newHostMetadataCache()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	slowDone := make(chan hostMetadataResult, 1)
	go func() { slowDone <- cache.get(ctx, p, "slow.example") }()

	// Wait until the slow lookup is actually inside HostShow.
	for {
		p.mu.Lock()
		started := p.calls["slow.example"] == 1
		p.mu.Unlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}

	fastDone := make(chan hostMetadataResult, 1)
	go func() { fastDone <- cache.get(ctx, p, "fast.example") }()
	select {
	case res := <-fastDone:
		if res.Err != nil || res.Host.FQDN != "fast.example" {
			t.Fatalf("fast lookup = %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a different host's lookup blocked behind an in-flight host_show")
	}
	close(release)
	if res := <-slowDone; res.Err != nil {
		t.Fatalf("slow lookup failed: %v", res.Err)
	}
}
