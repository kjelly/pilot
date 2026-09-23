package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/freeipaaccess"
	"github.com/kjelly/pilot/internal/gatewayapi"
	"github.com/kjelly/pilot/internal/sessionaudit"
)

// transportFakeGatewayProvider is fakeGatewayProvider (gpu-a.example.com in
// scope, HBAC-allowed) plus a controllable pilot-transport-ready hostgroup,
// host SSH keys, and a revocation switch for the fresh-authorize test.
type transportFakeGatewayProvider struct {
	fakeGatewayProvider
	ready    []string
	readyErr error
	hostKeys []string
	revoked  atomic.Bool
}

func (p *transportFakeGatewayProvider) HostgroupShow(ctx context.Context, name string) (freeipaaccess.Hostgroup, error) {
	if name == gatewayapi.TransportReadyHostgroup {
		if p.readyErr != nil {
			return freeipaaccess.Hostgroup{}, p.readyErr
		}
		return freeipaaccess.Hostgroup{Name: name, MemberHosts: p.ready}, nil
	}
	return p.fakeGatewayProvider.HostgroupShow(ctx, name)
}

func (p *transportFakeGatewayProvider) HBACRuleFind(ctx context.Context) ([]freeipaaccess.HBACRule, error) {
	if p.revoked.Load() {
		return nil, nil
	}
	return p.fakeGatewayProvider.HBACRuleFind(ctx)
}

func (p *transportFakeGatewayProvider) HostShow(ctx context.Context, fqdn string) (freeipaaccess.Host, error) {
	return freeipaaccess.Host{FQDN: fqdn, SSHPublicKeys: p.hostKeys}, nil
}

type transportGatewayOpts struct {
	enabled   bool
	ready     []string
	readyErr  error
	recording string
	hostKeys  []string
}

// startFakeTransportGateway starts a real gatewayapi.Server (the real
// authorize + transport gate over a real Unix socket, SO_PEERCRED
// included) and returns a client dialing it plus the provider for tests
// that flip revocation mid-test.
func startFakeTransportGateway(t *testing.T, opts transportGatewayOpts) (*portalClient, *transportFakeGatewayProvider) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "gw.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	gw := accessportal.GatewayConfig{ID: "gpu-01", Scope: "gpu", TargetHostgroup: "pilot-target-gpu"}
	provider := &transportFakeGatewayProvider{
		fakeGatewayProvider: fakeGatewayProvider{username: currentOSUsername(t)},
		ready:               opts.ready, readyErr: opts.readyErr, hostKeys: opts.hostKeys,
	}
	srv := gatewayapi.NewServer(gw, provider, accessportal.NewResolver(provider, gw), nil)
	srv.Transport = gatewayapi.TransportPolicy{Enabled: opts.enabled}
	srv.RecordingPolicy = gatewayapi.RecordingPolicy{Mode: opts.recording}
	go srv.Serve(ln)                                         //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown(context.Background()) }) //nolint:errcheck
	return newPortalClient(sockPath), provider
}

// fakeTransportResolver answers every lookup with the same addresses and
// counts calls/hosts, so tests can prove resolve-exactly-once.
type fakeTransportResolver struct {
	mu    sync.Mutex
	addrs []net.IPAddr
	err   error
	hosts []string
}

func (r *fakeTransportResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hosts = append(r.hosts, host)
	return r.addrs, r.err
}

func (r *fakeTransportResolver) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.hosts...)
}

// recordingTransportDialer records every requested address; addresses in
// fail are refused, everything else is connected to target (a real local
// TCP listener standing in for the target's sshd).
type recordingTransportDialer struct {
	mu     sync.Mutex
	target string
	fail   map[string]bool
	addrs  []string
}

func (d *recordingTransportDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	failed := d.fail[address]
	d.mu.Unlock()
	if failed {
		return nil, errors.New("connection refused")
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.target)
}

func (d *recordingTransportDialer) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// startEchoTarget is a TCP "target" that echoes everything it reads and
// half-closes once the client half-closes.
func startEchoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
				_ = c.(*net.TCPConn).CloseWrite()
			}(c)
		}
	}()
	return ln.Addr().String()
}

// syncBuffer is a goroutine-safe bytes.Buffer for captured audit output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) events(t *testing.T) []sessionaudit.SessionAuditEvent {
	t.Helper()
	var out []sessionaudit.SessionAuditEvent
	sc := bufio.NewScanner(strings.NewReader(b.String()))
	for sc.Scan() {
		var ev sessionaudit.SessionAuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("audit line %q: %v", sc.Text(), err)
		}
		out = append(out, ev)
	}
	return out
}

type transportHarness struct {
	deps     portalTransportDeps
	resolver *fakeTransportResolver
	dialer   *recordingTransportDialer
	stdout   *bytes.Buffer
	audit    *syncBuffer
	provider *transportFakeGatewayProvider
}

func newTransportHarness(t *testing.T, opts transportGatewayOpts, stdin io.Reader) *transportHarness {
	t.Helper()
	client, provider := startFakeTransportGateway(t, opts)
	h := &transportHarness{
		resolver: &fakeTransportResolver{addrs: []net.IPAddr{{IP: net.ParseIP("10.20.30.40")}}},
		dialer:   &recordingTransportDialer{target: startEchoTarget(t), fail: map[string]bool{}},
		stdout:   &bytes.Buffer{},
		audit:    &syncBuffer{},
		provider: provider,
	}
	h.deps = portalTransportDeps{
		client:     client,
		resolver:   h.resolver,
		dialer:     h.dialer,
		localAddrs: func() ([]net.Addr, error) { return nil, nil },
		stdin:      stdin,
		stdout:     h.stdout,
		emitter:    sessionaudit.NewEmitterWithWriter("pilot-access-gateway-test", h.audit),
	}
	return h
}

var readyGPUA = transportGatewayOpts{enabled: true, ready: []string{"gpu-a.example.com"}}

// TestRunPortalTransport_DeniedPathsNeverResolveOrDial covers AG49 (any
// deny => zero DNS and zero dials), AG51 (recording allowlist), and AG56
// (stdout stays empty; stderr text is the stable message) together.
func TestRunPortalTransport_DeniedPathsNeverResolveOrDial(t *testing.T) {
	cases := []struct {
		name       string
		opts       transportGatewayOpts
		target     string
		wantMsg    string
		wantResult string
	}{
		{"out of scope", readyGPUA, "gpu-z.example.com", transportMsgAccessDenied, "authorize_denied"},
		{"transport disabled", transportGatewayOpts{enabled: false, ready: []string{"gpu-a.example.com"}}, "gpu-a.example.com", transportMsgNotEnabled, "transport_disabled"},
		{"target not ready", transportGatewayOpts{enabled: true}, "gpu-a.example.com", transportMsgNotEnabled, "transport_target_not_ready"},
		{"ready lookup failed", transportGatewayOpts{enabled: true, readyErr: errors.New("ipa down")}, "gpu-a.example.com", transportMsgNotEnabled, "transport_ready_lookup_failed"},
		{"terminal_output recording", transportGatewayOpts{enabled: true, ready: []string{"gpu-a.example.com"}, recording: "terminal_output"}, "gpu-a.example.com", transportMsgRecordingPolicy, transportResultRecordingDeny},
		{"terminal_io recording", transportGatewayOpts{enabled: true, ready: []string{"gpu-a.example.com"}, recording: "terminal_io"}, "gpu-a.example.com", transportMsgRecordingPolicy, transportResultRecordingDeny},
		{"unknown future recording mode", transportGatewayOpts{enabled: true, ready: []string{"gpu-a.example.com"}, recording: "keystrokes"}, "gpu-a.example.com", transportMsgRecordingPolicy, transportResultRecordingDeny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTransportHarness(t, tc.opts, strings.NewReader("never sent"))
			err := runPortalTransport(context.Background(), h.deps, tc.target)
			if err == nil || err.Error() != tc.wantMsg {
				t.Fatalf("err = %v, want %q", err, tc.wantMsg)
			}
			if got := h.resolver.calls(); len(got) != 0 {
				t.Fatalf("resolver called %v on a denied path", got)
			}
			if got := h.dialer.dialed(); len(got) != 0 {
				t.Fatalf("dialer called %v on a denied path", got)
			}
			if h.stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", h.stdout.String())
			}
			evs := h.audit.events(t)
			last := evs[len(evs)-1]
			if last.Kind != sessionaudit.KindGatewayTransportDenied || last.Result != tc.wantResult {
				t.Fatalf("last audit event = %s/%s, want %s/%s", last.Kind, last.Result, sessionaudit.KindGatewayTransportDenied, tc.wantResult)
			}
		})
	}
	t.Run("recording metadata is compatible", func(t *testing.T) {
		if !transportRecordingCompatible("") || !transportRecordingCompatible("metadata") {
			t.Fatal(`"" and "metadata" must be transport-compatible`)
		}
	})
}

// TestRunPortalTransport_FreshAuthorizeEveryCall is AG50: a transport
// allowed a moment ago is denied as soon as FreeIPA stops granting it —
// nothing from the first decision is reused.
func TestRunPortalTransport_FreshAuthorizeEveryCall(t *testing.T) {
	h := newTransportHarness(t, readyGPUA, strings.NewReader("hello"))
	if err := runPortalTransport(context.Background(), h.deps, "gpu-a.example.com"); err != nil {
		t.Fatalf("first transport: %v", err)
	}
	h.provider.revoked.Store(true)
	h.deps.stdin = strings.NewReader("again")
	before := len(h.dialer.dialed())
	if err := runPortalTransport(context.Background(), h.deps, "gpu-a.example.com"); err == nil || err.Error() != transportMsgAccessDenied {
		t.Fatalf("second transport after revocation: err = %v, want %q", err, transportMsgAccessDenied)
	}
	if after := len(h.dialer.dialed()); after != before {
		t.Fatalf("revoked transport dialed again (%d -> %d)", before, after)
	}
}

// TestRunPortalTransport_ResolveOnceDialExactIP22 is AG52: one lookup of
// the gateway-canonical FQDN, then only exact <ip>:22 dials in resolver
// order, never the hostname, never a second lookup, at most three
// candidates; the audited target IP is the one actually connected.
func TestRunPortalTransport_ResolveOnceDialExactIP22(t *testing.T) {
	h := newTransportHarness(t, readyGPUA, strings.NewReader("x"))
	h.resolver.addrs = []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}, {IP: net.ParseIP("10.0.0.2")}, {IP: net.ParseIP("fd00::3")}, {IP: net.ParseIP("10.0.0.4")}}
	h.dialer.fail = map[string]bool{"10.0.0.1:22": true, "10.0.0.2:22": true}
	if err := runPortalTransport(context.Background(), h.deps, "GPU-A.example.com"); err != nil {
		t.Fatalf("transport: %v", err)
	}
	if got := h.resolver.calls(); len(got) != 1 || got[0] != "gpu-a.example.com" {
		t.Fatalf("resolver calls = %v, want exactly [gpu-a.example.com]", got)
	}
	want := []string{"10.0.0.1:22", "10.0.0.2:22", "[fd00::3]:22"}
	if got := h.dialer.dialed(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("dialed %v, want %v", got, want)
	}
	var connected *sessionaudit.SessionAuditEvent
	for _, ev := range h.audit.events(t) {
		if ev.Kind == sessionaudit.KindGatewayTransportConnected {
			ev := ev
			connected = &ev
		}
	}
	if connected == nil || connected.TargetIP != "fd00::3" || connected.TargetFQDN != "gpu-a.example.com" {
		t.Fatalf("connected event = %+v, want target_ip fd00::3 for gpu-a.example.com", connected)
	}

	t.Run("at most three candidates", func(t *testing.T) {
		h := newTransportHarness(t, readyGPUA, strings.NewReader("x"))
		h.resolver.addrs = []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}, {IP: net.ParseIP("10.0.0.2")}, {IP: net.ParseIP("10.0.0.3")}, {IP: net.ParseIP("10.0.0.4")}}
		h.dialer.fail = map[string]bool{"10.0.0.1:22": true, "10.0.0.2:22": true, "10.0.0.3:22": true, "10.0.0.4:22": true}
		if err := runPortalTransport(context.Background(), h.deps, "gpu-a.example.com"); err == nil || err.Error() != transportMsgUnavailable {
			t.Fatalf("err = %v, want %q", err, transportMsgUnavailable)
		}
		if got := h.dialer.dialed(); len(got) != 3 {
			t.Fatalf("dialed %v, want exactly 3 attempts", got)
		}
	})
	t.Run("dns failure", func(t *testing.T) {
		h := newTransportHarness(t, readyGPUA, strings.NewReader("x"))
		h.resolver.err = errors.New("no such host")
		if err := runPortalTransport(context.Background(), h.deps, "gpu-a.example.com"); err == nil || err.Error() != transportMsgUnavailable {
			t.Fatalf("err = %v, want %q", err, transportMsgUnavailable)
		}
		if len(h.dialer.dialed()) != 0 || h.stdout.Len() != 0 {
			t.Fatalf("dns failure must not dial or write stdout")
		}
	})
	t.Run("only special addresses", func(t *testing.T) {
		h := newTransportHarness(t, readyGPUA, strings.NewReader("x"))
		h.resolver.addrs = []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("::1")}}
		if err := runPortalTransport(context.Background(), h.deps, "gpu-a.example.com"); err == nil || err.Error() != transportMsgAccessDenied {
			t.Fatalf("err = %v, want %q", err, transportMsgAccessDenied)
		}
		if len(h.dialer.dialed()) != 0 {
			t.Fatalf("special addresses were dialed: %v", h.dialer.dialed())
		}
	})
	t.Run("local address enumeration failure fails closed", func(t *testing.T) {
		h := newTransportHarness(t, readyGPUA, strings.NewReader("x"))
		h.deps.localAddrs = func() ([]net.Addr, error) { return nil, errors.New("netlink") }
		if err := runPortalTransport(context.Background(), h.deps, "gpu-a.example.com"); err == nil || err.Error() != transportMsgAccessDenied {
			t.Fatalf("err = %v, want %q", err, transportMsgAccessDenied)
		}
		if len(h.dialer.dialed()) != 0 {
			t.Fatalf("dialed despite unknown local addresses: %v", h.dialer.dialed())
		}
	})
}

// TestFilterTransportAddrs is AG53.
func TestFilterTransportAddrs(t *testing.T) {
	ip := func(s string) net.IPAddr { return net.IPAddr{IP: net.ParseIP(s)} }
	in := []net.IPAddr{
		ip("127.0.0.1"), ip("::1"), ip("0.0.0.0"), ip("::"),
		ip("169.254.10.20"), ip("fe80::1"), ip("224.0.0.1"), ip("ff02::1"), ip("ff01::1"),
		ip("::ffff:127.0.0.1"), {IP: net.ParseIP("fd00::9"), Zone: "eth0"},
		ip("192.168.122.4"), // this gateway's own address
		ip("10.0.0.5"), ip("172.16.1.1"), ip("192.168.1.9"), ip("fd12:3456::7"), ip("::ffff:10.0.0.6"),
		ip("10.0.0.5"), // duplicate
	}
	local := []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.122.4"), Mask: net.CIDRMask(24, 32)}}
	var got []string
	for _, a := range filterTransportAddrs(in, local) {
		got = append(got, a.String())
	}
	want := []string{"10.0.0.5", "172.16.1.1", "192.168.1.9", "fd12:3456::7", "10.0.0.6"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("filterTransportAddrs = %v, want %v", got, want)
	}
}

// TestBridgeTransport_ByteForByte is AG54: arbitrary binary (NUL, 0xff,
// newlines, 16 MiB of random bytes) survives the bridge unchanged.
func TestBridgeTransport_ByteForByte(t *testing.T) {
	payload := make([]byte, 16<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	copy(payload, []byte{0x00, 0xff, '\n', '\r', 0x00, 0xff})
	conn, err := net.Dial("tcp", startEchoTarget(t))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	var out bytes.Buffer
	stats, err := bridgeTransport(context.Background(), bytes.NewReader(payload), &out, conn)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("output differs from input (%d vs %d bytes)", out.Len(), len(payload))
	}
	if stats.ClientToTarget != int64(len(payload)) || stats.TargetToClient != int64(len(payload)) {
		t.Fatalf("stats = %+v, want %d both ways", stats, len(payload))
	}
}

// TestBridgeTransport_HalfClose is AG55.
func TestBridgeTransport_HalfClose(t *testing.T) {
	t.Run("target still delivers after stdin EOF", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer func() { _ = ln.Close() }()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			_, _ = io.Copy(io.Discard, c) // wait for the client's half-close
			_, _ = c.Write([]byte("final-bytes-after-eof"))
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		var out bytes.Buffer
		if _, err := bridgeTransport(context.Background(), strings.NewReader("request"), &out, conn); err != nil {
			t.Fatalf("bridge: %v", err)
		}
		if out.String() != "final-bytes-after-eof" {
			t.Fatalf("out = %q", out.String())
		}
	})
	t.Run("target closes while stdin never does: bounded exit", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer func() { _ = ln.Close() }()
		go func() {
			c, err := ln.Accept()
			if err == nil {
				_, _ = c.Write([]byte("bye"))
				_ = c.Close()
			}
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		stdinR, stdinW := io.Pipe()
		defer func() { _ = stdinW.Close() }()
		var out bytes.Buffer
		start := time.Now()
		if _, err := bridgeTransport(context.Background(), stdinR, &out, conn); err != nil {
			t.Fatalf("bridge: %v", err)
		}
		if elapsed := time.Since(start); elapsed > transportStdinGrace+2*time.Second {
			t.Fatalf("bridge took %v with a never-closing stdin, want <= grace", elapsed)
		}
		if out.String() != "bye" {
			t.Fatalf("out = %q", out.String())
		}
	})
	t.Run("context cancellation closes the target socket", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer func() { _ = ln.Close() }()
		serverGone := make(chan struct{})
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, c) // returns once the bridge closes the socket
			_ = c.Close()
			close(serverGone)
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		stdinR, stdinW := io.Pipe()
		defer func() { _ = stdinW.Close() }()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := bridgeTransport(ctx, stdinR, io.Discard, conn)
			done <- err
		}()
		time.Sleep(100 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("bridge after cancel: %v", err)
			}
		case <-time.After(transportStdinGrace + 3*time.Second):
			t.Fatal("bridge did not return after context cancellation")
		}
		select {
		case <-serverGone:
		case <-time.After(3 * time.Second):
			t.Fatal("target socket was not closed on cancellation")
		}
	})
}

// TestRunPortalTransport_AuditEvents is AG57: a successful session emits
// requested -> connected -> closed carrying user/fqdn/ip/bytes/duration,
// and the payload itself never appears in the audit stream.
func TestRunPortalTransport_AuditEvents(t *testing.T) {
	const payload = "SSH-2.0-inner-secret-payload\x00\xff"
	h := newTransportHarness(t, readyGPUA, strings.NewReader(payload))
	if err := runPortalTransport(context.Background(), h.deps, "gpu-a.example.com"); err != nil {
		t.Fatalf("transport: %v", err)
	}
	if h.stdout.String() != payload {
		t.Fatalf("stdout = %q, want the echoed payload only", h.stdout.String())
	}
	raw := h.audit.String()
	if strings.Contains(raw, "inner-secret-payload") {
		t.Fatalf("audit stream leaked transport payload: %s", raw)
	}
	evs := h.audit.events(t)
	var kinds []string
	for _, ev := range evs {
		kinds = append(kinds, ev.Kind)
		if ev.SessionID != evs[0].SessionID || ev.User != currentOSUsername(t) || ev.GatewayID != "gpu-01" {
			t.Fatalf("event %+v does not carry the session's id/user/gateway", ev)
		}
	}
	want := []string{sessionaudit.KindGatewayTransportRequested, sessionaudit.KindGatewayTransportConnected, sessionaudit.KindGatewayTransportClosed}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("audit kinds = %v, want %v", kinds, want)
	}
	closed := evs[2]
	if closed.Result != "ok" || closed.TargetIP != "10.20.30.40" || closed.TargetFQDN != "gpu-a.example.com" ||
		closed.BytesClientToTarget == nil || *closed.BytesClientToTarget != int64(len(payload)) ||
		closed.BytesTargetToClient == nil || *closed.BytesTargetToClient != int64(len(payload)) ||
		closed.DurationMS == nil || *closed.DurationMS < 0 {
		t.Fatalf("closed event = %+v", closed)
	}
}
