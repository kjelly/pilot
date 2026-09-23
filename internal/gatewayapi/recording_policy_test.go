package gatewayapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/freeipaaccess"
	"github.com/kjelly/pilot/internal/ingesttoken"
)

var testSigningKey = []byte("0123456789abcdef0123456789abcdef")

// TestResolveRecordingMode covers every row of per-host recording spec §4.
func TestResolveRecordingMode(t *testing.T) {
	known := func(override string) accessportal.SSHRecordingAccessPolicy {
		return accessportal.SSHRecordingAccessPolicy{Known: true, Valid: true, Override: override}
	}
	cases := []struct {
		name       string
		def        string
		host       accessportal.SSHRecordingAccessPolicy
		wantMode   string
		wantSource string
		wantErr    error
	}{
		{"absent + unset", "", known(""), "metadata", RecordingSourceBuiltInDefault, nil},
		{"absent + metadata", "metadata", known(""), "metadata", RecordingSourceGatewayDefault, nil},
		{"absent + terminal_output", "terminal_output", known(""), "terminal_output", RecordingSourceGatewayDefault, nil},
		{"absent + terminal_io", "terminal_io", known(""), "terminal_io", RecordingSourceGatewayDefault, nil},
		{"off + terminal_output", "terminal_output", known("off"), "metadata", RecordingSourceHost, nil},
		{"off + unset", "", known("off"), "metadata", RecordingSourceHost, nil},
		{"terminal_output + metadata", "metadata", known("terminal_output"), "terminal_output", RecordingSourceHost, nil},
		{"terminal_output + terminal_io", "terminal_io", known("terminal_output"), "terminal_output", RecordingSourceHost, nil},
		{"reserved terminal_io override", "", known("terminal_io"), "", "", ErrRecordingPolicyInvalid},
		{"invalid marker", "terminal_output", accessportal.SSHRecordingAccessPolicy{Known: true, Reason: "duplicate"}, "", "", ErrRecordingPolicyInvalid},
		{"unknown (host_show failed)", "metadata", accessportal.SSHRecordingAccessPolicy{Reason: "host_show_failed"}, "", "", ErrRecordingPolicyUnknown},
		{"zero value fails closed", "", accessportal.SSHRecordingAccessPolicy{}, "", "", ErrRecordingPolicyUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mode, source, err := ResolveRecordingMode(c.def, c.host)
			if !errors.Is(err, c.wantErr) || mode != c.wantMode || source != c.wantSource {
				t.Fatalf("= (%q, %q, %v), want (%q, %q, %v)", mode, source, err, c.wantMode, c.wantSource, c.wantErr)
			}
		})
	}
}

// policyProvider is fakeProvider with a switchable host policy/HostShow error.
type policyProvider struct {
	fakeProvider
	mu     sync.Mutex
	policy freeipaaccess.HostRecordingPolicy
	err    error
}

func (p *policyProvider) set(policy freeipaaccess.HostRecordingPolicy, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policy, p.err = policy, err
}

func (p *policyProvider) HostShow(ctx context.Context, fqdn string) (freeipaaccess.Host, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return freeipaaccess.Host{}, p.err
	}
	return freeipaaccess.Host{FQDN: fqdn, SSHRecording: p.policy}, nil
}

var (
	absentPolicy = freeipaaccess.HostRecordingPolicy{Valid: true}
	outputPolicy = freeipaaccess.HostRecordingPolicy{Present: true, Mode: "terminal_output", Valid: true}
	offPolicy    = freeipaaccess.HostRecordingPolicy{Present: true, Mode: "off", Valid: true}
)

// recordingServer serves a gateway backed by provider with policy applied.
func recordingServer(t *testing.T, provider *policyProvider, policy RecordingPolicy) (*http.Client, string) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "gw.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	gw := accessportal.GatewayConfig{ID: "gpu-01", Scope: "gpu", TargetHostgroup: "pilot-target-gpu"}
	srv := NewServer(gw, provider, accessportal.NewResolver(provider, gw), nil)
	srv.RecordingPolicy = policy
	go srv.Serve(ln)                                         //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown(context.Background()) }) //nolint:errcheck
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", sockPath)
	}}}, "http://unix"
}

func storePolicy(t *testing.T) RecordingPolicy {
	t.Helper()
	signer, err := ingesttoken.NewSigner(testSigningKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	return RecordingPolicy{
		FailurePolicy: "fail_closed", QueueEvents: 1024, FlushIntervalMS: 500, FailureGraceMS: 10000,
		MaxSessionDuration: 24 * time.Hour, SessionStoreURL: "https://store.example.test:8443",
		SessionStoreCAFile: "/etc/ipa/ca.crt", Signer: signer,
	}
}

const testSID = "0d33c638-83fa-4d77-9811-a97a7a7af1d5"

func authorize(t *testing.T, client *http.Client, base, target, sid string) (ConnectAuthorizeResponse, string) {
	t.Helper()
	body, _ := json.Marshal(ConnectAuthorizeRequest{Target: target, SessionID: sid})
	resp, err := client.Post(base+"/v1/connect/authorize", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var raw bytes.Buffer
	_, _ = raw.ReadFrom(resp.Body)
	var got ConnectAuthorizeResponse
	if err := json.Unmarshal(raw.Bytes(), &got); err != nil {
		t.Fatalf("decode %s: %v", raw.String(), err)
	}
	return got, raw.String()
}

func TestConnectAuthorize_RecordingPolicyDenies(t *testing.T) {
	cases := map[string]struct {
		policy freeipaaccess.HostRecordingPolicy
		err    error
		reason string
	}{
		"host_show failed":     {err: errors.New("boom"), reason: DenyReasonRecordingPolicyUnavailable},
		"userclass unreadable": {policy: freeipaaccess.HostRecordingPolicy{Unreadable: true, Reason: "userclass_unreadable"}, reason: DenyReasonRecordingPolicyUnavailable},
		"duplicate marker":     {policy: freeipaaccess.HostRecordingPolicy{Present: true, Reason: "duplicate"}, reason: DenyReasonRecordingPolicyInvalid},
		"reserved terminal_io": {policy: freeipaaccess.HostRecordingPolicy{Present: true, Reason: "unknown_value"}, reason: DenyReasonRecordingPolicyInvalid},
		"zero-value policy":    {policy: freeipaaccess.HostRecordingPolicy{}, reason: DenyReasonRecordingPolicyInvalid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := &policyProvider{fakeProvider: fakeProvider{username: currentUsername(t)}}
			p.set(c.policy, c.err)
			client, base := recordingServer(t, p, storePolicy(t))
			got, _ := authorize(t, client, base, "gpu-a.example.com", testSID)
			if got.Allowed || got.DenyReason != c.reason {
				t.Fatalf("got allowed=%v deny_reason=%q, want deny %q", got.Allowed, got.DenyReason, c.reason)
			}
			if got.RecordingSessionStoreIngestToken != "" || got.RecordingSessionStoreURL != "" {
				t.Fatal("a denied authorize carried recording credentials")
			}
		})
	}
}

func TestConnectAuthorize_TerminalWithoutStoreDenied(t *testing.T) {
	p := &policyProvider{fakeProvider: fakeProvider{username: currentUsername(t)}}
	p.set(outputPolicy, nil)
	client, base := recordingServer(t, p, RecordingPolicy{FailurePolicy: "fail_closed"})
	got, _ := authorize(t, client, base, "gpu-a.example.com", testSID)
	if got.Allowed || got.DenyReason != DenyReasonRecordingBackend {
		t.Fatalf("got allowed=%v reason=%q, want deny %q", got.Allowed, got.DenyReason, DenyReasonRecordingBackend)
	}
}

func TestConnectAuthorize_MetadataCarriesNoIngestCredential(t *testing.T) {
	for name, pol := range map[string]freeipaaccess.HostRecordingPolicy{"inherit": absentPolicy, "off": offPolicy} {
		t.Run(name, func(t *testing.T) {
			p := &policyProvider{fakeProvider: fakeProvider{username: currentUsername(t)}}
			p.set(pol, nil)
			client, base := recordingServer(t, p, storePolicy(t))
			got, raw := authorize(t, client, base, "gpu-a.example.com", testSID)
			if !got.Allowed || got.RecordingMode != "metadata" {
				t.Fatalf("got %+v, want allowed metadata", got)
			}
			for _, field := range []string{"recording_session_store_url", "recording_session_store_ca_file", "recording_session_store_ingest_token", "recording_failure_policy", "recording_queue_events"} {
				if strings.Contains(raw, field) {
					t.Fatalf("metadata response carries %s: %s", field, raw)
				}
			}
		})
	}
}

func TestConnectAuthorize_MintsBoundIngestToken(t *testing.T) {
	p := &policyProvider{fakeProvider: fakeProvider{username: currentUsername(t)}}
	p.set(outputPolicy, nil)
	client, base := recordingServer(t, p, storePolicy(t))
	first, _ := authorize(t, client, base, "gpu-a.example.com", testSID)
	if !first.Allowed || first.RecordingMode != "terminal_output" || first.RecordingPolicySource != RecordingSourceHost {
		t.Fatalf("got %+v", first)
	}
	if first.RecordingSessionStoreURL != "https://store.example.test:8443" || first.RecordingFailurePolicy != "fail_closed" || first.RecordingFailureGraceMS != 10000 {
		t.Fatalf("recording coordinates = %+v", first)
	}
	v, _ := ingesttoken.NewVerifier(testSigningKey, nil)
	c, err := v.Verify(first.RecordingSessionStoreIngestToken)
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	want := ingesttoken.Claims{SessionID: testSID, User: currentUsername(t), Gateway: "gpu-01", Scope: "gpu", Target: "gpu-a.example.com", Mode: "terminal_output", Source: "host"}
	if c.SessionID != want.SessionID || c.User != want.User || c.Gateway != want.Gateway || c.Scope != want.Scope || c.Target != want.Target || c.Mode != want.Mode || c.Source != want.Source {
		t.Fatalf("claims = %+v, want %+v", c, want)
	}
	if got := time.Unix(c.Expires, 0).Sub(time.Unix(c.IssuedAt, 0)); got != 24*time.Hour {
		t.Fatalf("token lifetime = %v, want MaxSessionDuration", got)
	}
	second, _ := authorize(t, client, base, "gpu-a.example.com", testSID)
	c2, _ := v.Verify(second.RecordingSessionStoreIngestToken)
	if c2.JTI == c.JTI {
		t.Fatal("two authorizes minted the same jti")
	}
}

func TestConnectAuthorize_FreshPolicyEachRequest(t *testing.T) {
	p := &policyProvider{fakeProvider: fakeProvider{username: currentUsername(t)}}
	p.set(absentPolicy, nil)
	client, base := recordingServer(t, p, storePolicy(t))
	if got, _ := authorize(t, client, base, "gpu-a.example.com", testSID); got.RecordingMode != "metadata" {
		t.Fatalf("first authorize mode = %q, want metadata", got.RecordingMode)
	}
	p.set(outputPolicy, nil)
	if got, _ := authorize(t, client, base, "gpu-a.example.com", testSID); got.RecordingMode != "terminal_output" {
		t.Fatalf("second authorize mode = %q, want terminal_output immediately", got.RecordingMode)
	}
}

// TestConnectAuthorize_SessionIDOnlyBindsToken locks AG37: the session id
// never changes the HBAC decision; it is only required (as a UUID) when
// the effective mode records.
func TestConnectAuthorize_SessionIDOnlyBindsToken(t *testing.T) {
	p := &policyProvider{fakeProvider: fakeProvider{username: currentUsername(t)}}
	p.set(absentPolicy, nil)
	client, base := recordingServer(t, p, storePolicy(t))
	for _, sid := range []string{"", "not-a-uuid", testSID} {
		if got, _ := authorize(t, client, base, "gpu-a.example.com", sid); !got.Allowed {
			t.Fatalf("metadata authorize with sid %q denied: %+v", sid, got)
		}
		if got, _ := authorize(t, client, base, "not-in-scope.example.com", sid); got.Allowed {
			t.Fatalf("sid %q turned an out-of-scope target into an allow", sid)
		}
	}
	p.set(outputPolicy, nil)
	for _, sid := range []string{"", "not-a-uuid", strings.ToUpper(testSID)[:30]} {
		if got, _ := authorize(t, client, base, "gpu-a.example.com", sid); got.Allowed || got.DenyReason != DenyReasonRecordingSessionID {
			t.Fatalf("recorded authorize with sid %q = %+v, want deny %s", sid, got, DenyReasonRecordingSessionID)
		}
	}
}

func TestConnectAuthorize_DeniedHBACHasNoRecordingFields(t *testing.T) {
	p := &policyProvider{fakeProvider: fakeProvider{username: currentUsername(t)}}
	p.set(outputPolicy, nil)
	client, base := recordingServer(t, p, storePolicy(t))
	got, raw := authorize(t, client, base, "not-in-scope.example.com", testSID)
	if got.Allowed || got.DenyReason != "" || strings.Contains(raw, "recording_") {
		t.Fatalf("HBAC deny = %s, want a bare deny without recording fields", raw)
	}
}

func TestAccess_RecordingJSON(t *testing.T) {
	cases := []struct {
		name       string
		def        string
		policy     freeipaaccess.HostRecordingPolicy
		err        error
		wantStatus string
		wantEff    string
		wantDef    string
	}{
		{"inherit unset", "", absentPolicy, nil, "inherit", "metadata", "metadata"},
		{"inherit gateway output", "terminal_output", absentPolicy, nil, "inherit", "terminal_output", "terminal_output"},
		{"host output", "", outputPolicy, nil, "terminal_output", "terminal_output", "metadata"},
		{"host off over output default", "terminal_output", offPolicy, nil, "off", "metadata", "terminal_output"},
		{"unknown", "", absentPolicy, errors.New("boom"), "unknown", "", "metadata"},
		{"invalid", "", freeipaaccess.HostRecordingPolicy{Present: true, Reason: "malformed"}, nil, "invalid", "", "metadata"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &policyProvider{fakeProvider: fakeProvider{username: currentUsername(t)}}
			p.set(c.policy, c.err)
			pol := storePolicy(t)
			pol.DefaultMode = c.def
			client, base := recordingServer(t, p, pol)
			resp, err := client.Get(base + "/v1/access")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			var got AccessResponse
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if len(got.Hosts) != 1 {
				t.Fatalf("hosts = %+v (a host_show failure must not drop the host)", got.Hosts)
			}
			if r := got.Hosts[0].Recording; r.Status != c.wantStatus || r.Effective != c.wantEff || got.RecordingDefault != c.wantDef {
				t.Fatalf("recording = %+v default=%q, want status=%q effective=%q default=%q", r, got.RecordingDefault, c.wantStatus, c.wantEff, c.wantDef)
			}
		})
	}
}

// twoHostProvider scopes two hosts with independent recording policies.
type twoHostProvider struct {
	fakeProvider
	policies map[string]freeipaaccess.HostRecordingPolicy
}

func (p *twoHostProvider) HostShow(ctx context.Context, fqdn string) (freeipaaccess.Host, error) {
	return freeipaaccess.Host{FQDN: fqdn, SSHRecording: p.policies[fqdn]}, nil
}

func (p *twoHostProvider) HostgroupShow(ctx context.Context, name string) (freeipaaccess.Hostgroup, error) {
	if name != "pilot-target-gpu" {
		return freeipaaccess.Hostgroup{}, &freeipaaccess.RPCError{Name: "NotFound"}
	}
	return freeipaaccess.Hostgroup{Name: name, MemberHosts: []string{"gpu-a.example.com", "gpu-b.example.com"}}, nil
}

func (p *twoHostProvider) HBACRuleFind(ctx context.Context) ([]freeipaaccess.HBACRule, error) {
	return []freeipaaccess.HBACRule{{
		Name: "grant", Enabled: true,
		Groups: []string{"gpu-users"}, Hosts: []string{"gpu-a.example.com", "gpu-b.example.com"},
		Services: []string{"sshd"},
	}}, nil
}

// TestConnectAuthorize_UserClassUnreadableDenies locks AG56 (Phase 0 branch
// R): when the gateway principal cannot read one host's userclass, only
// that host's connects are denied with recording_policy_unavailable; a
// readable host in the same snapshot is unaffected.
func TestConnectAuthorize_UserClassUnreadableDenies(t *testing.T) {
	p := &twoHostProvider{
		fakeProvider: fakeProvider{username: currentUsername(t)},
		policies: map[string]freeipaaccess.HostRecordingPolicy{
			"gpu-a.example.com": absentPolicy,
			"gpu-b.example.com": {Unreadable: true, Reason: "userclass_unreadable"},
		},
	}
	sockPath := filepath.Join(t.TempDir(), "gw.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	gw := accessportal.GatewayConfig{ID: "gpu-01", Scope: "gpu", TargetHostgroup: "pilot-target-gpu"}
	srv := NewServer(gw, p, accessportal.NewResolver(p, gw), nil)
	srv.RecordingPolicy = storePolicy(t)
	go srv.Serve(ln)                                         //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown(context.Background()) }) //nolint:errcheck
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", sockPath)
	}}}

	if got, _ := authorize(t, client, "http://unix", "gpu-b.example.com", testSID); got.Allowed || got.DenyReason != DenyReasonRecordingPolicyUnavailable {
		t.Fatalf("unreadable host = allowed=%v reason=%q, want deny %s", got.Allowed, got.DenyReason, DenyReasonRecordingPolicyUnavailable)
	}
	if got, _ := authorize(t, client, "http://unix", "gpu-a.example.com", testSID); !got.Allowed || got.RecordingMode != "metadata" {
		t.Fatalf("readable host = %+v, want an allowed metadata connect", got)
	}
}
