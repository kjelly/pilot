package gatewayapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// transportFakeProvider is fakeProvider plus a controllable
// TransportReadyHostgroup and host SSH keys, counting ready-hostgroup
// lookups so tests can prove a disabled gateway never asks FreeIPA.
type transportFakeProvider struct {
	fakeProvider
	ready       []string
	readyNested []string
	readyErr    error
	hostKeys    []string
	hostShowErr error
	readyCalls  atomic.Int32
}

func (p *transportFakeProvider) HostgroupShow(ctx context.Context, name string) (freeipaaccess.Hostgroup, error) {
	if name == TransportReadyHostgroup {
		p.readyCalls.Add(1)
		if p.readyErr != nil {
			return freeipaaccess.Hostgroup{}, p.readyErr
		}
		return freeipaaccess.Hostgroup{Name: name, MemberHosts: p.ready, IndirectMemberHosts: p.readyNested}, nil
	}
	return p.fakeProvider.HostgroupShow(ctx, name)
}

func (p *transportFakeProvider) HostShow(ctx context.Context, fqdn string) (freeipaaccess.Host, error) {
	if p.hostShowErr != nil {
		return freeipaaccess.Host{}, p.hostShowErr
	}
	h := freeipaaccess.NewHostWithoutPolicy(fqdn)
	h.SSHPublicKeys = p.hostKeys
	return h, nil
}

func transportTestServer(t *testing.T, provider *transportFakeProvider, enabled bool) (*http.Client, string) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "gw.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	gw := accessportal.GatewayConfig{ID: "gpu-01", Scope: "gpu", TargetHostgroup: "pilot-target-gpu"}
	srv := NewServer(gw, provider, accessportal.NewResolver(provider, gw), nil)
	srv.Transport = TransportPolicy{Enabled: enabled}
	go srv.Serve(ln)                                         //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown(context.Background()) }) //nolint:errcheck
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return net.Dial("unix", sockPath) },
	}}, "http://unix"
}

func postJSON[T any](t *testing.T, client *http.Client, url string, body any) (T, int) {
	t.Helper()
	var out T
	b, _ := json.Marshal(body)
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return out, resp.StatusCode
}

// TestConnectAuthorize_TransportGate is captive-transport spec AG48: the
// server alone decides transport_allowed, on the same fresh authorize,
// failing closed on every non-happy path.
func TestConnectAuthorize_TransportGate(t *testing.T) {
	user := currentUsername(t)
	cases := []struct {
		name          string
		enabled       bool
		provider      *transportFakeProvider
		target        string
		wantAllowed   bool
		wantTransport bool
		wantReason    string
		wantLookups   int32
	}{
		{"disabled never asks FreeIPA", false, &transportFakeProvider{ready: []string{"gpu-a.example.com"}}, "gpu-a.example.com", true, false, TransportDenyDisabled, 0},
		{"enabled + direct member", true, &transportFakeProvider{ready: []string{"gpu-a.example.com"}}, "gpu-a.example.com", true, true, "", 1},
		{"enabled + nested member", true, &transportFakeProvider{readyNested: []string{"GPU-A.example.com."}}, "gpu-a.example.com", true, true, "", 1},
		{"enabled + not a member", true, &transportFakeProvider{ready: []string{"gpu-b.example.com"}}, "gpu-a.example.com", true, false, TransportDenyTargetNotReady, 1},
		{"enabled + ready lookup fails", true, &transportFakeProvider{readyErr: errors.New("boom")}, "gpu-a.example.com", true, false, TransportDenyReadyLookupFailed, 1},
		{"not authorized carries no transport fields", true, &transportFakeProvider{ready: []string{"gpu-z.example.com"}}, "gpu-z.example.com", false, false, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.provider.username = user
			client, base := transportTestServer(t, tc.provider, tc.enabled)
			got, status := postJSON[ConnectAuthorizeResponse](t, client, base+"/v1/connect/authorize", ConnectAuthorizeRequest{Target: tc.target})
			if status != http.StatusOK {
				t.Fatalf("status = %d", status)
			}
			if got.Allowed != tc.wantAllowed || got.TransportAllowed != tc.wantTransport || got.TransportDenyReason != tc.wantReason {
				t.Fatalf("got allowed=%v transport=%v reason=%q, want %v/%v/%q", got.Allowed, got.TransportAllowed, got.TransportDenyReason, tc.wantAllowed, tc.wantTransport, tc.wantReason)
			}
			if n := tc.provider.readyCalls.Load(); n != tc.wantLookups {
				t.Fatalf("ready hostgroup lookups = %d, want %d", n, tc.wantLookups)
			}
		})
	}
}

// TestTransportHostKeys is captive-transport spec AG58 (server side): host
// keys come back only under the same authorize + transport gate; a denied
// caller gets allowed=false and an empty (non-null) list, and a host_show
// failure is a 503, never a silently empty "allowed" answer.
func TestTransportHostKeys(t *testing.T) {
	user := currentUsername(t)
	keys := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID2FYB+eiBTZfrR6SPm7Q8R5j9mxWNZe5p6TTSfCjDLY root@tx-target"}

	t.Run("allowed", func(t *testing.T) {
		p := &transportFakeProvider{fakeProvider: fakeProvider{username: user}, ready: []string{"gpu-a.example.com"}, hostKeys: keys}
		client, base := transportTestServer(t, p, true)
		got, status := postJSON[TransportHostKeysResponse](t, client, base+"/v1/transport/host-keys", TransportHostKeysRequest{Target: "GPU-A.example.com"})
		if status != http.StatusOK || !got.Allowed || got.Target != "gpu-a.example.com" || len(got.HostKeys) != 1 || got.HostKeys[0] != keys[0] {
			t.Fatalf("status=%d got=%+v", status, got)
		}
	})
	for _, tc := range []struct {
		name    string
		enabled bool
		ready   []string
		target  string
	}{
		{"transport disabled", false, []string{"gpu-a.example.com"}, "gpu-a.example.com"},
		{"target not ready", true, nil, "gpu-a.example.com"},
		{"not authorized", true, []string{"gpu-z.example.com"}, "gpu-z.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &transportFakeProvider{fakeProvider: fakeProvider{username: user}, ready: tc.ready, hostKeys: keys}
			client, base := transportTestServer(t, p, tc.enabled)
			resp, err := client.Post(base+"/v1/transport/host-keys", "application/json", bytes.NewReader([]byte(`{"target":"`+tc.target+`"}`)))
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			var raw map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.StatusCode != http.StatusOK || raw["allowed"] != false {
				t.Fatalf("status=%d body=%v, want 200 allowed=false", resp.StatusCode, raw)
			}
			if list, ok := raw["host_keys"].([]any); !ok || len(list) != 0 {
				t.Fatalf("host_keys = %#v, want an empty JSON array", raw["host_keys"])
			}
		})
	}
	t.Run("host_show failure is 503", func(t *testing.T) {
		p := &transportFakeProvider{fakeProvider: fakeProvider{username: user}, ready: []string{"gpu-a.example.com"}, hostShowErr: errors.New("ipa down")}
		client, base := transportTestServer(t, p, true)
		if _, status := postJSON[TransportHostKeysResponse](t, client, base+"/v1/transport/host-keys", TransportHostKeysRequest{Target: "gpu-a.example.com"}); status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", status)
		}
	})
	t.Run("extra fields rejected", func(t *testing.T) {
		p := &transportFakeProvider{fakeProvider: fakeProvider{username: user}, ready: []string{"gpu-a.example.com"}, hostKeys: keys}
		client, base := transportTestServer(t, p, true)
		resp, err := client.Post(base+"/v1/transport/host-keys", "application/json", bytes.NewReader([]byte(`{"target":"gpu-a.example.com","username":"root"}`)))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})
}
