package gatewayapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// fakeProvider is a minimal freeipaaccess.Provider for exercising the
// HTTP layer end-to-end over a real Unix socket (SO_PEERCRED included) —
// it does not need to be realistic beyond "resolves the current test
// process's own OS user", since that's who will actually connect.
type fakeProvider struct {
	username string
}

var _ freeipaaccess.Provider = (*fakeProvider)(nil)

func (f *fakeProvider) Ping(ctx context.Context) (freeipaaccess.PingResult, error) {
	return freeipaaccess.PingResult{ServerVersion: "fake"}, nil
}
func (f *fakeProvider) UserShow(ctx context.Context, username string) (freeipaaccess.User, error) {
	if username != f.username {
		return freeipaaccess.User{}, &freeipaaccess.RPCError{Name: "NotFound"}
	}
	return freeipaaccess.User{Username: username, Enabled: true, DirectGroups: []string{"gpu-users"}}, nil
}
func (f *fakeProvider) GroupShow(ctx context.Context, name string) (freeipaaccess.Group, error) {
	return freeipaaccess.Group{}, &freeipaaccess.RPCError{Name: "NotFound"}
}
func (f *fakeProvider) HostShow(ctx context.Context, fqdn string) (freeipaaccess.Host, error) {
	return freeipaaccess.Host{FQDN: fqdn}, nil
}
func (f *fakeProvider) HostgroupShow(ctx context.Context, name string) (freeipaaccess.Hostgroup, error) {
	if name != "pilot-target-gpu" {
		return freeipaaccess.Hostgroup{}, &freeipaaccess.RPCError{Name: "NotFound"}
	}
	return freeipaaccess.Hostgroup{Name: name, MemberHosts: []string{"gpu-a.example.com"}}, nil
}
func (f *fakeProvider) HBACRuleFind(ctx context.Context) ([]freeipaaccess.HBACRule, error) {
	return []freeipaaccess.HBACRule{{
		Name: "grant", Enabled: true,
		Groups: []string{"gpu-users"}, Hosts: []string{"gpu-a.example.com"},
		Services: []string{"sshd"},
	}}, nil
}
func (f *fakeProvider) HBACServiceGroupShow(ctx context.Context, name string) (freeipaaccess.HBACServiceGroup, error) {
	return freeipaaccess.HBACServiceGroup{}, &freeipaaccess.RPCError{Name: "NotFound"}
}
func (f *fakeProvider) SudoRuleFind(ctx context.Context) ([]freeipaaccess.SudoRule, error) {
	return nil, nil
}
func (f *fakeProvider) SudoCommandShow(ctx context.Context, name string) (freeipaaccess.SudoCommand, error) {
	return freeipaaccess.SudoCommand{Command: name}, nil
}
func (f *fakeProvider) SudoCommandGroupShow(ctx context.Context, name string) (freeipaaccess.SudoCommandGroup, error) {
	return freeipaaccess.SudoCommandGroup{}, &freeipaaccess.RPCError{Name: "NotFound"}
}
func (f *fakeProvider) HBACTest(ctx context.Context, req freeipaaccess.HBACTestRequest) (freeipaaccess.HBACTestResult, error) {
	return freeipaaccess.HBACTestResult{}, &freeipaaccess.RPCError{Name: "NotFound"}
}

// testServer starts a real Server over a real Unix socket and returns an
// http.Client dialing it, so tests exercise the genuine SO_PEERCRED path
// (this test process connecting to itself), not a mocked context.
func testServer(t *testing.T, username string) (*http.Client, string) {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "gw.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	gw := accessportal.GatewayConfig{ID: "gpu-01", Scope: "gpu", TargetHostgroup: "pilot-target-gpu"}
	provider := &fakeProvider{username: username}
	resolver := accessportal.NewResolver(provider, gw)
	srv := NewServer(gw, provider, resolver, nil)

	go srv.Serve(ln)                                         //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown(context.Background()) }) //nolint:errcheck

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
	}
	return client, "http://unix"
}

func currentUsername(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current unavailable: %v", err)
	}
	return u.Username
}

func TestHandleIdentity(t *testing.T) {
	username := currentUsername(t)
	client, base := testServer(t, username)
	resp, err := client.Get(base + "/v1/identity")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got IdentityResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Username != username {
		t.Fatalf("Username = %q, want %q (resolved via real SO_PEERCRED + getent)", got.Username, username)
	}
	if int(got.UID) != os.Getuid() {
		t.Fatalf("UID = %d, want %d", got.UID, os.Getuid())
	}
	if got.Gateway != (GatewayInfo{ID: "gpu-01", Scope: "gpu", TargetHostgroup: "pilot-target-gpu"}) {
		t.Fatalf("Gateway = %+v", got.Gateway)
	}
}

func TestHandleAccess(t *testing.T) {
	username := currentUsername(t)
	client, base := testServer(t, username)
	resp, err := client.Get(base + "/v1/access")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var got AccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Hosts) != 1 || got.Hosts[0].FQDN != "gpu-a.example.com" || !got.Hosts[0].SSH.Allowed {
		t.Fatalf("Hosts = %+v", got.Hosts)
	}
}

// TestHandleAccess_ClientCannotOverrideUser (spec.md §22.2, SI-07): even
// though the fakeProvider only recognizes one username, a query string
// trying to ask for a different user must be ignored — /v1/access reads
// nothing from the URL at all.
func TestHandleAccess_ClientCannotOverrideUser(t *testing.T) {
	client, base := testServer(t, currentUsername(t))
	resp, err := client.Get(base + "/v1/access?user=someone-else&scope=dmz&target_hostgroup=pilot-target-dmz")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var got AccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.User != currentUsername(t) || got.Gateway.Scope != "gpu" {
		t.Fatalf("query string overrode identity/scope: %+v", got)
	}
}

func TestHandleAccessHost_UnmanagedHostIs404(t *testing.T) {
	client, base := testServer(t, currentUsername(t))
	resp, err := client.Get(base + "/v1/access/not-in-scope.example.com")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandleConnectAuthorize_Allowed(t *testing.T) {
	client, base := testServer(t, currentUsername(t))
	body, _ := json.Marshal(ConnectAuthorizeRequest{Target: "gpu-a.example.com"})
	resp, err := client.Post(base+"/v1/connect/authorize", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	var got ConnectAuthorizeResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Allowed || got.GatewayID != "gpu-01" || got.GatewayScope != "gpu" {
		t.Fatalf("got = %+v", got)
	}
}

// TestHandleConnectAuthorize_TargetInjectionIsInert (spec.md §40 S2): a
// shell-metacharacter-laden target must never be executed — this handler
// never execs anything, it only ever uses the string as an opaque map
// key, so an injection payload just fails to match any real host.
func TestHandleConnectAuthorize_TargetInjectionIsInert(t *testing.T) {
	client, base := testServer(t, currentUsername(t))
	body, _ := json.Marshal(ConnectAuthorizeRequest{Target: "gpu-a.example.com; rm -rf /tmp/x"})
	resp, err := client.Post(base+"/v1/connect/authorize", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	var got ConnectAuthorizeResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Allowed {
		t.Fatalf("expected denial for a non-matching/injected target, got %+v", got)
	}
}

// TestHandleConnectAuthorize_RejectsExtraFields (spec.md §22.4, SI-07):
// the body decoder must reject an attempt to smuggle
// username/gateway_id/scope in, not merely ignore them.
func TestHandleConnectAuthorize_RejectsExtraFields(t *testing.T) {
	client, base := testServer(t, currentUsername(t))
	raw := []byte(`{"target":"gpu-a.example.com","username":"root","gateway_id":"gpu-02"}`)
	resp, err := client.Post(base+"/v1/connect/authorize", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
}

func TestHandleHealth_OK(t *testing.T) {
	client, base := testServer(t, currentUsername(t))
	resp, err := client.Get(base + "/v1/health")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != "ok" {
		t.Fatalf("Status = %q", got.Status)
	}
}
