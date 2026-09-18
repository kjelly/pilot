package directoryapi

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
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// fakeProvider is a minimal freeipaaccess.Provider + HostgroupFinder for
// exercising the HTTP layer end-to-end over a real Unix socket
// (SO_PEERCRED included) — it does not need to be realistic beyond
// "resolves the current test process's own OS user", since that's who
// will actually connect. One scope (gpu) with one Gateway instance.
type fakeProvider struct {
	username string
}

var _ freeipaaccess.Provider = (*fakeProvider)(nil)
var _ freeipaaccess.HostgroupFinder = (*fakeProvider)(nil)

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
	switch name {
	case "pilot-target-gpu":
		return freeipaaccess.Hostgroup{Name: name, MemberHosts: []string{"gpu-a.example.com"}}, nil
	case "pilot-gateway-gpu":
		return freeipaaccess.Hostgroup{Name: name, MemberHosts: []string{"gw-gpu-01.example.com"}}, nil
	default:
		return freeipaaccess.Hostgroup{}, &freeipaaccess.RPCError{Name: "NotFound"}
	}
}
func (f *fakeProvider) HostgroupFind(ctx context.Context, criteria string) ([]freeipaaccess.HostgroupSummary, error) {
	var out []freeipaaccess.HostgroupSummary
	for _, name := range []string{"pilot-target-gpu", "pilot-gateway-gpu"} {
		if strings.Contains(name, criteria) {
			out = append(out, freeipaaccess.HostgroupSummary{Name: name})
		}
	}
	return out, nil
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
	return testServerWithConfig(t, username, nil)
}

// testServerWithConfig is testServer plus an optional hook to mutate the
// *Server (e.g. set PortalUserGroup) before it starts serving.
func testServerWithConfig(t *testing.T, username string, configure func(*Server)) (*http.Client, string) {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "directory.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	provider := &fakeProvider{username: username}
	cfg := DirectoryConfig{ID: "access-01", TargetHostgroupPrefix: "pilot-target-", GatewayHostgroupPrefix: "pilot-gateway-"}
	srv := NewServer(cfg, provider, provider, nil)
	if configure != nil {
		configure(srv)
	}

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
	if got.Directory != (DirectoryInfo{ID: "access-01", TargetHostgroupPrefix: "pilot-target-", GatewayHostgroupPrefix: "pilot-gateway-"}) {
		t.Fatalf("Directory = %+v", got.Directory)
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
	if len(got.Targets) != 1 || got.Targets[0].FQDN != "gpu-a.example.com" || !got.Targets[0].SSH.Allowed {
		t.Fatalf("Targets = %+v", got.Targets)
	}
	if len(got.Targets[0].Routes) != 1 || got.Targets[0].Routes[0].Scope != "gpu" || got.Targets[0].Routes[0].RouteStatus != "ready" {
		t.Fatalf("Routes = %+v", got.Targets[0].Routes)
	}
}

// TestHandleAccess_ClientCannotOverrideUser (spec.md §11.1): even though
// the fakeProvider only recognizes one username, a query string trying
// to ask for a different user must be ignored — /v1/access reads nothing
// from the URL at all.
func TestHandleAccess_ClientCannotOverrideUser(t *testing.T) {
	client, base := testServer(t, currentUsername(t))
	resp, err := client.Get(base + "/v1/access?user=someone-else")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var got AccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.User != currentUsername(t) {
		t.Fatalf("query string overrode identity: %+v", got)
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

func TestHandleConnectResolve_Allowed(t *testing.T) {
	client, base := testServer(t, currentUsername(t))
	body, _ := json.Marshal(ConnectResolveRequest{Target: "gpu-a.example.com"})
	resp, err := client.Post(base+"/v1/connect/resolve", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	var got ConnectResolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Allowed || got.SessionID == "" || got.Route == nil || got.Route.Scope != "gpu" {
		t.Fatalf("got = %+v", got)
	}
	if len(got.Route.GatewayCandidates) != 1 || got.Route.GatewayCandidates[0] != "gw-gpu-01.example.com" {
		t.Fatalf("GatewayCandidates = %v", got.Route.GatewayCandidates)
	}
}

// TestHandleConnectResolve_SessionIDIsFreshEveryCall (spec.md §21.1):
// every connect attempt gets a fresh, unique session_id.
func TestHandleConnectResolve_SessionIDIsFreshEveryCall(t *testing.T) {
	client, base := testServer(t, currentUsername(t))
	body, _ := json.Marshal(ConnectResolveRequest{Target: "gpu-a.example.com"})

	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		resp, err := client.Post(base+"/v1/connect/resolve", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		var got ConnectResolveResponse
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		resp.Body.Close()
		if seen[got.SessionID] {
			t.Fatalf("session_id %q repeated across calls", got.SessionID)
		}
		seen[got.SessionID] = true
	}
}

// TestHandleConnectResolve_TargetInjectionIsInert (spec.md §40 S2): a
// shell-metacharacter-laden target must never be executed — this handler
// only ever uses the string as an opaque map key, so an injection
// payload just fails to match any real target.
func TestHandleConnectResolve_TargetInjectionIsInert(t *testing.T) {
	client, base := testServer(t, currentUsername(t))
	body, _ := json.Marshal(ConnectResolveRequest{Target: "gpu-a.example.com; rm -rf /tmp/x"})
	resp, err := client.Post(base+"/v1/connect/resolve", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	var got ConnectResolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Allowed {
		t.Fatalf("expected denial for a non-matching/injected target, got %+v", got)
	}
}

// TestHandleConnectResolve_RejectsExtraFields (spec.md §11.2, D6): the
// body decoder must reject an attempt to smuggle
// user/scope/gateway/session_id in, not merely ignore them.
func TestHandleConnectResolve_RejectsExtraFields(t *testing.T) {
	client, base := testServer(t, currentUsername(t))
	raw := []byte(`{"target":"gpu-a.example.com","session_id":"attacker-chosen","gateway_id":"gpu-02"}`)
	resp, err := client.Post(base+"/v1/connect/resolve", "application/json", bytes.NewReader(raw))
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
