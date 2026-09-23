package cmd

import (
	"context"
	"net"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/freeipaaccess"
	"github.com/kjelly/pilot/internal/gatewayapi"
)

// fakeGatewayProvider is a minimal freeipaaccess.Provider backing a real
// internal/gatewayapi.Server for testing pilot portal's client/TUI
// against the real HTTP-over-Unix-socket wire protocol Phase 3 already
// proved correct — not a mock of the gateway itself.
type fakeGatewayProvider struct {
	username string
}

var _ freeipaaccess.Provider = (*fakeGatewayProvider)(nil)

func (f *fakeGatewayProvider) Ping(ctx context.Context) (freeipaaccess.PingResult, error) {
	return freeipaaccess.PingResult{ServerVersion: "fake"}, nil
}
func (f *fakeGatewayProvider) UserShow(ctx context.Context, username string) (freeipaaccess.User, error) {
	if username != f.username {
		return freeipaaccess.User{}, &freeipaaccess.RPCError{Name: "NotFound"}
	}
	return freeipaaccess.User{Username: username, Enabled: true, DirectGroups: []string{"gpu-users"}}, nil
}
func (f *fakeGatewayProvider) GroupShow(ctx context.Context, name string) (freeipaaccess.Group, error) {
	return freeipaaccess.Group{}, &freeipaaccess.RPCError{Name: "NotFound"}
}
func (f *fakeGatewayProvider) HostShow(ctx context.Context, fqdn string) (freeipaaccess.Host, error) {
	return freeipaaccess.Host{FQDN: fqdn}, nil
}
func (f *fakeGatewayProvider) HostgroupShow(ctx context.Context, name string) (freeipaaccess.Hostgroup, error) {
	if name != "pilot-target-gpu" {
		return freeipaaccess.Hostgroup{}, &freeipaaccess.RPCError{Name: "NotFound"}
	}
	return freeipaaccess.Hostgroup{Name: name, MemberHosts: []string{"gpu-a.example.com"}}, nil
}
func (f *fakeGatewayProvider) HBACRuleFind(ctx context.Context) ([]freeipaaccess.HBACRule, error) {
	return []freeipaaccess.HBACRule{{
		Name: "grant", Enabled: true,
		Groups: []string{"gpu-users"}, Hosts: []string{"gpu-a.example.com"}, Services: []string{"sshd"},
	}}, nil
}
func (f *fakeGatewayProvider) HBACServiceGroupShow(ctx context.Context, name string) (freeipaaccess.HBACServiceGroup, error) {
	return freeipaaccess.HBACServiceGroup{}, &freeipaaccess.RPCError{Name: "NotFound"}
}
func (f *fakeGatewayProvider) SudoRuleFind(ctx context.Context) ([]freeipaaccess.SudoRule, error) {
	return []freeipaaccess.SudoRule{{
		Name: "sudo-grant", Enabled: true,
		Groups: []string{"gpu-users"}, Hosts: []string{"gpu-a.example.com"},
		AllowCommands: []string{"/usr/bin/systemctl status nginx"},
	}}, nil
}
func (f *fakeGatewayProvider) SudoCommandShow(ctx context.Context, name string) (freeipaaccess.SudoCommand, error) {
	return freeipaaccess.SudoCommand{Command: name}, nil
}
func (f *fakeGatewayProvider) SudoCommandGroupShow(ctx context.Context, name string) (freeipaaccess.SudoCommandGroup, error) {
	return freeipaaccess.SudoCommandGroup{}, &freeipaaccess.RPCError{Name: "NotFound"}
}
func (f *fakeGatewayProvider) HBACTest(ctx context.Context, req freeipaaccess.HBACTestRequest) (freeipaaccess.HBACTestResult, error) {
	return freeipaaccess.HBACTestResult{}, &freeipaaccess.RPCError{Name: "NotFound"}
}

// currentOSUsername is the identity SO_PEERCRED+getent will actually
// resolve this test process to — the fake provider must recognize this,
// not an arbitrary name like "alice", since the real gatewayapi.Server
// derives identity from the real connecting process, never from a value
// the test hands it directly.
func currentOSUsername(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current unavailable: %v", err)
	}
	return u.Username
}

// startFakeGateway starts a real gatewayapi.Server over a real Unix
// socket and returns a portalClient dialing it. username must be this
// test process's own OS username (see currentOSUsername) — the server
// resolves the real caller's identity via SO_PEERCRED, it is never told
// who is calling.
func startFakeGateway(t *testing.T, username string) *portalClient {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "gw.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	gw := accessportal.GatewayConfig{ID: "gpu-01", Scope: "gpu", TargetHostgroup: "pilot-target-gpu"}
	provider := &fakeGatewayProvider{username: username}
	resolver := accessportal.NewResolver(provider, gw)
	srv := gatewayapi.NewServer(gw, provider, resolver, nil)
	go srv.Serve(ln)                                         //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown(context.Background()) }) //nolint:errcheck

	// Portal tests must not depend on real DNS/network access — stub every
	// host as resolvable by default. A test exercising the unresolved-host
	// UI itself overrides this again after startFakeGateway returns; t.Cleanup
	// unwinds LIFO, so that override is restored back to this stub, never to
	// the real net.DefaultResolver.
	oldResolve := portalResolveHost
	portalResolveHost = func(ctx context.Context, host string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	t.Cleanup(func() { portalResolveHost = oldResolve })

	return newPortalClient(sockPath)
}

func TestPortalClientIdentityAndAccess(t *testing.T) {
	username := currentOSUsername(t)
	client := startFakeGateway(t, username)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	identity, err := client.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if identity.Username != username || identity.Gateway.Scope != "gpu" {
		t.Fatalf("Identity = %+v, want username %q", identity, username)
	}

	access, err := client.Access(ctx)
	if err != nil {
		t.Fatalf("Access: %v", err)
	}
	if len(access.Hosts) != 1 || access.Hosts[0].FQDN != "gpu-a.example.com" || !access.Hosts[0].SSH.Allowed {
		t.Fatalf("Access = %+v", access)
	}
}

func TestPortalClientConnectAuthorize(t *testing.T) {
	client := startFakeGateway(t, currentOSUsername(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	allowed, err := client.ConnectAuthorize(ctx, "gpu-a.example.com")
	if err != nil {
		t.Fatalf("ConnectAuthorize: %v", err)
	}
	if !allowed.Allowed {
		t.Fatalf("ConnectAuthorize = %+v, want allowed", allowed)
	}

	denied, err := client.ConnectAuthorize(ctx, "not-in-scope.example.com")
	if err != nil {
		t.Fatalf("ConnectAuthorize: %v", err)
	}
	if denied.Allowed {
		t.Fatalf("ConnectAuthorize = %+v, want denied", denied)
	}
}
