package cmd

import (
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/directoryapi"
	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// fakeDirectoryProvider is a minimal freeipaaccess.Provider +
// freeipaaccess.HostgroupFinder backing a real internal/directoryapi.Server
// for testing pilot directory's client/TUI against the real
// HTTP-over-Unix-socket wire protocol Phase 3 already proved correct —
// not a mock of the Directory backend itself. One scope (gpu) with one
// live gateway candidate, matching the real ag-gw01/ag-target01 fixture
// shape Phase 3's evidence doc captured.
type fakeDirectoryProvider struct {
	username string
}

var _ freeipaaccess.Provider = (*fakeDirectoryProvider)(nil)
var _ freeipaaccess.HostgroupFinder = (*fakeDirectoryProvider)(nil)

func (f *fakeDirectoryProvider) Ping(ctx context.Context) (freeipaaccess.PingResult, error) {
	return freeipaaccess.PingResult{ServerVersion: "fake"}, nil
}
func (f *fakeDirectoryProvider) UserShow(ctx context.Context, username string) (freeipaaccess.User, error) {
	if username != f.username {
		return freeipaaccess.User{}, &freeipaaccess.RPCError{Name: "NotFound"}
	}
	return freeipaaccess.User{Username: username, Enabled: true, DirectGroups: []string{"gpu-users"}}, nil
}
func (f *fakeDirectoryProvider) GroupShow(ctx context.Context, name string) (freeipaaccess.Group, error) {
	return freeipaaccess.Group{}, &freeipaaccess.RPCError{Name: "NotFound"}
}
func (f *fakeDirectoryProvider) HostShow(ctx context.Context, fqdn string) (freeipaaccess.Host, error) {
	return freeipaaccess.Host{FQDN: fqdn}, nil
}
func (f *fakeDirectoryProvider) HostgroupShow(ctx context.Context, name string) (freeipaaccess.Hostgroup, error) {
	switch name {
	case "pilot-target-gpu":
		return freeipaaccess.Hostgroup{Name: name, MemberHosts: []string{"gpu-a.example.com"}}, nil
	case "pilot-gateway-gpu":
		return freeipaaccess.Hostgroup{Name: name, MemberHosts: []string{"gw-gpu-01.example.com"}}, nil
	}
	return freeipaaccess.Hostgroup{}, &freeipaaccess.RPCError{Name: "NotFound"}
}
func (f *fakeDirectoryProvider) HostgroupFind(ctx context.Context, criteria string) ([]freeipaaccess.HostgroupSummary, error) {
	all := []string{"pilot-target-gpu", "pilot-gateway-gpu"}
	var out []freeipaaccess.HostgroupSummary
	for _, name := range all {
		if len(criteria) <= len(name) && name[:len(criteria)] == criteria {
			out = append(out, freeipaaccess.HostgroupSummary{Name: name})
		}
	}
	return out, nil
}
func (f *fakeDirectoryProvider) HBACRuleFind(ctx context.Context) ([]freeipaaccess.HBACRule, error) {
	return []freeipaaccess.HBACRule{{
		Name: "grant", Enabled: true,
		Groups: []string{"gpu-users"}, Hostgroups: []string{"pilot-target-gpu"}, Services: []string{"sshd"},
	}}, nil
}
func (f *fakeDirectoryProvider) HBACServiceGroupShow(ctx context.Context, name string) (freeipaaccess.HBACServiceGroup, error) {
	return freeipaaccess.HBACServiceGroup{}, &freeipaaccess.RPCError{Name: "NotFound"}
}
func (f *fakeDirectoryProvider) SudoRuleFind(ctx context.Context) ([]freeipaaccess.SudoRule, error) {
	return []freeipaaccess.SudoRule{{
		Name: "sudo-grant", Enabled: true,
		Groups: []string{"gpu-users"}, Hostgroups: []string{"pilot-target-gpu"},
		AllowCommands: []string{"/usr/bin/systemctl status nginx"},
	}}, nil
}
func (f *fakeDirectoryProvider) SudoCommandShow(ctx context.Context, name string) (freeipaaccess.SudoCommand, error) {
	return freeipaaccess.SudoCommand{Command: name}, nil
}
func (f *fakeDirectoryProvider) SudoCommandGroupShow(ctx context.Context, name string) (freeipaaccess.SudoCommandGroup, error) {
	return freeipaaccess.SudoCommandGroup{}, &freeipaaccess.RPCError{Name: "NotFound"}
}
func (f *fakeDirectoryProvider) HBACTest(ctx context.Context, req freeipaaccess.HBACTestRequest) (freeipaaccess.HBACTestResult, error) {
	return freeipaaccess.HBACTestResult{}, &freeipaaccess.RPCError{Name: "NotFound"}
}

// startFakeDirectory starts a real directoryapi.Server over a real Unix
// socket and returns a directoryClient dialing it. username must be this
// test process's own OS username (currentOSUsername) — the server
// resolves the real caller's identity via SO_PEERCRED, it is never told
// who is calling.
func startFakeDirectory(t *testing.T, username string) *directoryClient {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "directory.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	provider := &fakeDirectoryProvider{username: username}
	dirCfg := directoryapi.DirectoryConfig{ID: "directory-01", TargetHostgroupPrefix: "pilot-target-", GatewayHostgroupPrefix: "pilot-gateway-"}
	srv := directoryapi.NewServer(dirCfg, provider, provider, slog.Default())
	go srv.Serve(ln)                                         //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown(context.Background()) }) //nolint:errcheck

	return newDirectoryClient(sockPath)
}

// fakeMultiGatewayDirectoryProvider is fakeDirectoryProvider with TWO live
// pilot-gateway-gpu members, for the failover test (spec.md §19) —
// directorySSHLauncher can fail the first candidate and prove the second
// is tried.
type fakeMultiGatewayDirectoryProvider struct {
	fakeDirectoryProvider
}

func (f *fakeMultiGatewayDirectoryProvider) HostgroupShow(ctx context.Context, name string) (freeipaaccess.Hostgroup, error) {
	if name == "pilot-gateway-gpu" {
		return freeipaaccess.Hostgroup{Name: name, MemberHosts: []string{"gw-gpu-01.example.com", "gw-gpu-02.example.com"}}, nil
	}
	return f.fakeDirectoryProvider.HostgroupShow(ctx, name)
}

func startFakeDirectoryMultiGateway(t *testing.T, username string) *directoryClient {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "directory.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	provider := &fakeMultiGatewayDirectoryProvider{fakeDirectoryProvider{username: username}}
	dirCfg := directoryapi.DirectoryConfig{ID: "directory-01", TargetHostgroupPrefix: "pilot-target-", GatewayHostgroupPrefix: "pilot-gateway-"}
	srv := directoryapi.NewServer(dirCfg, provider, provider, slog.Default())
	go srv.Serve(ln)                                         //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown(context.Background()) }) //nolint:errcheck

	return newDirectoryClient(sockPath)
}

func TestDirectoryClientIdentityAndAccess(t *testing.T) {
	username := currentOSUsername(t)
	client := startFakeDirectory(t, username)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	identity, err := client.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if identity.Username != username || identity.Directory.ID != "directory-01" {
		t.Fatalf("Identity = %+v, want username %q", identity, username)
	}

	access, err := client.Access(ctx)
	if err != nil {
		t.Fatalf("Access: %v", err)
	}
	if len(access.Targets) != 1 || access.Targets[0].FQDN != "gpu-a.example.com" || !access.Targets[0].SSH.Allowed {
		t.Fatalf("Access = %+v", access)
	}
	if len(access.Targets[0].Routes) != 1 || access.Targets[0].Routes[0].RouteStatus != "ready" {
		t.Fatalf("Routes = %+v, want one ready route", access.Targets[0].Routes)
	}
}

func TestDirectoryClientConnectResolve(t *testing.T) {
	client := startFakeDirectory(t, currentOSUsername(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	allowed, err := client.ConnectResolve(ctx, "gpu-a.example.com")
	if err != nil {
		t.Fatalf("ConnectResolve: %v", err)
	}
	if !allowed.Allowed || allowed.Route == nil || len(allowed.Route.GatewayCandidates) != 1 {
		t.Fatalf("ConnectResolve = %+v, want allowed with one gateway candidate", allowed)
	}

	denied, err := client.ConnectResolve(ctx, "not-in-scope.example.com")
	if err != nil {
		t.Fatalf("ConnectResolve: %v", err)
	}
	if denied.Allowed {
		t.Fatalf("ConnectResolve = %+v, want denied", denied)
	}
}
