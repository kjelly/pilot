package accessportal

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// blockingHostProvider exposes overlapping RPCs without relying on a speed
// threshold. Only hosts which pass scope and HBAC may reach HostShow.
type blockingHostProvider struct {
	*fakeProvider
	started      chan string
	release      chan struct{}
	mu           sync.Mutex
	active, peak int
}

func (p *blockingHostProvider) HostShow(ctx context.Context, fqdn string) (freeipaaccess.Host, error) {
	p.mu.Lock()
	p.active++
	if p.active > p.peak {
		p.peak = p.active
	}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.active--; p.mu.Unlock() }()
	p.started <- fqdn
	select {
	case <-p.release:
	case <-ctx.Done():
		return freeipaaccess.Host{}, ctx.Err()
	}
	if fqdn == "h00.example.com" {
		return freeipaaccess.Host{}, errors.New("host lookup failed")
	}
	return freeipaaccess.NewHostWithoutPolicy(fqdn), nil
}

func manyHostProvider(n int) *fakeProvider {
	hosts := make([]string, n)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%02d.example.com", i)
	}
	return &fakeProvider{
		users:      map[string]freeipaaccess.User{"alice": {Username: "alice"}},
		hostgroups: map[string]freeipaaccess.Hostgroup{"scope": {MemberHosts: hosts}},
		hbacRules:  []freeipaaccess.HBACRule{{Name: "allow", Enabled: true, Users: []string{"alice"}, HostCategoryAll: true, Services: []string{"sshd"}}},
	}
}

func TestLoadUserAccess_ParallelHostsKeepOrderAndFailClosedPolicy(t *testing.T) {
	p := &blockingHostProvider{fakeProvider: manyHostProvider(27), started: make(chan string, 28), release: make(chan struct{})}
	p.hbacRules[0].HostCategoryAll = false
	p.hbacRules[0].Hosts = append([]string(nil), p.hostgroups["scope"].MemberHosts...)
	hg := p.hostgroups["scope"]
	hg.MemberHosts = append(hg.MemberHosts, "denied.example.com")
	p.hostgroups["scope"] = hg
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type outcome struct {
		access UserAccess
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		a, e := NewResolver(p, GatewayConfig{TargetHostgroup: "scope"}).LoadUserAccess(ctx, "alice")
		done <- outcome{a, e}
	}()
	for range queryConcurrency {
		select {
		case <-p.started:
		case <-ctx.Done():
			t.Fatal("host RPCs were serialized; expected four overlapping reads")
		}
	}
	close(p.release)
	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	if len(got.access.Hosts) != 27 {
		t.Fatalf("got %d hosts", len(got.access.Hosts))
	}
	for i, h := range got.access.Hosts {
		if want := fmt.Sprintf("h%02d.example.com", i); h.FQDN != want {
			t.Fatalf("host %d = %s, want %s", i, h.FQDN, want)
		}
	}
	if got.access.Hosts[0].SSHRecording.Status() != RecordingStatusUnknown {
		t.Fatal("failed host read must keep recording policy unknown")
	}
	if got.access.Hosts[1].SSHRecording.Status() != RecordingStatusInherit {
		t.Fatal("successful host read lost recording policy")
	}
	if p.peak > queryConcurrency {
		t.Fatalf("peak concurrency=%d, limit=%d", p.peak, queryConcurrency)
	}
	close(p.started)
	for name := range p.started {
		if name == "denied.example.com" {
			t.Fatal("host metadata was fetched before checking HBAC")
		}
	}
}

func TestQueryBatch_CancellationStopsPendingRPCs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan string, 20)
	done := make(chan error, 1)
	go func() {
		_, err := queryBatch(ctx, make([]string, 20), func(ctx context.Context, name string) (string, error) {
			started <- name
			<-ctx.Done()
			return "", ctx.Err()
		})
		done <- err
	}()
	for range queryConcurrency {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("workers did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled batch did not exit")
	}
	if len(started) != 0 {
		t.Fatalf("started %d pending RPCs after cancellation", len(started))
	}
}

func TestLoadPolicySnapshot_OnlyExpandsApplicableRules(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	p := manyHostProvider(1)
	p.users["alice"] = freeipaaccess.User{Username: "alice", IndirectGroups: []string{"nested"}}
	// All irrelevant rules reference missing groups. Querying them would fail.
	p.hbacRules = append(p.hbacRules,
		freeipaaccess.HBACRule{Name: "other", Enabled: true, Users: []string{"bob"}, Hostgroups: []string{"missing"}},
		freeipaaccess.HBACRule{Name: "disabled", Users: []string{"alice"}, Hostgroups: []string{"missing"}},
		freeipaaccess.HBACRule{Name: "nested", Enabled: true, Groups: []string{"nested"}, Hostgroups: []string{"scope"}, Services: []string{"sshd"}},
	)
	p.sudoRules = []freeipaaccess.SudoRule{
		{Name: "other", Enabled: true, Users: []string{"bob"}, Hostgroups: []string{"missing"}},
		{Name: "expired", Enabled: true, Users: []string{"alice"}, NotAfter: &past, AllowCommandGroups: []string{"missing"}},
		{Name: "future", Enabled: true, Users: []string{"alice"}, NotBefore: &future, Hostgroups: []string{"missing"}},
		{Name: "all", Enabled: true, UserCategoryAll: true, HostCategoryAll: true, CommandCategoryAll: true},
	}
	s, err := LoadPolicySnapshot(context.Background(), p, "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.HBACRules) != 2 || len(s.SudoRules) != 1 {
		t.Fatalf("kept rules: HBAC=%+v sudo=%+v", s.HBACRules, s.SudoRules)
	}
	a, err := ResolveScopeAccess(context.Background(), p, s, GatewayConfig{TargetHostgroup: "scope"})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Hosts) != 1 || a.Hosts[0].Sudo.Scope != "all" || len(a.Hosts[0].SSH.Rules) != 2 {
		t.Fatalf("access changed: %+v", a)
	}
	// A new request must observe revocation; there is no cross-request cache.
	p.hbacRules = nil
	a, err = NewResolver(p, GatewayConfig{TargetHostgroup: "scope"}).LoadUserAccess(context.Background(), "alice")
	if err != nil || len(a.Hosts) != 0 {
		t.Fatalf("revoked access survived: %+v %v", a, err)
	}
}

func TestLoadPolicySnapshot_ApplicableGroupFailureStillDenies(t *testing.T) {
	p := manyHostProvider(1)
	p.hbacRules[0].HostCategoryAll = false
	p.hbacRules[0].Hostgroups = []string{"missing"}
	a, err := NewResolver(p, GatewayConfig{TargetHostgroup: "scope"}).LoadUserAccess(context.Background(), "alice")
	if err == nil || len(a.Hosts) != 0 {
		t.Fatalf("expected fail-closed error, got %+v %v", a, err)
	}
}

type blockingGroupsProvider struct {
	*fakeProvider
	started chan string
	release chan struct{}
}

func (p *blockingGroupsProvider) wait(ctx context.Context, name string) error {
	p.started <- name
	select {
	case <-p.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *blockingGroupsProvider) HostgroupShow(ctx context.Context, name string) (freeipaaccess.Hostgroup, error) {
	if err := p.wait(ctx, name); err != nil {
		return freeipaaccess.Hostgroup{}, err
	}
	return freeipaaccess.Hostgroup{MemberHosts: []string{"HOST.EXAMPLE.COM."}}, nil
}
func (p *blockingGroupsProvider) HBACServiceGroupShow(ctx context.Context, name string) (freeipaaccess.HBACServiceGroup, error) {
	if err := p.wait(ctx, name); err != nil {
		return freeipaaccess.HBACServiceGroup{}, err
	}
	return freeipaaccess.HBACServiceGroup{Services: []string{"sshd"}}, nil
}
func (p *blockingGroupsProvider) SudoCommandGroupShow(ctx context.Context, name string) (freeipaaccess.SudoCommandGroup, error) {
	if err := p.wait(ctx, name); err != nil {
		return freeipaaccess.SudoCommandGroup{}, err
	}
	return freeipaaccess.SudoCommandGroup{Commands: []string{"/usr/bin/id"}}, nil
}

func TestReferencedGroups_AreFetchedConcurrently(t *testing.T) {
	names := []string{"a", "b", "c", "d"}
	for _, kind := range []string{"host", "service", "command"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			p := &blockingGroupsProvider{fakeProvider: manyHostProvider(1), started: make(chan string, 4), release: make(chan struct{})}
			r := NewResolver(p, GatewayConfig{})
			type outcome struct {
				groups map[string]map[string]struct{}
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				var m map[string]map[string]struct{}
				var err error
				switch kind {
				case "host":
					m, err = r.expandReferencedHostgroups(ctx, []freeipaaccess.HBACRule{{Hostgroups: names}}, nil)
				case "service":
					m, err = r.expandReferencedServiceGroups(ctx, []freeipaaccess.HBACRule{{ServiceGroups: names}})
				case "command":
					m, err = r.expandReferencedCommandGroups(ctx, []freeipaaccess.SudoRule{{AllowCommandGroups: names, DenyCommandGroups: names}})
				}
				done <- outcome{m, err}
			}()
			for range 4 {
				select {
				case <-p.started:
				case <-ctx.Done():
					t.Fatal("group RPCs were serialized")
				}
			}
			close(p.release)
			got := <-done
			if got.err != nil {
				t.Fatal(got.err)
			}
			value := map[string]string{"host": "host.example.com", "service": "sshd", "command": "/usr/bin/id"}[kind]
			for _, name := range names {
				if !reflect.DeepEqual(got.groups[name], map[string]struct{}{value: {}}) {
					t.Fatalf("%s=%v", name, got.groups[name])
				}
			}
		})
	}
}

// BenchmarkLoadUserAccess43RPCs models the incident's request count with a
// controlled 5ms RPC delay. It measures client-side scheduling, not FreeIPA.
type latencyProvider struct{ *fakeProvider }

func (p *latencyProvider) pause(ctx context.Context) error {
	select {
	case <-time.After(5 * time.Millisecond):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *latencyProvider) UserShow(ctx context.Context, name string) (freeipaaccess.User, error) {
	if err := p.pause(ctx); err != nil {
		return freeipaaccess.User{}, err
	}
	return p.fakeProvider.UserShow(ctx, name)
}
func (p *latencyProvider) HBACRuleFind(ctx context.Context) ([]freeipaaccess.HBACRule, error) {
	if err := p.pause(ctx); err != nil {
		return nil, err
	}
	return p.fakeProvider.HBACRuleFind(ctx)
}
func (p *latencyProvider) SudoRuleFind(ctx context.Context) ([]freeipaaccess.SudoRule, error) {
	if err := p.pause(ctx); err != nil {
		return nil, err
	}
	return p.fakeProvider.SudoRuleFind(ctx)
}
func (p *latencyProvider) HostgroupShow(ctx context.Context, name string) (freeipaaccess.Hostgroup, error) {
	if err := p.pause(ctx); err != nil {
		return freeipaaccess.Hostgroup{}, err
	}
	return p.fakeProvider.HostgroupShow(ctx, name)
}
func (p *latencyProvider) HostShow(ctx context.Context, name string) (freeipaaccess.Host, error) {
	if err := p.pause(ctx); err != nil {
		return freeipaaccess.Host{}, err
	}
	return p.fakeProvider.HostShow(ctx, name)
}

func BenchmarkLoadUserAccess43RPCs(b *testing.B) {
	p := manyHostProvider(27)
	p.hbacRules[0].HostCategoryAll = false
	hosts := p.hostgroups["scope"].MemberHosts
	for i := range 12 {
		name := fmt.Sprintf("group-%02d", i)
		p.hostgroups[name] = freeipaaccess.Hostgroup{MemberHosts: hosts}
		p.hbacRules[0].Hostgroups = append(p.hbacRules[0].Hostgroups, name)
	}
	resolver := NewResolver(&latencyProvider{p}, GatewayConfig{TargetHostgroup: "scope"})
	b.ResetTimer()
	for range b.N {
		a, err := resolver.LoadUserAccess(context.Background(), "alice")
		if err != nil || len(a.Hosts) != 27 {
			b.Fatalf("access=%+v error=%v", a, err)
		}
	}
}
