package accessportal

import (
	"context"

	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// fakeProvider is a hand-built in-memory freeipaaccess.Provider for
// exercising this package's own resolution logic. It never touches JSON —
// internal/freeipaaccess's own tests (against real captured fixtures)
// already prove the wire parsing; this package only needs realistic
// already-parsed domain values, which the tests below take from real
// captures documented in
// docs/evidence/pilot-access-gateway/2026-09-14-phase2-accessportal.md.
type fakeProvider struct {
	users             map[string]freeipaaccess.User
	hosts             map[string]freeipaaccess.Host
	hostShowErr       map[string]error
	hostgroups        map[string]freeipaaccess.Hostgroup
	hbacRules         []freeipaaccess.HBACRule
	hbacServiceGroups map[string]freeipaaccess.HBACServiceGroup
	sudoRules         []freeipaaccess.SudoRule
	sudoCommandGroups map[string]freeipaaccess.SudoCommandGroup
}

var _ freeipaaccess.Provider = (*fakeProvider)(nil)

func notFound(name string) error {
	return &freeipaaccess.RPCError{Code: 4001, Name: "NotFound", Message: name + ": not found"}
}

func (f *fakeProvider) Ping(ctx context.Context) (freeipaaccess.PingResult, error) {
	return freeipaaccess.PingResult{}, nil
}

func (f *fakeProvider) UserShow(ctx context.Context, username string) (freeipaaccess.User, error) {
	u, ok := f.users[username]
	if !ok {
		return freeipaaccess.User{}, notFound(username)
	}
	return u, nil
}

func (f *fakeProvider) GroupShow(ctx context.Context, name string) (freeipaaccess.Group, error) {
	return freeipaaccess.Group{}, notFound(name)
}

func (f *fakeProvider) HostShow(ctx context.Context, fqdn string) (freeipaaccess.Host, error) {
	if err, ok := f.hostShowErr[fqdn]; ok {
		return freeipaaccess.Host{}, err
	}
	if h, ok := f.hosts[fqdn]; ok {
		return h, nil
	}
	return freeipaaccess.Host{FQDN: fqdn}, nil
}

func (f *fakeProvider) HostgroupShow(ctx context.Context, name string) (freeipaaccess.Hostgroup, error) {
	hg, ok := f.hostgroups[name]
	if !ok {
		return freeipaaccess.Hostgroup{}, notFound(name)
	}
	return hg, nil
}

func (f *fakeProvider) HBACRuleFind(ctx context.Context) ([]freeipaaccess.HBACRule, error) {
	return f.hbacRules, nil
}

func (f *fakeProvider) HBACServiceGroupShow(ctx context.Context, name string) (freeipaaccess.HBACServiceGroup, error) {
	sg, ok := f.hbacServiceGroups[name]
	if !ok {
		return freeipaaccess.HBACServiceGroup{}, notFound(name)
	}
	return sg, nil
}

func (f *fakeProvider) SudoRuleFind(ctx context.Context) ([]freeipaaccess.SudoRule, error) {
	return f.sudoRules, nil
}

func (f *fakeProvider) SudoCommandShow(ctx context.Context, name string) (freeipaaccess.SudoCommand, error) {
	return freeipaaccess.SudoCommand{Command: name}, nil
}

func (f *fakeProvider) SudoCommandGroupShow(ctx context.Context, name string) (freeipaaccess.SudoCommandGroup, error) {
	cg, ok := f.sudoCommandGroups[name]
	if !ok {
		return freeipaaccess.SudoCommandGroup{}, notFound(name)
	}
	return cg, nil
}

func (f *fakeProvider) HBACTest(ctx context.Context, req freeipaaccess.HBACTestRequest) (freeipaaccess.HBACTestResult, error) {
	return freeipaaccess.HBACTestResult{}, notFound("hbactest not used in this test")
}
