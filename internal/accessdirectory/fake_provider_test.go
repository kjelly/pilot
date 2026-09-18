package accessdirectory

import (
	"context"
	"strings"

	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// fakeProvider is a hand-built in-memory freeipaaccess.Provider +
// freeipaaccess.HostgroupFinder for exercising this package's own
// cross-scope merge/dedup logic. internal/freeipaaccess's own tests
// (real captured fixtures) already prove wire parsing, and
// internal/accessportal's own tests already prove per-scope HBAC/sudo
// resolution — this package only needs realistic already-resolved domain
// values and a way to prove call counts.
type fakeProvider struct {
	users             map[string]freeipaaccess.User
	hosts             map[string]freeipaaccess.Host
	hostgroups        map[string]freeipaaccess.Hostgroup
	hostgroupShowErr  map[string]error // simulates a hostgroup existing for hostgroup_find but failing hostgroup_show (deleted mid-resolve)
	hbacRules         []freeipaaccess.HBACRule
	hbacServiceGroups map[string]freeipaaccess.HBACServiceGroup
	sudoRules         []freeipaaccess.SudoRule
	sudoCommandGroups map[string]freeipaaccess.SudoCommandGroup

	// Call counters proving spec.md §9.3's O(1)-regardless-of-scope-count
	// requirement: LoadPolicySnapshot's own calls must happen exactly
	// once per LoadDirectoryAccess call, no matter how many scopes it
	// then resolves against.
	userShowCalls      map[string]int
	hostShowCalls      map[string]int
	hostgroupShowCalls map[string]int
	hbacRuleFindCalls  int
	sudoRuleFindCalls  int
}

var _ freeipaaccess.Provider = (*fakeProvider)(nil)
var _ freeipaaccess.HostgroupFinder = (*fakeProvider)(nil)

func notFound(name string) error {
	return &freeipaaccess.RPCError{Code: 4001, Name: "NotFound", Message: name + ": not found"}
}

func (f *fakeProvider) Ping(ctx context.Context) (freeipaaccess.PingResult, error) {
	return freeipaaccess.PingResult{}, nil
}

func (f *fakeProvider) UserShow(ctx context.Context, username string) (freeipaaccess.User, error) {
	if f.userShowCalls == nil {
		f.userShowCalls = map[string]int{}
	}
	f.userShowCalls[username]++
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
	if f.hostShowCalls == nil {
		f.hostShowCalls = map[string]int{}
	}
	f.hostShowCalls[fqdn]++
	if h, ok := f.hosts[fqdn]; ok {
		return h, nil
	}
	return freeipaaccess.Host{FQDN: fqdn}, nil
}

func (f *fakeProvider) HostgroupShow(ctx context.Context, name string) (freeipaaccess.Hostgroup, error) {
	if f.hostgroupShowCalls == nil {
		f.hostgroupShowCalls = map[string]int{}
	}
	f.hostgroupShowCalls[name]++
	if err, ok := f.hostgroupShowErr[name]; ok {
		return freeipaaccess.Hostgroup{}, err
	}
	hg, ok := f.hostgroups[name]
	if !ok {
		return freeipaaccess.Hostgroup{}, notFound(name)
	}
	return hg, nil
}

// HostgroupFind mirrors real FreeIPA's substring-match semantics
// (docs/tmp/now/spec.md §8.1) — not a prefix-only match — against every
// hostgroup this fake "IPA server" knows about, independent of
// hostgroupShowErr (a name can be discoverable via find and still fail a
// later show, simulating deletion between the two calls).
func (f *fakeProvider) HostgroupFind(ctx context.Context, criteria string) ([]freeipaaccess.HostgroupSummary, error) {
	var out []freeipaaccess.HostgroupSummary
	for name := range f.hostgroups {
		if strings.Contains(name, criteria) {
			out = append(out, freeipaaccess.HostgroupSummary{Name: name})
		}
	}
	return out, nil
}

func (f *fakeProvider) HBACRuleFind(ctx context.Context) ([]freeipaaccess.HBACRule, error) {
	f.hbacRuleFindCalls++
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
	f.sudoRuleFindCalls++
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
