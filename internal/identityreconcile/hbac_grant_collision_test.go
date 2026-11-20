package identityreconcile

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

// name_collision_with_grant (spec §3.3, §4.2): the playbook creates, changes and deletes
// the HBAC rules it compiles from grants, whose names are in the name-space of
// inventory.CompiledLoginRulePrefix; the Go engine must never reconcile or delete a rule of
// that name-space because the roster says so.

const grantRosterHead = `
schema_version: 3
users:
  - {name: alice}
hbac:
  rules:
    - name: other
      subjects: {users: [alice]}
      targets: {hostcat: all}
      services: [sshd]
`

// grantRoster is a roster with one ordinary rule ("other") and one rule named name.
func grantRoster(name, state string) string {
	st := ""
	if state != "" {
		st = "\n      state: " + state
	}
	return grantRosterHead + fmt.Sprintf(`    - name: %s%s
      subjects: {users: [alice]}
      targets: {hostcat: all}
      services: [sshd]
`, name, st)
}

func TestBuildHBACBlocksRosterRulesInTheGrantNamespaceAndOnlyThose(t *testing.T) {
	compiled := inventory.CompiledLoginRuleName("vendor-project-x")
	for name, tc := range map[string]struct {
		rule, state string
		blocked     bool
	}{
		"the compiled name of a grant":                {compiled, "", true},
		"the bare prefix and one more character":      {inventory.CompiledLoginRulePrefix + "x", "", true},
		"upper case":                                  {strings.ToUpper(compiled), "", true},
		"mixed case":                                  {"Pilot-Grant-Login-Vendor-X-0A1b2c3d", "", true},
		"an absent entry":                             {compiled, "absent", true},
		"an absent entry in other case":               {strings.ToUpper(compiled), "absent", true},
		"the prefix in the middle of the name":        {"my-" + inventory.CompiledLoginRulePrefix + "x", "", false},
		"the prefix without its last dash":            {strings.TrimSuffix(inventory.CompiledLoginRulePrefix, "-") + "x", "", false},
		"the grant sudo name-space is not an HBAC's":  {"pilot-grant-sudo-vendor-x-0a1b2c3d", "", false},
		"a name that only looks like it":              {"pilot-grant-logins-x", "", false},
		"a name that follows the prefix with nothing": {"pilot-grant-login", "", false},
	} {
		obs := convergedObsWith()
		d := hbacDesired(t, grantRoster(tc.rule, tc.state))
		p := BuildHBAC(HBACInput{Desired: d, Obs: obs, Preview: true})
		var got []Blocked
		for _, b := range p.Blocked {
			if b.Reason == BlockedNameCollisionGrant {
				got = append(got, b)
			}
		}
		if (len(got) > 0) != tc.blocked {
			t.Errorf("%s: blocked %v, want %v (%v)", name, got, tc.blocked, p.Blocked)
			continue
		}
		if tc.blocked {
			if len(got) != 1 || !strings.EqualFold(got[0].Object, tc.rule) {
				t.Errorf("%s: blocked %v", name, got)
			}
			// Nothing is planned for the rule, whatever its state (not even the delete of
			// an absent entry whose live rule exists)...
			for _, op := range p.Operations {
				if op.Object == lower(tc.rule) {
					t.Errorf("%s: %s is planned for a rule in the grant name-space", name, op.ID)
				}
			}
		} else if tc.state == "" && hbacFind(p, KindHBACRuleCreate, lower(tc.rule)) == nil {
			t.Errorf("%s: an ordinary rule is not created: %v", name, hbacKinds(p))
		}
		// ... and the other rule of the roster is planned as if nothing were blocked.
		if hbacFind(p, KindHBACRuleCreate, "other") == nil {
			t.Errorf("%s: the blocked rule blocked another rule: %v", name, hbacKinds(p))
		}
	}
}

// convergedObsWith is a server that holds a live rule compiled from a grant (not in the
// roster, enabled, with members) and the live rule of an entry the roster marks absent.
func convergedObsWith() HBACObservation {
	obs := baseObs(
		LiveHBACRule{Name: inventory.CompiledLoginRuleName("vendor-project-x"), Enabled: true, Users: []string{"alice"}, Services: []string{"sshd"}, HostCategory: "all"},
		LiveHBACRule{Name: inventory.CompiledLoginRuleName("unrelated"), Enabled: false, Users: []string{"carl"}, Services: []string{"sshd"}},
	)
	return obs
}

func TestBuildHBACLeavesAGrantRuleTheRosterDoesNotNameAlone(t *testing.T) {
	// No roster rule is in the name-space: the live compiled rules are not touched (no
	// removal of their members, no disable, no delete) and are only reported as not managed.
	d := hbacDesired(t, grantRosterHead)
	p := BuildHBAC(HBACInput{Desired: d, Obs: convergedObsWith(), Preview: true})
	if len(p.Blocked) != 0 {
		t.Fatalf("blocked %v", p.Blocked)
	}
	for _, op := range p.Operations {
		if strings.HasPrefix(op.Object, inventory.CompiledLoginRulePrefix) {
			t.Errorf("an operation on a live rule compiled from a grant: %s", op.ID)
		}
	}
	if hbacFind(p, KindHBACRuleCreate, "other") == nil {
		t.Errorf("plan %v", hbacKinds(p))
	}
}

func TestExecuteHBACNeverTouchesALiveGrantRuleAndRefusesAGrantNamedRosterRule(t *testing.T) {
	compiled := inventory.CompiledLoginRuleName("vendor-project-x")
	setup := func(f *fakeHBAC) {
		r := f.newRule(compiled)
		r.hostCat = "all"
		r.users["alice"], r.services["sshd"] = true, true
		f.users["alice"] = true
	}
	// A roster that names no rule in the name-space: the run writes only its own rule and
	// leaves the compiled one as it was.
	e := newHBACEnv(t, grantRosterHead, setup)
	e.mustApply()
	for _, c := range e.f.writes() {
		if len(c.args) > 0 && strings.EqualFold(fmt.Sprint(c.args[0]), compiled) {
			t.Errorf("a write on the rule compiled from a grant: %s %v", c.method, c.args)
		}
	}
	if r := e.f.ruleNamed(compiled); r == nil || !r.enabled || !r.users["alice"] || !r.services["sshd"] || r.hostCat != "all" {
		t.Errorf("the compiled rule changed: %+v", r)
	}

	// A roster that deletes it (state: absent) or reconciles it is refused before any write.
	for _, state := range []string{"", "absent"} {
		e = newHBACEnv(t, grantRoster(compiled, state), setup)
		res, err := e.execute()
		if !errors.Is(err, ErrBlocked) || !strings.Contains(err.Error(), BlockedNameCollisionGrant) {
			t.Fatalf("state %q: err %v", state, err)
		}
		if len(e.f.writes()) != 0 || e.entry.prepared != 0 || res.Stop == nil || res.Stop.Stage != stopPlan1 {
			t.Errorf("state %q: writes %v", state, e.writeMethods())
		}
		if r := e.f.ruleNamed(compiled); r == nil || !r.enabled || !r.users["alice"] {
			t.Errorf("state %q: the compiled rule changed: %+v", state, r)
		}
	}
}

// The prefix is internal/inventory's, not a copy: every name the grant compiler makes is
// in the name-space the engine blocks, and nothing else the compiler makes is.
func TestGrantNamespaceFollowsTheCompiler(t *testing.T) {
	if inventory.CompiledLoginRulePrefix == "" || lower(inventory.CompiledLoginRulePrefix) != inventory.CompiledLoginRulePrefix {
		t.Fatalf("the prefix %q is empty or not lower case", inventory.CompiledLoginRulePrefix)
	}
	for _, g := range []string{"vendor-project-x", "Vendor X", "vendor_x", "A", "日本語", strings.Repeat("long-", 20), ""} {
		name := inventory.CompiledLoginRuleName(g)
		if !inGrantNamespace(name) || !inGrantNamespace(strings.ToUpper(name)) {
			t.Errorf("the compiled name %q of grant %q is not in the name-space", name, g)
		}
		if inGrantNamespace(inventory.CompiledSudoRuleName(g)) {
			t.Errorf("the sudo name of grant %q is in the HBAC name-space", g)
		}
	}
}
