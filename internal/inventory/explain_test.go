package inventory

import "testing"

// setHBACRules replaces root's hbac.rules with rules — grantsRosterBase
// already declares an empty hbac.rules, so explain tests mutate it in
// place rather than re-declaring `hbac:` in a YAML fragment (go-yaml.v3
// rejects a duplicate top-level key).
func setHBACRules(root map[string]any, rules []any) {
	root["hbac"] = map[string]any{"rules": rules}
}

func TestExplainStaticHBAC_DirectUserHit(t *testing.T) {
	root := grantsRoster(t, "")
	setHBACRules(root, []any{map[string]any{
		"name":     "direct-rule",
		"subjects": map[string]any{"users": []any{"vendor01"}, "groups": []any{}},
		"targets":  map[string]any{"hosts": []any{"db-special.ipa.pilot.internal"}, "hostgroups": []any{}},
		"services": []any{"sshd"},
	}})
	sources := ExplainStaticHBAC(root, "vendor01", "db-special.ipa.pilot.internal", "sshd")
	if len(sources) != 1 || !sources[0].DirectUserHit || !sources[0].DirectHostHit {
		t.Fatalf("expected one direct-hit static_hbac source, got: %+v", sources)
	}
}

func TestExplainStaticHBAC_GroupPathThroughTeam(t *testing.T) {
	root := grantsRoster(t, "")
	setHBACRules(root, []any{map[string]any{
		"name":     "team-rule",
		"subjects": map[string]any{"users": []any{}, "groups": []any{"team-sre"}},
		"targets":  map[string]any{"hosts": []any{}, "hostgroups": []any{"production-db"}},
		"services": []any{"sshd"},
	}})
	// alice is a member of team-sre in grantsRosterBase; production-db has
	// no host members by default, so populate that so this matches via
	// hostgroup path too.
	hostgroups := listField(root, "hostgroups")
	productionDB := asMap(hostgroups[0])
	productionDB["membership"] = map[string]any{"hosts": []any{"db-special.ipa.pilot.internal"}}

	sources := ExplainStaticHBAC(root, "alice", "db-special.ipa.pilot.internal", "sshd")
	if len(sources) != 1 {
		t.Fatalf("expected one group/hostgroup-path source, got: %+v", sources)
	}
	s := sources[0]
	if s.DirectUserHit || len(s.GroupPath) != 1 || s.GroupPath[0] != "team-sre" {
		t.Fatalf("expected GroupPath=[team-sre], got: %+v", s)
	}
	if s.DirectHostHit || len(s.HostgroupPath) != 1 || s.HostgroupPath[0] != "production-db" {
		t.Fatalf("expected HostgroupPath=[production-db], got: %+v", s)
	}
}

func TestExplainStaticHBAC_DisabledOrAbsentRuleExcluded(t *testing.T) {
	root := grantsRoster(t, "")
	setHBACRules(root, []any{
		map[string]any{
			"name":     "disabled-rule",
			"enabled":  false,
			"subjects": map[string]any{"users": []any{"vendor01"}, "groups": []any{}},
			"targets":  map[string]any{"hosts": []any{"db-special.ipa.pilot.internal"}, "hostgroups": []any{}},
			"services": []any{"sshd"},
		},
		map[string]any{
			"name":     "absent-rule",
			"state":    "absent",
			"subjects": map[string]any{"users": []any{"vendor01"}, "groups": []any{}},
			"targets":  map[string]any{"hosts": []any{"db-special.ipa.pilot.internal"}, "hostgroups": []any{}},
			"services": []any{"sshd"},
		},
	})
	if sources := ExplainStaticHBAC(root, "vendor01", "db-special.ipa.pilot.internal", "sshd"); len(sources) != 0 {
		t.Fatalf("expected disabled/absent rules to be excluded, got: %+v", sources)
	}
}

func TestExplainStaticHBAC_AllHosts(t *testing.T) {
	root := grantsRoster(t, "")
	setHBACRules(root, []any{map[string]any{
		"name":     "allhosts-rule",
		"subjects": map[string]any{"users": []any{"vendor01"}, "groups": []any{}},
		"targets":  map[string]any{"hostcat": "all"},
		"services": []any{"sshd"},
	}})
	sources := ExplainStaticHBAC(root, "vendor01", "any-host.ipa.pilot.internal", "sshd")
	if len(sources) != 1 || !sources[0].AllHosts {
		t.Fatalf("expected an AllHosts match, got: %+v", sources)
	}
}

func TestExplainGrants_TemporaryGrantActiveDirectHit(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-12-31T00:00:00Z"}
    justification: {reason: "explain test"}
`)
	sources, err := ExplainGrants(root, "vendor01", "db-special.ipa.pilot.internal", "sshd", mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 1 || sources[0].Kind != "temporary_grant" || sources[0].Lifecycle != GrantActive {
		t.Fatalf("expected one active temporary_grant source, got: %+v", sources)
	}
	if sources[0].NextTransition == nil {
		t.Fatal("expected a next_transition_at for an active grant")
	}
}

func TestExplainGrants_ExpiredGrantExcluded(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-01-01T00:00:00Z"}
    justification: {reason: "explain test"}
`)
	sources, err := ExplainGrants(root, "vendor01", "db-special.ipa.pilot.internal", "sshd", mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 0 {
		t.Fatalf("expected an expired grant to be excluded from explain, got: %+v", sources)
	}
}

func TestExplainGrants_SudoGrantIgnoresServiceFilter(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: alice-prod-nginx
    kind: sudo_grant
    subjects: {users: [alice], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    validity: {not_after: "2026-12-31T00:00:00Z"}
    justification: {reason: "explain test"}
`)
	sources, err := ExplainGrants(root, "alice", "db-special.ipa.pilot.internal", "sshd", mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 1 || sources[0].Kind != "sudo_grant" {
		t.Fatalf("expected sudo_grant to match regardless of --service, got: %+v", sources)
	}
}

func TestExplainGrants_NonMatchingUserExcluded(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-12-31T00:00:00Z"}
    justification: {reason: "explain test"}
`)
	sources, err := ExplainGrants(root, "someone-else", "db-special.ipa.pilot.internal", "sshd", mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 0 {
		t.Fatalf("expected no match for a non-subject user, got: %+v", sources)
	}
}
