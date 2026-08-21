package inventory

import "testing"

func refPaths(refs []RosterReference) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.Path
	}
	return out
}

const referenceFixture = `
schema_version: 2
groups:
  - name: team-platform
    category: team
    membership: {users: [typo-user], groups: [team-parent]}
  - name: team-parent
    category: team
hbac:
  rules:
    - name: ssh-platform
      subjects: {users: [typo-user], groups: [access-platform]}
      targets: {hostcat: all}
      services: [sshd]
sudo:
  rules:
    - name: sudo-build
      subjects: {users: [typo-user], groups: [role-build]}
      targets: {hostcat: all}
      run_as: {users: [], groups: [role-build]}
netgroups:
  - name: ng-build
    membership: {authoritative: true, users: [typo-user], groups: [team-parent]}
nfs:
  servers:
    - host: nfs1.ipa.pilot.internal
      shares:
        - name: project-alpha
          ownership: {group: data-project-alpha-rw}
          acl:
            access:
              named_groups: [{name: data-project-alpha-rw}]
            default:
              named_groups: [{name: data-project-alpha-rw}]
`

func TestRosterUserReferences_FindsEveryKind(t *testing.T) {
	root := mustParseRoster(t, referenceFixture)
	refs := RosterUserReferences(root, "typo-user")
	want := []string{
		"groups[team-platform].membership.users",
		"hbac.rules[ssh-platform].subjects.users",
		"netgroups[ng-build].membership.users",
		"sudo.rules[sudo-build].subjects.users",
	}
	got := refPaths(refs)
	if len(got) != len(want) {
		t.Fatalf("RosterUserReferences() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("RosterUserReferences()[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
	for _, r := range refs {
		if r.Cascade != RosterReferenceCascadeRemovable {
			t.Fatalf("expected every user reference to be removable, got %+v", r)
		}
	}
}

func TestRosterUserReferences_NoneWhenUnreferenced(t *testing.T) {
	root := mustParseRoster(t, referenceFixture)
	if refs := RosterUserReferences(root, "nobody"); len(refs) != 0 {
		t.Fatalf("expected no references, got %v", refs)
	}
}

func TestRosterGroupReferences_FindsEveryKindIncludingBlocked(t *testing.T) {
	root := mustParseRoster(t, referenceFixture)
	refs := RosterGroupReferences(root, "data-project-alpha-rw")
	want := map[string]RosterReferenceCascade{
		"nfs.servers[nfs1.ipa.pilot.internal].shares[project-alpha].acl.access.named_groups[data-project-alpha-rw]":  RosterReferenceCascadeRemovable,
		"nfs.servers[nfs1.ipa.pilot.internal].shares[project-alpha].acl.default.named_groups[data-project-alpha-rw]": RosterReferenceCascadeRemovable,
		"nfs.servers[nfs1.ipa.pilot.internal].shares[project-alpha].ownership.group":                                 RosterReferenceCascadeBlocked,
	}
	if len(refs) != len(want) {
		t.Fatalf("RosterGroupReferences() = %v, want keys %v", refs, want)
	}
	for _, r := range refs {
		wantCascade, ok := want[r.Path]
		if !ok {
			t.Fatalf("unexpected reference path %q", r.Path)
		}
		if r.Cascade != wantCascade {
			t.Fatalf("reference %q: Cascade = %q, want %q", r.Path, r.Cascade, wantCascade)
		}
	}
}

func TestRosterGroupReferences_FindsMembershipHBACAndSudoRunAs(t *testing.T) {
	root := mustParseRoster(t, referenceFixture)
	refs := RosterGroupReferences(root, "team-parent")
	got := refPaths(refs)
	want := []string{"groups[team-platform].membership.groups", "netgroups[ng-build].membership.groups"}
	if len(got) != len(want) {
		t.Fatalf("RosterGroupReferences() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("RosterGroupReferences()[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	refs = RosterGroupReferences(root, "role-build")
	got = refPaths(refs)
	want = []string{"sudo.rules[sudo-build].run_as.groups", "sudo.rules[sudo-build].subjects.groups"}
	if len(got) != len(want) {
		t.Fatalf("RosterGroupReferences(role-build) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("RosterGroupReferences(role-build)[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRosterGroupReferences_NoneWhenUnreferenced(t *testing.T) {
	root := mustParseRoster(t, referenceFixture)
	if refs := RosterGroupReferences(root, "nobody-group"); len(refs) != 0 {
		t.Fatalf("expected no references, got %v", refs)
	}
}
