package inventory

import (
	"errors"
	"strings"
	"testing"
)

const removeFixture = `---
schema_version: 2
freeipa:
  domain: ipa.pilot.internal
users:
  - name: typo-user
    state: present
  - name: alice
    state: present
  - name: bob
    state: absent
  - name: dave
    state: present
groups:
  - name: team-platform
    category: team
    membership: {users: [typo-user, alice], groups: []}
  - name: team-empty
    category: team
    membership: {users: [], groups: []}
  - name: access-ssh
    category: access
hbac:
  rules:
    - name: ssh-one-user
      subjects: {users: [typo-user], groups: [access-ssh]}
      targets: {hostcat: all}
      services: [sshd]
sudo:
  rules:
    - name: sudo-build
      subjects: {users: [typo-user, alice], groups: []}
      targets: {hostcat: all}
netgroups:
  - name: ng-build
    membership: {authoritative: true, users: [typo-user], groups: []}
`

const removeGroupFixture = `---
schema_version: 2
freeipa:
  domain: ipa.pilot.internal
groups:
  - name: team-never-applied
    category: team
  - name: team-parent
    category: team
    membership: {users: [], groups: [team-never-applied]}
  - name: data-project-alpha-rw
    category: filesystem
  - name: team-absent-already
    category: team
    state: absent
nfs:
  servers:
    - host: nfs1.ipa.pilot.internal
      shares:
        - name: project-alpha
          ownership: {group: data-project-alpha-rw}
          acl:
            access: {named_groups: [{name: data-project-alpha-rw}]}
            default: {named_groups: []}
`

// ---- SimulateRemoveRosterUser / RemoveRosterUser --------------------------

func TestSimulateRemoveRosterUser_UnreferencedUserRemovesClean(t *testing.T) {
	path := writeRosterFixture(t, removeFixture)
	sim, err := SimulateRemoveRosterUser(path, "dave", RemoveRosterUserOptions{})
	if err != nil {
		t.Fatalf("SimulateRemoveRosterUser() error = %v", err)
	}
	if !sim.Found {
		t.Fatalf("expected Found=true")
	}
	if len(sim.References) != 0 {
		t.Fatalf("dave is unreferenced; expected no References, got %v", sim.References)
	}
	if len(sim.Violations) != 0 {
		t.Fatalf("expected a clean candidate, got violations: %v", sim.Violations)
	}
}

func TestSimulateRemoveRosterUser_MissingUserReportsNotFound(t *testing.T) {
	path := writeRosterFixture(t, removeFixture)
	sim, err := SimulateRemoveRosterUser(path, "nobody", RemoveRosterUserOptions{})
	if err != nil {
		t.Fatalf("SimulateRemoveRosterUser() error = %v", err)
	}
	if sim.Found {
		t.Fatalf("expected Found=false for a missing user")
	}
}

func TestSimulateRemoveRosterUser_AbsentStateRejected(t *testing.T) {
	path := writeRosterFixture(t, removeFixture)
	_, err := SimulateRemoveRosterUser(path, "bob", RemoveRosterUserOptions{})
	if !errors.Is(err, ErrRosterUserAbsentLifecycle) {
		t.Fatalf("SimulateRemoveRosterUser() error = %v, want ErrRosterUserAbsentLifecycle", err)
	}
}

func TestSimulateRemoveRosterUser_ReferencedWithoutCascadeReportsReferencesOnly(t *testing.T) {
	path := writeRosterFixture(t, removeFixture)
	sim, err := SimulateRemoveRosterUser(path, "typo-user", RemoveRosterUserOptions{})
	if err != nil {
		t.Fatalf("SimulateRemoveRosterUser() error = %v", err)
	}
	if !sim.Found || len(sim.References) == 0 {
		t.Fatalf("expected Found=true with references, got %+v", sim)
	}
	if len(sim.RemovedReferences) != 0 || sim.Violations != nil {
		t.Fatalf("expected no mutation candidate to be built without cascade, got %+v", sim)
	}
}

func TestSimulateRemoveRosterUser_CascadeRemovesEveryDirectReference(t *testing.T) {
	path := writeRosterFixture(t, removeFixture)
	sim, err := SimulateRemoveRosterUser(path, "typo-user", RemoveRosterUserOptions{CascadeReferences: true})
	if err != nil {
		t.Fatalf("SimulateRemoveRosterUser() error = %v", err)
	}
	if len(sim.RemovedReferences) != 4 {
		t.Fatalf("expected 4 removed references (group/hbac/sudo/netgroup), got %d: %v", len(sim.RemovedReferences), sim.RemovedReferences)
	}
	if len(sim.Violations) != 0 {
		t.Fatalf("expected a clean candidate after cascade, got violations: %v", sim.Violations)
	}
}

func TestSimulateRemoveRosterUser_CascadeThatInvalidatesHBACFails(t *testing.T) {
	// ssh-one-user's only subject is typo-user; removing it leaves the rule
	// with zero subjects, which checkHBAC's "needs at least one subject"
	// rule must reject — cascade must never delete the now-empty rule to
	// paper over this (spec.md §18).
	path := writeRosterFixture(t, `---
schema_version: 2
freeipa: {domain: ipa.pilot.internal}
users:
  - name: typo-user
    state: present
hbac:
  rules:
    - name: ssh-one-user
      subjects: {users: [typo-user], groups: []}
      targets: {hostcat: all}
      services: [sshd]
`)
	sim, err := SimulateRemoveRosterUser(path, "typo-user", RemoveRosterUserOptions{CascadeReferences: true})
	if err != nil {
		t.Fatalf("SimulateRemoveRosterUser() error = %v", err)
	}
	if !contains(ruleNames(sim.Violations), "hbac subjects") {
		t.Fatalf("expected an hbac subjects violation after cascade, got: %v", sim.Violations)
	}
}

func TestSimulateRemoveRosterUser_AmbiguousNameErrors(t *testing.T) {
	path := writeRosterFixture(t, "schema_version: 2\nusers:\n  - name: dup\n  - name: dup\n")
	if _, err := SimulateRemoveRosterUser(path, "dup", RemoveRosterUserOptions{}); err == nil {
		t.Fatalf("expected an ambiguous-name error")
	}
}

func TestRemoveRosterUser_UnreferencedUserPersistsRemoval(t *testing.T) {
	path := writeRosterFixture(t, removeFixture)
	if err := RemoveRosterUser(path, "dave", RemoveRosterUserOptions{}); err != nil {
		t.Fatalf("RemoveRosterUser() error = %v", err)
	}
	names, err := RosterUserNames(path)
	if err != nil {
		t.Fatal(err)
	}
	if contains(names, "dave") {
		t.Fatalf("expected dave to be removed, got %v", names)
	}
	if !contains(names, "typo-user") || !contains(names, "bob") || !contains(names, "alice") {
		t.Fatalf("expected other users to survive untouched, got %v", names)
	}
}

func TestRemoveRosterUser_WithoutCascadeRefusesWhenReferenced(t *testing.T) {
	path := writeRosterFixture(t, removeFixture)
	err := RemoveRosterUser(path, "typo-user", RemoveRosterUserOptions{})
	if err == nil {
		t.Fatalf("expected an error when typo-user is still referenced")
	}
	if !strings.Contains(err.Error(), "still referenced") {
		t.Fatalf("error = %v, want a still-referenced message", err)
	}
	names, err := RosterUserNames(path)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(names, "typo-user") {
		t.Fatalf("roster must be unchanged on refusal, got %v", names)
	}
}

func TestRemoveRosterUser_CascadeRemovesUserAndReferences(t *testing.T) {
	path := writeRosterFixture(t, removeFixture)
	if err := RemoveRosterUser(path, "typo-user", RemoveRosterUserOptions{CascadeReferences: true}); err != nil {
		t.Fatalf("RemoveRosterUser() error = %v", err)
	}
	violations, err := ValidateRosterFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected the written roster to validate clean, got: %v", violations)
	}
	names, err := RosterUserNames(path)
	if err != nil {
		t.Fatal(err)
	}
	if contains(names, "typo-user") {
		t.Fatalf("expected typo-user to be removed, got %v", names)
	}
	group, _, err := RosterGroup(path, "team-platform")
	if err != nil {
		t.Fatal(err)
	}
	if contains(stringListField(mapField(group, "membership"), "users"), "typo-user") {
		t.Fatalf("expected typo-user removed from group membership, got %v", group)
	}
	if !contains(stringListField(mapField(group, "membership"), "users"), "alice") {
		t.Fatalf("expected alice's membership to survive untouched, got %v", group)
	}
}

func TestRemoveRosterUser_AbsentStateRefused(t *testing.T) {
	path := writeRosterFixture(t, removeFixture)
	err := RemoveRosterUser(path, "bob", RemoveRosterUserOptions{})
	if !errors.Is(err, ErrRosterUserAbsentLifecycle) {
		t.Fatalf("RemoveRosterUser() error = %v, want ErrRosterUserAbsentLifecycle", err)
	}
}

func TestRemoveRosterUser_MissingUserErrors(t *testing.T) {
	path := writeRosterFixture(t, removeFixture)
	if err := RemoveRosterUser(path, "nobody", RemoveRosterUserOptions{}); err == nil {
		t.Fatalf("expected an error for a missing user")
	}
}

func TestRemoveRosterUser_EncryptedRosterReturnsErrRosterEncrypted(t *testing.T) {
	path := writeRosterFixture(t, "$ANSIBLE_VAULT;1.1;AES256\n633864363...\n")
	if err := RemoveRosterUser(path, "alice", RemoveRosterUserOptions{}); err != ErrRosterEncrypted {
		t.Fatalf("RemoveRosterUser() error = %v, want ErrRosterEncrypted", err)
	}
}

// ---- SimulateRemoveRosterGroup / RemoveRosterGroup ------------------------

func TestSimulateRemoveRosterGroup_NeverAppliedGroupRemovesClean(t *testing.T) {
	path := writeRosterFixture(t, removeGroupFixture)
	sim, err := SimulateRemoveRosterGroup(path, "data-project-alpha-rw", RemoveRosterGroupOptions{})
	if err != nil {
		t.Fatalf("SimulateRemoveRosterGroup() error = %v", err)
	}
	if !sim.Found {
		t.Fatalf("expected Found=true")
	}
	// data-project-alpha-rw has a blocked nfs ownership.group reference,
	// so it must be reported and never produce a mutation candidate.
	if len(sim.Violations) != 0 || len(sim.RemovedReferences) != 0 {
		t.Fatalf("expected no mutation candidate while a blocked reference exists, got %+v", sim)
	}
	blocked := false
	for _, ref := range sim.References {
		if ref.Cascade == RosterReferenceCascadeBlocked {
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("expected a blocked reference to be reported, got %v", sim.References)
	}
}

func TestSimulateRemoveRosterGroup_BlockedReferenceIgnoresCascadeFlag(t *testing.T) {
	path := writeRosterFixture(t, removeGroupFixture)
	sim, err := SimulateRemoveRosterGroup(path, "data-project-alpha-rw", RemoveRosterGroupOptions{CascadeReferences: true})
	if err != nil {
		t.Fatalf("SimulateRemoveRosterGroup() error = %v", err)
	}
	if len(sim.RemovedReferences) != 0 {
		t.Fatalf("cascade must never remove a blocked reference, got %v", sim.RemovedReferences)
	}
}

func TestSimulateRemoveRosterGroup_CascadeRemovesMembershipReference(t *testing.T) {
	path := writeRosterFixture(t, removeGroupFixture)
	sim, err := SimulateRemoveRosterGroup(path, "team-never-applied", RemoveRosterGroupOptions{CascadeReferences: true})
	if err != nil {
		t.Fatalf("SimulateRemoveRosterGroup() error = %v", err)
	}
	if len(sim.RemovedReferences) != 1 {
		t.Fatalf("expected exactly one removed membership reference, got %v", sim.RemovedReferences)
	}
	if len(sim.Violations) != 0 {
		t.Fatalf("expected a clean candidate after cascade, got: %v", sim.Violations)
	}
}

func TestSimulateRemoveRosterGroup_AbsentStateRejected(t *testing.T) {
	path := writeRosterFixture(t, removeGroupFixture)
	_, err := SimulateRemoveRosterGroup(path, "team-absent-already", RemoveRosterGroupOptions{})
	if !errors.Is(err, ErrRosterGroupAbsentLifecycle) {
		t.Fatalf("SimulateRemoveRosterGroup() error = %v, want ErrRosterGroupAbsentLifecycle", err)
	}
}

func TestRemoveRosterGroup_NeverAppliedGroupWithoutBlockedRefRemoves(t *testing.T) {
	path := writeRosterFixture(t, removeGroupFixture)
	if err := RemoveRosterGroup(path, "team-never-applied", RemoveRosterGroupOptions{CascadeReferences: true}); err != nil {
		t.Fatalf("RemoveRosterGroup() error = %v", err)
	}
	names, err := RosterGroupNames(path)
	if err != nil {
		t.Fatal(err)
	}
	if contains(names, "team-never-applied") {
		t.Fatalf("expected team-never-applied to be removed, got %v", names)
	}
	parent, _, err := RosterGroup(path, "team-parent")
	if err != nil {
		t.Fatal(err)
	}
	if contains(stringListField(mapField(parent, "membership"), "groups"), "team-never-applied") {
		t.Fatalf("expected the membership reference to be cascaded away, got %v", parent)
	}
}

func TestRemoveRosterGroup_BlockedNFSOwnershipReferenceAlwaysRefuses(t *testing.T) {
	path := writeRosterFixture(t, removeGroupFixture)
	err := RemoveRosterGroup(path, "data-project-alpha-rw", RemoveRosterGroupOptions{CascadeReferences: true})
	if err == nil {
		t.Fatalf("expected an error: ownership.group is a blocked reference even with cascade")
	}
	if !strings.Contains(err.Error(), "blocked reference") {
		t.Fatalf("error = %v, want a blocked-reference message", err)
	}
	names, err := RosterGroupNames(path)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(names, "data-project-alpha-rw") {
		t.Fatalf("roster must be unchanged on refusal, got %v", names)
	}
}

func TestRemoveRosterGroup_AbsentStateRefused(t *testing.T) {
	path := writeRosterFixture(t, removeGroupFixture)
	err := RemoveRosterGroup(path, "team-absent-already", RemoveRosterGroupOptions{})
	if !errors.Is(err, ErrRosterGroupAbsentLifecycle) {
		t.Fatalf("RemoveRosterGroup() error = %v, want ErrRosterGroupAbsentLifecycle", err)
	}
}

func TestRemoveRosterGroup_EncryptedRosterReturnsErrRosterEncrypted(t *testing.T) {
	path := writeRosterFixture(t, "$ANSIBLE_VAULT;1.1;AES256\n633864363...\n")
	if err := RemoveRosterGroup(path, "team-never-applied", RemoveRosterGroupOptions{}); err != ErrRosterEncrypted {
		t.Fatalf("RemoveRosterGroup() error = %v, want ErrRosterEncrypted", err)
	}
}
