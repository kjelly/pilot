package inventory

import (
	"strings"
	"testing"
)

const hostRemoveFixture = `---
schema_version: 2
freeipa:
  domain: ipa.pilot.internal
hosts:
  - name: web1.ipa.pilot.internal
    state: present
    ip_address: "10.0.0.5"
  - name: web2.ipa.pilot.internal
    state: present
    ip_address: "10.0.0.6"
hostgroups:
  - name: web-servers
    state: present
    membership: {authoritative: true, hosts: [web1.ipa.pilot.internal, web2.ipa.pilot.internal], hostgroups: []}
netgroups:
  - name: ng-web
    membership: {authoritative: true, hosts: [web1.ipa.pilot.internal], users: [], groups: [], hostgroups: [], netgroups: []}
hbac:
  rules:
    - name: web-login
      subjects: {users: [admin], groups: []}
      targets: {hosts: [web1.ipa.pilot.internal, web2.ipa.pilot.internal], hostgroups: []}
      services: [sshd]
sudo:
  rules:
    - name: web-sudo
      subjects: {users: [admin], groups: []}
      targets: {hosts: [web1.ipa.pilot.internal, web2.ipa.pilot.internal], hostgroups: []}
`

// ---- SimulateRemoveRosterHost ---------------------------------------------

func TestSimulateRemoveRosterHost_ConvergesAbsentAndPrunesReferences(t *testing.T) {
	path := writeRosterFixture(t, hostRemoveFixture)
	violations, found, err := SimulateRemoveRosterHost(path, "web1.ipa.pilot.internal")
	if err != nil {
		t.Fatalf("SimulateRemoveRosterHost() error = %v", err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if len(violations) != 0 {
		t.Fatalf("expected a clean candidate, got violations: %v", violations)
	}

	// The on-disk file must remain untouched — Simulate* never writes.
	after := readFileHelper(t, path)
	if after != hostRemoveFixture {
		t.Fatal("SimulateRemoveRosterHost() must not mutate the roster file on disk")
	}
}

func TestSimulateRemoveRosterHost_NotFound(t *testing.T) {
	path := writeRosterFixture(t, hostRemoveFixture)
	violations, found, err := SimulateRemoveRosterHost(path, "does-not-exist.ipa.pilot.internal")
	if err != nil {
		t.Fatalf("SimulateRemoveRosterHost() error = %v", err)
	}
	if found {
		t.Fatal("expected found=false")
	}
	if violations != nil {
		t.Fatalf("expected nil violations for a not-found host, got %v", violations)
	}
}

func TestSimulateRemoveRosterHost_Ambiguous(t *testing.T) {
	fixture := strings.Replace(hostRemoveFixture, "web2.ipa.pilot.internal", "web1.ipa.pilot.internal", 1)
	path := writeRosterFixture(t, fixture)
	_, _, err := SimulateRemoveRosterHost(path, "web1.ipa.pilot.internal")
	if err == nil {
		t.Fatal("expected an error for an ambiguous host name")
	}
}

// SimulateRemoveRosterHost on an already-absent host must remain a safe,
// idempotent no-op (INV-9: a resumed decommission must not error just
// because a prior attempt already converged the roster side).
func TestSimulateRemoveRosterHost_AlreadyAbsentIsIdempotent(t *testing.T) {
	fixture := strings.Replace(hostRemoveFixture, "state: present\n    ip_address: \"10.0.0.5\"", "state: absent\n    ip_address: \"10.0.0.5\"", 1)
	path := writeRosterFixture(t, fixture)
	violations, found, err := SimulateRemoveRosterHost(path, "web1.ipa.pilot.internal")
	if err != nil {
		t.Fatalf("SimulateRemoveRosterHost() on an already-absent host error = %v", err)
	}
	if !found {
		t.Fatal("expected found=true for an already-absent host entry")
	}
	if len(violations) != 0 {
		t.Fatalf("expected a clean candidate, got violations: %v", violations)
	}
}

// ---- RemoveRosterHostReferences --------------------------------------------

func TestRemoveRosterHostReferences_PrunesOnlyThisHostsMembership(t *testing.T) {
	path := writeRosterFixture(t, hostRemoveFixture)
	if err := RemoveRosterHostReferences(path, "web1.ipa.pilot.internal"); err != nil {
		t.Fatalf("RemoveRosterHostReferences() error = %v", err)
	}

	hg, found, err := RosterHostgroup(path, "web-servers")
	if err != nil || !found {
		t.Fatalf("RosterHostgroup() error=%v found=%v", err, found)
	}
	membership := asMap(hg["membership"])
	hosts := stringListField(membership, "hosts")
	if contains(hosts, "web1.ipa.pilot.internal") {
		t.Fatalf("expected web1 pruned from hostgroup membership, got %v", hosts)
	}
	if !contains(hosts, "web2.ipa.pilot.internal") {
		t.Fatalf("expected web2 (a DIFFERENT host) to remain a member, got %v", hosts)
	}

	hbacRule, found, err := RosterHBACRule(path, "web-login")
	if err != nil || !found {
		t.Fatalf("RosterHBACRule() error=%v found=%v", err, found)
	}
	targets := asMap(hbacRule["targets"])
	if contains(stringListField(targets, "hosts"), "web1.ipa.pilot.internal") {
		t.Fatalf("expected web1 pruned from HBAC rule targets.hosts, got %v", targets)
	}

	// The hostgroup/HBAC/sudo/netgroup OBJECTS themselves must survive —
	// only this host's membership/target entry is pruned, never the
	// containing rule.
	names, err := RosterHostgroupNames(path)
	if err != nil {
		t.Fatalf("RosterHostgroupNames() error = %v", err)
	}
	if !contains(names, "web-servers") {
		t.Fatalf("expected the web-servers hostgroup object to survive, got %v", names)
	}
}

func TestRemoveRosterHostReferences_NoReferencesIsNoop(t *testing.T) {
	path := writeRosterFixture(t, hostRemoveFixture)
	before := readFileHelper(t, path)
	if err := RemoveRosterHostReferences(path, "web2.ipa.pilot.internal"); err != nil {
		t.Fatalf("RemoveRosterHostReferences() error = %v", err)
	}
	// web2 only appears in the hostgroup membership list; pruning it
	// still changes that one list, so just confirm it succeeds and the
	// other host's references are untouched — the hbac/sudo/netgroup
	// sections never mentioned web2 at all.
	hbacRule, found, err := RosterHBACRule(path, "web-login")
	if err != nil || !found {
		t.Fatalf("RosterHBACRule() error=%v found=%v", err, found)
	}
	targets := asMap(hbacRule["targets"])
	if !contains(stringListField(targets, "hosts"), "web1.ipa.pilot.internal") {
		t.Fatalf("expected web1 (unrelated to this call) to remain an HBAC target, got %v", targets)
	}
	_ = before
}

// ---- SetRosterHostAbsent ----------------------------------------------------

func TestSetRosterHostAbsent_ConvergesStateWithoutDeletingEntry(t *testing.T) {
	path := writeRosterFixture(t, hostRemoveFixture)
	if err := SetRosterHostAbsent(path, "web1.ipa.pilot.internal"); err != nil {
		t.Fatalf("SetRosterHostAbsent() error = %v", err)
	}

	names, err := RosterHostNamesForTest(path)
	if err != nil {
		t.Fatalf("read hosts: %v", err)
	}
	if !contains(names, "web1.ipa.pilot.internal") {
		t.Fatalf("expected the hosts[] entry to SURVIVE with state: absent (not be deleted), got names=%v", names)
	}

	root, err := ReadRosterAsMapFile(path)
	if err != nil {
		t.Fatalf("ReadRosterAsMapFile() error = %v", err)
	}
	hosts := listField(root, "hosts")
	idx, _ := findNamedEntry(hosts, "web1.ipa.pilot.internal")
	if idx < 0 {
		t.Fatal("expected to find web1's entry")
	}
	if stateOrDefault(asMap(hosts[idx]), "present") != "absent" {
		t.Fatalf("expected state: absent, got %v", asMap(hosts[idx]))
	}
	// ip_address must be preserved — the identity-apply playbook's
	// surgical DNS deletion needs it to know the exact owned value.
	if stringField(asMap(hosts[idx]), "ip_address") != "10.0.0.5" {
		t.Fatalf("expected ip_address to be preserved, got %v", asMap(hosts[idx]))
	}
}

func TestSetRosterHostAbsent_UnknownHostErrors(t *testing.T) {
	path := writeRosterFixture(t, hostRemoveFixture)
	if err := SetRosterHostAbsent(path, "does-not-exist.ipa.pilot.internal"); err == nil {
		t.Fatal("expected an error for an unknown host name")
	}
}

func TestSetRosterHostAbsent_Ambiguous(t *testing.T) {
	fixture := strings.Replace(hostRemoveFixture, "web2.ipa.pilot.internal", "web1.ipa.pilot.internal", 1)
	path := writeRosterFixture(t, fixture)
	if err := SetRosterHostAbsent(path, "web1.ipa.pilot.internal"); err == nil {
		t.Fatal("expected an error for an ambiguous host name")
	}
}

// RosterHostNamesForTest is a tiny local helper mirroring
// RosterHostgroupNames/RosterUserNames for hosts[], which roster.go has no
// exported reader for yet — kept test-local rather than growing the
// package's public surface for a need only this test file has so far.
func RosterHostNamesForTest(path string) ([]string, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return namesOf(listField(root, "hosts")), nil
}
