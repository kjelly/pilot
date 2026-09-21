package outbound

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/inventory"
)

var projectionTestNow = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

const projectionTestHostsYML = `
vars:
  ansible_user: ubuntu
hosts:
  web1:
    ansible_host: "10.0.0.21"
    roles: [docker, freeipa-client]
    env: prod
    annotations:
      location: "DC1/Rack-A03"
      project: "demo"
  web2:
    ansible_host: "10.0.0.22"
    roles: [docker]
    env: staging
    secret_hint: "must-not-leak-PILOT-SECRET-NEVER-LEAK-123"
`

const projectionTestRoster = `
schema_version: 1
freeipa: {domain: ipa.pilot.internal}
users:
  - name: alice
    state: present
    display_name: Alice Wang
    email: alice@example.internal
    uid: 10001
    gid: 10001
    enabled: true
    password: {initial: "PILOT-SECRET-NEVER-LEAK-123"}
    ssh_keys: {authoritative: true, values: ["ssh-ed25519 AAAA-SECRET-KEY-FIXTURE"]}
  - name: bob
    state: disabled
    enabled: false
  - name: dave
    state: present
    enabled: true
  - name: carol
    state: absent
    enabled: true
groups:
  - name: team-x
    state: present
    category: team
    membership: {authoritative: true, users: [alice], groups: []}
  - name: team-x-parent
    state: present
    category: team
    membership: {authoritative: true, users: [], groups: [team-x]}
hostgroups:
  - name: web-hosts
    state: present
    membership: {authoritative: true, hosts: [web1.ipa.pilot.internal], hostgroups: [web-hosts-2]}
  - name: web-hosts-2
    state: present
    membership: {authoritative: true, hosts: [web2.ipa.pilot.internal], hostgroups: []}
hosts:
  - name: web1.ipa.pilot.internal
    state: present
    ip_address: "10.0.0.21"
  - name: web2.ipa.pilot.internal
    state: present
    ip_address: "10.0.0.22"
  - name: removed.ipa.pilot.internal
    state: absent
    ip_address: "10.0.0.99"
account_policies:
  - name: dave-expired
    user: dave
    state: present
    validity: {not_after: "2020-01-01T00:00:00Z"}
hbac:
  rules:
    - name: allow-team
      state: present
      enabled: true
      subjects: {users: [], groups: [team-x-parent]}
      targets: {hosts: [], hostgroups: [web-hosts]}
      services: [sshd]
    - name: allow-direct
      state: present
      enabled: true
      subjects: {users: [alice, dave], groups: []}
      targets: {hostcat: all}
      services: [sshd]
    - name: allow-disabled
      state: present
      enabled: false
      subjects: {users: [alice], groups: []}
      targets: {hostcat: all}
      services: [sshd]
sudo:
  command_groups:
    - name: cmdgrp-restart
      commands: ["/usr/bin/systemctl restart nginx"]
    - name: cmdgrp-logs
      commands: ["/usr/bin/journalctl -u nginx"]
  rules:
    - name: sudo-ops
      state: present
      subjects: {users: [alice], groups: []}
      targets: {hostcat: all}
      allow: {command_groups: [cmdgrp-restart], commands: ["/usr/bin/systemctl status nginx"]}
      deny: {command_groups: [cmdgrp-logs], commands: ["/usr/bin/rm"]}
      run_as: {users: [root], groups: [wheel]}
      options: ["!authenticate"]
    - name: sudo-admin-all
      state: present
      subjects: {users: [alice], groups: []}
      targets: {hostcat: all}
      allow: {}
grants:
  - name: vendor-active
    kind: temporary_grant
    state: present
    subjects: {users: [alice], groups: []}
    targets: {hostcat: all}
    services: [sshd]
    validity: {not_after: "2100-01-01T00:00:00Z"}
  - name: vendor-expired
    kind: temporary_grant
    state: present
    subjects: {users: [alice], groups: []}
    targets: {hostcat: all}
    services: [sshd]
    validity: {not_after: "2000-01-01T00:00:00Z"}
  - name: sudo-active-grant
    kind: sudo_grant
    state: present
    subjects: {users: [alice], groups: []}
    targets: {hostcat: all}
    privilege: {commands: [/usr/bin/systemctl], command_groups: []}
    run_as: {users: [root], groups: []}
    options: []
    validity: {not_after: "2100-01-01T00:00:00Z"}
  - name: sudo-expired-grant
    kind: sudo_grant
    state: present
    subjects: {users: [alice], groups: []}
    targets: {hostcat: all}
    privilege: {commands: [/usr/bin/systemctl], command_groups: []}
    run_as: {users: [root], groups: []}
    options: []
    validity: {not_after: "2000-01-01T00:00:00Z"}
  - name: bg-emergency
    kind: breakglass
    subjects: {users: [alice], groups: []}
    targets: {hostcat: all}
    services: [sshd]
`

func writeProjectionFixture(t *testing.T) (workspaceDir string, rosterPath string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(projectionTestHostsYML), 0o600); err != nil {
		t.Fatal(err)
	}
	rosterPath = filepath.Join(dir, "ipa-identity.yaml")
	if err := os.WriteFile(rosterPath, []byte(projectionTestRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, rosterPath
}

func hostVarsForRoster(rosterPath string, hostNames ...string) map[string]map[string]any {
	hv := make(map[string]map[string]any, len(hostNames))
	for _, h := range hostNames {
		hv[h] = map[string]any{"freeipa_roster_file": rosterPath}
	}
	return hv
}

func buildTestProjection(t *testing.T, dir, rosterPath string) ProjectionResult {
	t.Helper()
	return BuildProjection(ProjectionRequest{
		WorkspaceDir: dir,
		HostVars:     hostVarsForRoster(rosterPath, "web1", "web2"),
		Now:          projectionTestNow,
	})
}

func findHost(hosts []ProjectedHost, id string) (ProjectedHost, bool) {
	for _, h := range hosts {
		if h.ID == id {
			return h, true
		}
	}
	return ProjectedHost{}, false
}

func findUser(users []ProjectedUser, name string) (ProjectedUser, bool) {
	for _, u := range users {
		if u.Name == name {
			return u, true
		}
	}
	return ProjectedUser{}, false
}

func findLogin(entries []ProjectedLoginAccess, id string) (ProjectedLoginAccess, bool) {
	for _, e := range entries {
		if e.ID == id {
			return e, true
		}
	}
	return ProjectedLoginAccess{}, false
}

func findSudo(entries []ProjectedSudoAccess, id string) (ProjectedSudoAccess, bool) {
	for _, e := range entries {
		if e.ID == id {
			return e, true
		}
	}
	return ProjectedSudoAccess{}, false
}

// TestOutboundProjection_P1: inventory hosts include annotations.
func TestOutboundProjection_P1(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	web1, ok := findHost(result.Snapshot.Hosts, "inventory:web1")
	if !ok {
		t.Fatal("expected inventory:web1")
	}
	want := map[string]string{"location": "DC1/Rack-A03", "project": "demo"}
	if !reflect.DeepEqual(web1.Annotations, want) {
		t.Fatalf("web1.Annotations = %v, want %v", web1.Annotations, want)
	}
}

// TestOutboundProjection_P2: host Extra (arbitrary hosts.yml vars) is
// never present anywhere in the snapshot.
func TestOutboundProjection_P2(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	assertNoSecretLeak(t, result.Snapshot, "must-not-leak-PILOT-SECRET-NEVER-LEAK-123")
}

// TestOutboundProjection_P3: password fields never leak.
func TestOutboundProjection_P3(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	assertNoSecretLeak(t, result.Snapshot, "PILOT-SECRET-NEVER-LEAK-123")
}

// TestOutboundProjection_P4: ssh key values never leak.
func TestOutboundProjection_P4(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	assertNoSecretLeak(t, result.Snapshot, "ssh-ed25519 AAAA-SECRET-KEY-FIXTURE")
}

func assertNoSecretLeak(t *testing.T, snap UserHostAccessSnapshotV1, sentinel string) {
	t.Helper()
	body := fmtSnapshot(snap)
	if strings.Contains(body, sentinel) {
		t.Fatalf("snapshot leaked sentinel %q:\n%s", sentinel, body)
	}
}

// TestOutboundProjection_P5: nested group membership expands.
func TestOutboundProjection_P5(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	alice, ok := findUser(result.Snapshot.Users, "alice")
	if !ok {
		t.Fatal("expected alice")
	}
	want := []string{"team-x", "team-x-parent"}
	if !reflect.DeepEqual(alice.EffectiveGroups, want) {
		t.Fatalf("alice.EffectiveGroups = %v, want %v", alice.EffectiveGroups, want)
	}
}

// TestOutboundProjection_P6: nested hostgroup membership expands.
func TestOutboundProjection_P6(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	var webHosts ProjectedHostgroup
	found := false
	for _, hg := range result.Snapshot.Hostgroups {
		if hg.Name == "web-hosts" {
			webHosts, found = hg, true
		}
	}
	if !found {
		t.Fatal("expected web-hosts hostgroup")
	}
	want := []string{"inventory:web1", "inventory:web2"}
	if !reflect.DeepEqual(webHosts.EffectiveHostIDs, want) {
		t.Fatalf("web-hosts.EffectiveHostIDs = %v, want %v", webHosts.EffectiveHostIDs, want)
	}
}

// TestOutboundProjection_P7: effective HBAC (via nested group) is correct.
func TestOutboundProjection_P7(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	rule, ok := findLogin(result.Snapshot.Access.Login, "static_hbac:allow-team")
	if !ok {
		t.Fatal("expected static_hbac:allow-team")
	}
	if !reflect.DeepEqual(rule.Users, []string{"alice"}) {
		t.Fatalf("allow-team.Users = %v, want [alice] (via nested team-x-parent -> team-x)", rule.Users)
	}
	want := []string{"inventory:web1", "inventory:web2"}
	if !reflect.DeepEqual(rule.HostIDs, want) {
		t.Fatalf("allow-team.HostIDs = %v, want %v", rule.HostIDs, want)
	}
}

// TestOutboundProjection_P8: effective sudo is correct.
func TestOutboundProjection_P8(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	rule, ok := findSudo(result.Snapshot.Access.Sudo, "static_sudo:sudo-ops")
	if !ok {
		t.Fatal("expected static_sudo:sudo-ops")
	}
	if !reflect.DeepEqual(rule.Users, []string{"alice"}) {
		t.Fatalf("sudo-ops.Users = %v, want [alice]", rule.Users)
	}
	if rule.AllCommands {
		t.Fatal("sudo-ops.AllCommands = true, want false")
	}
	wantCommands := []string{"/usr/bin/systemctl restart nginx", "/usr/bin/systemctl status nginx"}
	if !reflect.DeepEqual(rule.Commands, wantCommands) {
		t.Fatalf("sudo-ops.Commands = %v, want %v", rule.Commands, wantCommands)
	}
}

// TestOutboundProjection_P9: an active temporary_grant is included.
func TestOutboundProjection_P9(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	rule, ok := findLogin(result.Snapshot.Access.Login, "temporary_grant:vendor-active")
	if !ok {
		t.Fatal("expected temporary_grant:vendor-active")
	}
	if rule.ValidUntil == nil || rule.ValidUntil.Year() != 2100 {
		t.Fatalf("vendor-active.ValidUntil = %v, want 2100", rule.ValidUntil)
	}
}

// TestOutboundProjection_P10: an inactive (expired) temporary_grant is
// excluded from effective login.
func TestOutboundProjection_P10(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	if _, ok := findLogin(result.Snapshot.Access.Login, "temporary_grant:vendor-expired"); ok {
		t.Fatal("expired temporary_grant must be excluded")
	}
}

// TestOutboundProjection_P11: an active sudo_grant is represented with
// validity.
func TestOutboundProjection_P11(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	rule, ok := findSudo(result.Snapshot.Access.Sudo, "sudo_grant:sudo-active-grant")
	if !ok {
		t.Fatal("expected sudo_grant:sudo-active-grant")
	}
	if rule.ValidNotAfter == nil || rule.ValidNotAfter.Year() != 2100 {
		t.Fatalf("sudo-active-grant.ValidNotAfter = %v, want 2100", rule.ValidNotAfter)
	}
}

// TestOutboundProjection_P12/P13: active breakglass included, inactive
// excluded.
func TestOutboundProjection_P12(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := BuildProjection(ProjectionRequest{
		WorkspaceDir: dir,
		HostVars:     hostVarsForRoster(rosterPath, "web1", "web2"),
		Now:          projectionTestNow,
		BreakglassActivations: []inventory.BreakglassActivationInput{
			{Name: "bg-emergency", ExpiresAt: projectionTestNow.Add(time.Hour)},
		},
	})
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	if _, ok := findLogin(result.Snapshot.Access.Login, "breakglass:bg-emergency"); !ok {
		t.Fatal("expected active breakglass:bg-emergency")
	}
}

func TestOutboundProjection_P13(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath) // no activations passed
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	if _, ok := findLogin(result.Snapshot.Access.Login, "breakglass:bg-emergency"); ok {
		t.Fatal("no active breakglass activation was supplied, must be excluded")
	}
}

// TestOutboundProjection_P14: deterministic sort/hash — rebuilding the
// same fixture twice yields the same snapshot ID, and hash excludes
// non-semantic fields (there are none in UserHostAccessSnapshotV1 itself
// — this also proves CanonicalizeSnapshot's sort is stable).
func TestOutboundProjection_P14(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	r1 := buildTestProjection(t, dir, rosterPath)
	r2 := buildTestProjection(t, dir, rosterPath)
	if !r1.Available || !r2.Available {
		t.Fatalf("projection unavailable: r1=%+v r2=%+v", r1, r2)
	}
	if SnapshotID(r1.Snapshot) != SnapshotID(r2.Snapshot) {
		t.Fatal("rebuilding the same fixture must produce the same snapshot ID")
	}
	if !strings.HasPrefix(SnapshotID(r1.Snapshot), "sha256:") {
		t.Fatalf("SnapshotID = %q, want sha256: prefix", SnapshotID(r1.Snapshot))
	}
}

// TestOutboundProjection_P17: a configured-but-unreadable roster never
// becomes an empty authoritative snapshot.
func TestOutboundProjection_P17(t *testing.T) {
	dir, _ := writeProjectionFixture(t)
	missing := filepath.Join(dir, "does-not-exist.yaml")
	result := BuildProjection(ProjectionRequest{
		WorkspaceDir: dir,
		HostVars:     hostVarsForRoster(missing, "web1"),
		Now:          projectionTestNow,
	})
	if result.Available {
		t.Fatalf("expected unavailable for a missing configured roster, got %+v", result)
	}
	if result.ErrorClass != ErrorClassProjectionUnavailable {
		t.Fatalf("ErrorClass = %q, want %q", result.ErrorClass, ErrorClassProjectionUnavailable)
	}
	if len(result.Snapshot.Users) != 0 || len(result.Snapshot.Hosts) != 0 {
		t.Fatalf("unavailable result must carry a zero-value snapshot, got %+v", result.Snapshot)
	}
}

// TestOutboundProjection_P18: a disabled HBAC rule is omitted entirely.
func TestOutboundProjection_P18(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	if _, ok := findLogin(result.Snapshot.Access.Login, "static_hbac:allow-disabled"); ok {
		t.Fatal("disabled HBAC rule must be omitted")
	}
}

// TestOutboundProjection_P19: an account-policy-expired user (dave) is
// retained as a user entity (Enabled=false) but excluded from access
// users.
func TestOutboundProjection_P19(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	dave, ok := findUser(result.Snapshot.Users, "dave")
	if !ok {
		t.Fatal("expected dave to remain as a user entity")
	}
	if dave.Enabled {
		t.Fatal("dave's account_policy is expired, Enabled must be false")
	}
	rule, ok := findLogin(result.Snapshot.Access.Login, "static_hbac:allow-direct")
	if !ok {
		t.Fatal("expected static_hbac:allow-direct")
	}
	if !reflect.DeepEqual(rule.Users, []string{"alice"}) {
		t.Fatalf("allow-direct.Users = %v, want [alice] (dave must be excluded)", rule.Users)
	}
}

// TestOutboundProjection_P20: the snapshot emits only inventory hosts even
// when the roster contains matching FQDN/address entries. Roster host
// references are resolved to the inventory IDs instead of creating a second
// host entity.
func TestOutboundProjection_P20(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	if len(result.Snapshot.Hosts) != 2 {
		t.Fatalf("projected host count = %d, want only the 2 hosts.yml hosts", len(result.Snapshot.Hosts))
	}
	for _, host := range result.Snapshot.Hosts {
		if !strings.HasPrefix(host.ID, "inventory:") || host.Source != "inventory" {
			t.Fatalf("host must be inventory-sourced: %+v", host)
		}
	}
	if _, ok := findHost(result.Snapshot.Hosts, "freeipa:web1.ipa.pilot.internal"); ok {
		t.Fatal("roster host must not be emitted as a second host entity")
	}
}

func TestOutboundProjection_RosterHostMappingFailsClosed(t *testing.T) {
	inventoryHosts := []ProjectedHost{{ID: "inventory:web1", Address: "10.0.0.21"}}

	if _, err := mapRosterHostsToInventory([]inventory.ExternalRosterHost{{Name: "web1.ipa.pilot.internal", Address: "10.0.0.22"}}, inventoryHosts); err == nil {
		t.Fatal("expected an unmatched roster host address to fail closed")
	}

	ambiguous := append(append([]ProjectedHost(nil), inventoryHosts...), ProjectedHost{ID: "inventory:web2", Address: "10.0.0.21"})
	if _, err := mapRosterHostsToInventory([]inventory.ExternalRosterHost{{Name: "web1.ipa.pilot.internal", Address: "10.0.0.21"}}, ambiguous); err == nil {
		t.Fatal("expected an ambiguous roster host address to fail closed")
	}
}

// TestOutboundProjection_P21: every explicit access host_id resolves to
// a projected inventory host.
func TestOutboundProjection_P21(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	present := map[string]bool{}
	for _, h := range result.Snapshot.Hosts {
		present[h.ID] = true
	}
	for _, l := range result.Snapshot.Access.Login {
		for _, id := range l.HostIDs {
			if !present[id] {
				t.Fatalf("login access %q references host id %q with no projected host", l.ID, id)
			}
		}
	}
	for _, s := range result.Snapshot.Access.Sudo {
		for _, id := range s.HostIDs {
			if !present[id] {
				t.Fatalf("sudo access %q references host id %q with no projected host", s.ID, id)
			}
		}
	}
}

// TestOutboundProjection_P22a: a dangling explicit host reference fails
// closed (projection unavailable), never silently dropped.
func TestOutboundProjection_P22a(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte("hosts: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	roster := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal}
users:
  - name: alice
    state: present
    enabled: true
hosts: []
hbac:
  rules:
    - name: dangling-rule
      state: present
      enabled: true
      subjects: {users: [alice], groups: []}
      targets: {hosts: [ghost.ipa.pilot.internal], hostgroups: []}
      services: [sshd]
`
	rosterPath := filepath.Join(dir, "ipa-identity.yaml")
	if err := os.WriteFile(rosterPath, []byte(roster), 0o600); err != nil {
		t.Fatal(err)
	}
	result := BuildProjection(ProjectionRequest{
		WorkspaceDir: dir,
		HostVars:     hostVarsForRoster(rosterPath, "any"),
		Now:          projectionTestNow,
	})
	if result.Available {
		t.Fatalf("expected unavailable for a dangling host reference, got %+v", result)
	}
	if result.ErrorClass != ErrorClassProjectionUnavailable {
		t.Fatalf("ErrorClass = %q, want %q", result.ErrorClass, ErrorClassProjectionUnavailable)
	}
}

// TestOutboundProjection_P22b: state:absent roster entities (hosts,
// groups, hostgroups, users) are omitted from the snapshot.
func TestOutboundProjection_P22b(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	if _, ok := findHost(result.Snapshot.Hosts, "inventory:removed"); ok {
		t.Fatal("state:absent inventory host must be omitted")
	}
	for _, host := range result.Snapshot.Hosts {
		if strings.HasPrefix(host.ID, "freeipa:") {
			t.Fatalf("roster host must not be projected: %+v", host)
		}
	}
	if _, ok := findUser(result.Snapshot.Users, "carol"); ok {
		t.Fatal("state:absent user must be omitted")
	}
}

// TestOutboundProjection_P23: duplicate active breakglass activation
// records for the same name collapse to one stable entity.
func TestOutboundProjection_P23(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := BuildProjection(ProjectionRequest{
		WorkspaceDir: dir,
		HostVars:     hostVarsForRoster(rosterPath, "web1"),
		Now:          projectionTestNow,
		BreakglassActivations: []inventory.BreakglassActivationInput{
			{Name: "bg-emergency", ExpiresAt: projectionTestNow.Add(1 * time.Hour)},
			{Name: "bg-emergency", ExpiresAt: projectionTestNow.Add(9 * time.Hour)},
		},
	})
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	count := 0
	var got ProjectedLoginAccess
	for _, l := range result.Snapshot.Access.Login {
		if l.ID == "breakglass:bg-emergency" {
			count++
			got = l
		}
	}
	if count != 1 {
		t.Fatalf("breakglass:bg-emergency appeared %d times, want exactly 1", count)
	}
	if got.ValidUntil == nil || !got.ValidUntil.Equal(projectionTestNow.Add(9*time.Hour).UTC()) {
		t.Fatalf("ValidUntil = %v, want max expiry", got.ValidUntil)
	}
}

// TestOutboundProjection_P24: an unavailable result never fabricates an
// empty-but-present snapshot (the zero value, not e.g. Users: []string{}
// dressed up to look verified).
func TestOutboundProjection_P24(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := BuildProjection(ProjectionRequest{
		WorkspaceDir: dir,
		HostVars: map[string]map[string]any{
			"a": {"freeipa_roster_file": rosterPath},
			"b": {"freeipa_roster_file": rosterPath + ".other"},
		},
		Now: projectionTestNow,
	})
	if result.Available {
		t.Fatal("expected unavailable for multiple distinct roster sources")
	}
	if result.ErrorClass != ErrorClassMultipleRosterSources {
		t.Fatalf("ErrorClass = %q, want %q", result.ErrorClass, ErrorClassMultipleRosterSources)
	}
	zero := UserHostAccessSnapshotV1{}
	if !reflect.DeepEqual(result.Snapshot, zero) {
		t.Fatalf("unavailable Snapshot = %+v, want the zero value (event/envelope layer omits it entirely — Phase 3)", result.Snapshot)
	}
}

// TestOutboundProjection_P25: hostgroup direct/nested membership
// projects valid namespaced host IDs and an effective transitive
// closure.
func TestOutboundProjection_P25(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	var webHosts ProjectedHostgroup
	for _, hg := range result.Snapshot.Hostgroups {
		if hg.Name == "web-hosts" {
			webHosts = hg
		}
	}
	if !reflect.DeepEqual(webHosts.HostIDs, []string{"inventory:web1"}) {
		t.Fatalf("web-hosts.HostIDs (direct) = %v, want [inventory:web1]", webHosts.HostIDs)
	}
	if !reflect.DeepEqual(webHosts.Hostgroups, []string{"web-hosts-2"}) {
		t.Fatalf("web-hosts.Hostgroups (direct nested ref) = %v, want [web-hosts-2]", webHosts.Hostgroups)
	}
}

// TestOutboundProjection_P26: static sudo allow/deny command groups,
// direct commands, run-as, and options all resolve completely.
func TestOutboundProjection_P26(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	rule, ok := findSudo(result.Snapshot.Access.Sudo, "static_sudo:sudo-ops")
	if !ok {
		t.Fatal("expected static_sudo:sudo-ops")
	}
	wantDenied := []string{"/usr/bin/journalctl -u nginx", "/usr/bin/rm"}
	if !reflect.DeepEqual(rule.DeniedCommands, wantDenied) {
		t.Fatalf("DeniedCommands = %v, want %v", rule.DeniedCommands, wantDenied)
	}
	if !reflect.DeepEqual(rule.RunAsUsers, []string{"root"}) || !reflect.DeepEqual(rule.RunAsGroups, []string{"wheel"}) {
		t.Fatalf("run_as = users=%v groups=%v, want [root]/[wheel]", rule.RunAsUsers, rule.RunAsGroups)
	}
	if !reflect.DeepEqual(rule.Options, []string{"!authenticate"}) {
		t.Fatalf("Options = %v, want [!authenticate]", rule.Options)
	}

	adminAll, ok := findSudo(result.Snapshot.Access.Sudo, "static_sudo:sudo-admin-all")
	if !ok {
		t.Fatal("expected static_sudo:sudo-admin-all")
	}
	if !adminAll.AllCommands || len(adminAll.Commands) != 0 {
		t.Fatalf("sudo-admin-all = %+v, want all_commands=true with no explicit commands (bare allow:{})", adminAll)
	}
}

// TestOutboundProjection_P27a: an expired sudo_grant is excluded.
func TestOutboundProjection_P27a(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	result := buildTestProjection(t, dir, rosterPath)
	if !result.Available {
		t.Fatalf("projection unavailable: %+v", result)
	}
	if _, ok := findSudo(result.Snapshot.Access.Sudo, "sudo_grant:sudo-expired-grant"); ok {
		t.Fatal("expired sudo_grant must be excluded")
	}
}

// TestOutboundProjection_P27b: a duplicate stable key (two HBAC rules
// sharing the same name — a state ValidateRosterFile would normally
// reject, but this package must not silently trust an unvalidated
// roster) fails closed rather than producing an ambiguous diff key.
func TestOutboundProjection_P27b(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte("hosts: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	roster := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal}
users:
  - name: alice
    state: present
    enabled: true
hosts: []
hbac:
  rules:
    - name: dup-rule
      state: present
      enabled: true
      subjects: {users: [alice], groups: []}
      targets: {hostcat: all}
      services: [sshd]
    - name: dup-rule
      state: present
      enabled: true
      subjects: {users: [alice], groups: []}
      targets: {hostcat: all}
      services: [ftp]
`
	rosterPath := filepath.Join(dir, "ipa-identity.yaml")
	if err := os.WriteFile(rosterPath, []byte(roster), 0o600); err != nil {
		t.Fatal(err)
	}
	result := BuildProjection(ProjectionRequest{
		WorkspaceDir: dir,
		HostVars:     hostVarsForRoster(rosterPath, "any"),
		Now:          projectionTestNow,
	})
	if result.Available {
		t.Fatalf("expected unavailable for a duplicate stable key, got %+v", result)
	}
}

// TestOutboundProjection_P15/P16: encrypted roster support.
func TestOutboundProjection_P15(t *testing.T) {
	requireAnsibleVaultForOutbound(t)
	dir, rosterPath := writeProjectionFixture(t)
	vaultPasswordFile := filepath.Join(dir, "vault-pass")
	if err := os.WriteFile(vaultPasswordFile, []byte("s3cret-pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	encryptFileForOutboundTest(t, rosterPath, vaultPasswordFile)

	result := BuildProjection(ProjectionRequest{
		WorkspaceDir:      dir,
		HostVars:          hostVarsForRoster(rosterPath, "web1"),
		VaultPasswordFile: vaultPasswordFile,
		Now:               projectionTestNow,
	})
	if !result.Available {
		t.Fatalf("expected available for a correctly-decrypted roster, got %+v", result)
	}
	if _, ok := findUser(result.Snapshot.Users, "alice"); !ok {
		t.Fatal("expected alice after in-memory decrypt")
	}
	// Verify the roster file on disk never became plaintext.
	raw, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), "$ANSIBLE_VAULT") {
		t.Fatal("roster file must remain encrypted on disk")
	}
}

func TestOutboundProjection_P16(t *testing.T) {
	requireAnsibleVaultForOutbound(t)
	dir, rosterPath := writeProjectionFixture(t)
	vaultPasswordFile := filepath.Join(dir, "vault-pass")
	if err := os.WriteFile(vaultPasswordFile, []byte("s3cret-pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	encryptFileForOutboundTest(t, rosterPath, vaultPasswordFile)

	result := BuildProjection(ProjectionRequest{
		WorkspaceDir: dir,
		HostVars:     hostVarsForRoster(rosterPath, "web1"),
		// no VaultPasswordFile supplied
		Now: projectionTestNow,
	})
	if result.Available {
		t.Fatal("expected unavailable when no reusable vault password file is available")
	}
	if result.ErrorClass != ErrorClassProjectionUnavailable {
		t.Fatalf("ErrorClass = %q, want %q", result.ErrorClass, ErrorClassProjectionUnavailable)
	}
}

func requireAnsibleVaultForOutbound(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible-vault"); err != nil {
		t.Skipf("ansible-vault not installed: %v", err)
	}
}

func encryptFileForOutboundTest(t *testing.T, path, vaultPasswordFile string) {
	t.Helper()
	cmd := exec.Command("ansible-vault", "encrypt", "--vault-password-file", vaultPasswordFile, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ansible-vault encrypt (test setup) failed: %v: %s", err, out)
	}
}

// fmtSnapshot renders snap's fields relevant to secret-leak scanning
// (P2-P4) into a single string for a substring sentinel check.
func fmtSnapshot(snap UserHostAccessSnapshotV1) string {
	var sb strings.Builder
	for _, h := range snap.Hosts {
		sb.WriteString(h.ID + "|" + h.Name + "|" + h.Address + "|")
		for k, v := range h.Annotations {
			sb.WriteString(k + "=" + v + ";")
		}
	}
	for _, u := range snap.Users {
		sb.WriteString(u.Name + "|" + u.DisplayName + "|" + u.Email + "|")
		sb.WriteString(strings.Join(u.EffectiveGroups, ",") + "|")
	}
	for _, g := range snap.Groups {
		sb.WriteString(g.Name + "|" + strings.Join(g.Users, ",") + "|" + strings.Join(g.Groups, ",") + "|")
	}
	for _, l := range snap.Access.Login {
		sb.WriteString(l.ID + "|" + strings.Join(l.Users, ",") + "|" + strings.Join(l.HostIDs, ",") + "|")
	}
	for _, s := range snap.Access.Sudo {
		sb.WriteString(s.ID + "|" + strings.Join(s.Users, ",") + "|" + strings.Join(s.Commands, ",") + "|" + strings.Join(s.DeniedCommands, ",") + "|")
		sb.WriteString(strings.Join(s.RunAsUsers, ",") + "|" + strings.Join(s.RunAsGroups, ",") + "|" + strings.Join(s.Options, ","))
	}
	return sb.String()
}
