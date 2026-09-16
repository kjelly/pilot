package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

const externalProjectionTestRoster = `
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
  - name: bob
    state: disabled
    enabled: false
  - name: carol
    state: absent
    enabled: true
groups:
  - name: team-x
    state: present
    category: team
    membership: {authoritative: true, users: [alice], groups: []}
  - name: team-x-nested
    state: present
    category: team
    membership: {authoritative: true, users: [], groups: [team-x]}
hostgroups:
  - name: web-hosts
    state: present
    membership: {authoritative: true, hosts: [web1.ipa.pilot.internal], hostgroups: [web-hosts-nested]}
  - name: web-hosts-nested
    state: present
    membership: {authoritative: true, hosts: [web2.ipa.pilot.internal], hostgroups: []}
hosts:
  - name: web1.ipa.pilot.internal
    state: present
    ip_address: 10.0.0.1
  - name: web2.ipa.pilot.internal
    state: present
    ip_address: 10.0.0.2
  - name: removed.ipa.pilot.internal
    state: absent
    ip_address: 10.0.0.9
hbac:
  rules:
    - name: rule-active
      state: present
      enabled: true
      subjects: {users: [alice, bob], groups: []}
      targets: {hosts: [], hostgroups: [web-hosts]}
      services: [sshd]
    - name: rule-disabled
      state: present
      enabled: false
      subjects: {users: [alice], groups: []}
      targets: {hostcat: all}
      services: [sshd]
sudo:
  command_groups:
    - name: restart-nginx
      commands: ["/usr/bin/systemctl restart nginx"]
    - name: view-logs
      commands: ["/usr/bin/journalctl -u nginx"]
  rules:
    - name: sudo-ops
      state: present
      subjects: {users: [alice], groups: []}
      targets: {hostcat: all}
      allow: {command_groups: [restart-nginx], commands: []}
      deny: {command_groups: [view-logs], commands: ["/usr/bin/rm"]}
      run_as: {users: [root], groups: [wheel]}
      options: ["!authenticate"]
grants:
  - name: vendor-temp
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
  - name: vendor-sudo
    kind: sudo_grant
    state: present
    subjects: {users: [alice], groups: []}
    targets: {hostcat: all}
    privilege: {commands: [/usr/bin/systemctl], command_groups: []}
    run_as: {users: [root], groups: []}
    options: []
    validity: {not_after: "2100-01-01T00:00:00Z"}
  - name: bg-emergency
    kind: breakglass
    subjects: {users: [alice], groups: []}
    targets: {hostcat: all}
    services: [sshd]
`

func writeExternalProjectionTestRoster(t *testing.T) map[string]any {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ipa-identity.yaml")
	if err := os.WriteFile(path, []byte(externalProjectionTestRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := readRosterAsMap(path)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

var testNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestExternalUsers_PresentDisabledIncludedAbsentOmitted(t *testing.T) {
	root := writeExternalProjectionTestRoster(t)
	users, err := ExternalUsers(root, testNow)
	if err != nil {
		t.Fatalf("ExternalUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("ExternalUsers() = %+v, want exactly 2 (alice, bob — carol is absent)", users)
	}
	byName := map[string]ExternalUser{}
	for _, u := range users {
		byName[u.Name] = u
	}
	alice, ok := byName["alice"]
	if !ok || !alice.Enabled {
		t.Fatalf("alice = %+v, want present and enabled", alice)
	}
	if want := []string{"team-x", "team-x-nested"}; !reflect.DeepEqual(alice.EffectiveGroups, want) {
		t.Fatalf("alice.EffectiveGroups = %v, want %v (transitive nested group membership)", alice.EffectiveGroups, want)
	}
	bob, ok := byName["bob"]
	if !ok || bob.Enabled {
		t.Fatalf("bob = %+v, want present but disabled", bob)
	}
}

func TestExternalGroups_OnlyDirectMembership(t *testing.T) {
	root := writeExternalProjectionTestRoster(t)
	groups := ExternalGroups(root)
	byName := map[string]ExternalGroup{}
	for _, g := range groups {
		byName[g.Name] = g
	}
	nested, ok := byName["team-x-nested"]
	if !ok {
		t.Fatal("expected team-x-nested")
	}
	if len(nested.Users) != 0 || !reflect.DeepEqual(nested.Groups, []string{"team-x"}) {
		t.Fatalf("team-x-nested = %+v, want direct membership only (Groups=[team-x], no Users)", nested)
	}
}

func TestExternalHostgroups_EffectiveHostIDsTransitive(t *testing.T) {
	root := writeExternalProjectionTestRoster(t)
	hostgroups := ExternalHostgroups(root)
	byName := map[string]ExternalHostgroup{}
	for _, hg := range hostgroups {
		byName[hg.Name] = hg
	}
	web, ok := byName["web-hosts"]
	if !ok {
		t.Fatal("expected web-hosts")
	}
	want := []string{"web1.ipa.pilot.internal", "web2.ipa.pilot.internal"}
	if !reflect.DeepEqual(web.EffectiveHostIDs, want) {
		t.Fatalf("web-hosts.EffectiveHostIDs = %v, want %v", web.EffectiveHostIDs, want)
	}
	if !reflect.DeepEqual(web.HostIDs, []string{"web1.ipa.pilot.internal"}) {
		t.Fatalf("web-hosts.HostIDs (direct only) = %v, want [web1.ipa.pilot.internal]", web.HostIDs)
	}
}

func TestExternalRosterHosts_AbsentOmitted(t *testing.T) {
	root := writeExternalProjectionTestRoster(t)
	hosts := ExternalRosterHosts(root)
	if len(hosts) != 2 {
		t.Fatalf("ExternalRosterHosts() = %+v, want exactly 2 (removed.ipa.pilot.internal is absent)", hosts)
	}
}

func TestExternalEffectiveAccess_DisabledHBACOmitted(t *testing.T) {
	root := writeExternalProjectionTestRoster(t)
	login, _, err := ExternalEffectiveAccess(root, testNow, nil)
	if err != nil {
		t.Fatalf("ExternalEffectiveAccess: %v", err)
	}
	for _, l := range login {
		if l.Rule == "rule-disabled" {
			t.Fatalf("disabled HBAC rule must be omitted, got %+v", l)
		}
	}
}

func TestExternalEffectiveAccess_UserIntersectionDropsDisabledUser(t *testing.T) {
	root := writeExternalProjectionTestRoster(t)
	login, _, err := ExternalEffectiveAccess(root, testNow, nil)
	if err != nil {
		t.Fatalf("ExternalEffectiveAccess: %v", err)
	}
	var ruleActive *ExternalLoginAccess
	for i := range login {
		if login[i].Rule == "rule-active" {
			ruleActive = &login[i]
		}
	}
	if ruleActive == nil {
		t.Fatal("expected rule-active in login access")
	}
	if want := []string{"alice"}; !reflect.DeepEqual(ruleActive.Users, want) {
		t.Fatalf("rule-active.Users = %v, want %v (bob is disabled and must be excluded)", ruleActive.Users, want)
	}
}

func TestExternalEffectiveAccess_OnlyActiveGrantsIncluded(t *testing.T) {
	root := writeExternalProjectionTestRoster(t)
	login, _, err := ExternalEffectiveAccess(root, testNow, nil)
	if err != nil {
		t.Fatalf("ExternalEffectiveAccess: %v", err)
	}
	var names []string
	for _, l := range login {
		if l.Source == "temporary_grant" {
			names = append(names, l.Rule)
		}
	}
	sort.Strings(names)
	if want := []string{"vendor-temp"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("active temporary_grant rules = %v, want %v (vendor-expired must be omitted)", names, want)
	}
}

func TestExternalEffectiveAccess_SudoGrantActive(t *testing.T) {
	root := writeExternalProjectionTestRoster(t)
	_, sudo, err := ExternalEffectiveAccess(root, testNow, nil)
	if err != nil {
		t.Fatalf("ExternalEffectiveAccess: %v", err)
	}
	var grant *ExternalSudoAccess
	for i := range sudo {
		if sudo[i].Rule == "vendor-sudo" {
			grant = &sudo[i]
		}
	}
	if grant == nil {
		t.Fatalf("expected active sudo_grant vendor-sudo in %+v", sudo)
	}
	if grant.ValidNotAfter == nil || grant.ValidNotAfter.Year() != 2100 {
		t.Fatalf("vendor-sudo.ValidNotAfter = %v, want 2100", grant.ValidNotAfter)
	}
}

func TestExternalEffectiveAccess_StaticSudoDenyAndRunAsResolved(t *testing.T) {
	root := writeExternalProjectionTestRoster(t)
	_, sudo, err := ExternalEffectiveAccess(root, testNow, nil)
	if err != nil {
		t.Fatalf("ExternalEffectiveAccess: %v", err)
	}
	var opsRule *ExternalSudoAccess
	for i := range sudo {
		if sudo[i].Rule == "sudo-ops" {
			opsRule = &sudo[i]
		}
	}
	if opsRule == nil {
		t.Fatalf("expected sudo-ops in %+v", sudo)
	}
	wantDenied := []string{"/usr/bin/journalctl -u nginx", "/usr/bin/rm"}
	if !reflect.DeepEqual(opsRule.DeniedCommands, wantDenied) {
		t.Fatalf("sudo-ops.DeniedCommands = %v, want %v (direct deny.commands union deny.command_groups)", opsRule.DeniedCommands, wantDenied)
	}
	if !reflect.DeepEqual(opsRule.RunAsUsers, []string{"root"}) || !reflect.DeepEqual(opsRule.RunAsGroups, []string{"wheel"}) {
		t.Fatalf("sudo-ops run_as = users=%v groups=%v, want users=[root] groups=[wheel]", opsRule.RunAsUsers, opsRule.RunAsGroups)
	}
	if !reflect.DeepEqual(opsRule.Options, []string{"!authenticate"}) {
		t.Fatalf("sudo-ops.Options = %v, want [!authenticate]", opsRule.Options)
	}
}

func TestExternalEffectiveAccess_BreakglassCollapsesDuplicatesToMaxExpiry(t *testing.T) {
	root := writeExternalProjectionTestRoster(t)
	earlier := testNow.Add(1 * time.Hour)
	later := testNow.Add(5 * time.Hour)
	login, _, err := ExternalEffectiveAccess(root, testNow, []BreakglassActivationInput{
		{Name: "bg-emergency", ExpiresAt: earlier},
		{Name: "bg-emergency", ExpiresAt: later},
	})
	if err != nil {
		t.Fatalf("ExternalEffectiveAccess: %v", err)
	}
	var matches []ExternalLoginAccess
	for _, l := range login {
		if l.Source == "breakglass" {
			matches = append(matches, l)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("breakglass entities = %+v, want exactly 1 (duplicates collapsed)", matches)
	}
	if matches[0].ValidUntil == nil || !matches[0].ValidUntil.Equal(later.UTC()) {
		t.Fatalf("breakglass ValidUntil = %v, want max expiry %v", matches[0].ValidUntil, later.UTC())
	}
}

func TestExternalEffectiveAccess_BreakglassAbsentGrantDefinitionOmitted(t *testing.T) {
	root := writeExternalProjectionTestRoster(t)
	login, _, err := ExternalEffectiveAccess(root, testNow, []BreakglassActivationInput{
		{Name: "no-such-grant", ExpiresAt: testNow.Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("ExternalEffectiveAccess: %v", err)
	}
	for _, l := range login {
		if l.Source == "breakglass" {
			t.Fatalf("expected no breakglass entity for a definition absent from the roster, got %+v", l)
		}
	}
}
