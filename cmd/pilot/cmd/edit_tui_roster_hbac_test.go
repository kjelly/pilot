package cmd

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/inventory"
)

// writeHBACPolicyRosterFixture is the shared fixture for spec.md §11's HBAC
// authorization simplification: one group of each policy-relevant category
// (team/filesystem/role/legacy access), two hostgroups (so hostgroup edits
// have a real effect to prove), and one HBAC rule that already mixes every
// relationship dimension — direct users + subject groups, direct hosts +
// hostgroups — so sibling-preservation regressions are visible immediately.
func writeHBACPolicyRosterFixture(t *testing.T) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "roster.yaml")
	fixture := `schema_version: 1
freeipa: {domain: ipa.pilot.internal}
users:
  - {name: alice, state: present}
  - {name: bob, state: present}
groups:
  - {name: team-x, state: present, category: team}
  - {name: data-fs, state: present, category: filesystem}
  - {name: role-y, state: present, category: role}
  - {name: access-z, state: present, category: access}
hostgroups:
  - {name: hg1, state: present, membership: {hosts: [h1.ipa.pilot.internal]}}
  - {name: hg2, state: present, membership: {hosts: [h2.ipa.pilot.internal]}}
hbac:
  disable_allow_all: false
  rules:
    - name: r1
      state: present
      enabled: true
      subjects: {users: [bob], groups: [team-x]}
      targets: {hosts: [extra.ipa.pilot.internal], hostgroups: [hg1]}
      services: [sshd]
`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := inventory.ValidateRosterFile(path); err != nil || len(v) != 0 {
		t.Fatalf("fixture must validate clean, got err=%v violations=%v", err, v)
	}
	return dir, path
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// TestRosterGroupCategories_MatchIsCreatableGroupCategory is the "test
// proving synchronization" spec.md §6.3/§21.1 requires between the TUI's
// hand-maintained new-group category list and inventory's canonical
// IsCreatableGroupCategory policy — it must offer every creatable category
// exactly once, and never the deprecated "access" category.
func TestRosterGroupCategories_MatchIsCreatableGroupCategory(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range rosterGroupCategories {
		if !inventory.IsCreatableGroupCategory(c.Category) {
			t.Errorf("rosterGroupCategories offers non-creatable category %q", c.Category)
		}
		if seen[c.Category] {
			t.Errorf("rosterGroupCategories lists %q more than once", c.Category)
		}
		seen[c.Category] = true
	}
	for _, category := range []string{"team", "filesystem", "role"} {
		if !seen[category] {
			t.Errorf("rosterGroupCategories is missing creatable category %q", category)
		}
	}
	if seen["access"] {
		t.Error("rosterGroupCategories must not offer the deprecated access category")
	}
}

func TestPushRosterAddGroupCategory_ExcludesAccess(t *testing.T) {
	dir, path := writeHBACPolicyRosterFixture(t)
	var router editRouterModel
	pushRosterAddGroupCategory(&router, dir, path)
	view := viewContent(router.View())
	if strings.Contains(view, "access-*") {
		t.Fatalf("new-group category screen must not offer access, got:\n%s", view)
	}
	for _, want := range []string{"team-*", "data-*", "role-*"} {
		if !strings.Contains(view, want) {
			t.Fatalf("new-group category screen missing %q:\n%s", want, view)
		}
	}
}

func TestHBACSubjectGroupChoices_IncludesTeamRoleAccessExcludesFilesystem(t *testing.T) {
	_, path := writeHBACPolicyRosterFixture(t)
	choices, err := hbacSubjectGroupChoices(path)
	if err != nil {
		t.Fatalf("hbacSubjectGroupChoices() error = %v", err)
	}
	byID := map[string]string{}
	for _, c := range choices {
		byID[c.ID] = c.Label
	}
	if _, ok := byID["team-x"]; !ok {
		t.Error("expected team-x in HBAC subject group choices")
	}
	if _, ok := byID["role-y"]; !ok {
		t.Error("expected role-y in HBAC subject group choices")
	}
	if _, ok := byID["data-fs"]; ok {
		t.Error("data-fs (filesystem) must never be an HBAC subject group choice")
	}
	label, ok := byID["access-z"]
	if !ok {
		t.Fatal("expected legacy access-z in HBAC subject group choices")
	}
	if !strings.Contains(label, "[legacy access]") {
		t.Errorf("legacy access group label = %q, want a [legacy access] marker", label)
	}
	if byID["team-x"] != "team-x" || byID["role-y"] != "role-y" {
		t.Errorf("non-legacy group labels must equal their stable ID, got team-x=%q role-y=%q", byID["team-x"], byID["role-y"])
	}
}

func TestHBACSubjectUserChoices_IncludesAdminAndRosterUsersNoDuplicateAdmin(t *testing.T) {
	_, path := writeHBACPolicyRosterFixture(t)
	users, err := hbacSubjectUserChoices(path)
	if err != nil {
		t.Fatalf("hbacSubjectUserChoices() error = %v", err)
	}
	if got := sortedCopy(users); strings.Join(got, ",") != "admin,alice,bob" {
		t.Fatalf("hbacSubjectUserChoices() = %v, want [admin alice bob]", users)
	}
	count := 0
	for _, u := range users {
		if u == "admin" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("admin appears %d times, want exactly once", count)
	}
}

func TestValidateDirectHostsInput(t *testing.T) {
	if err := validateDirectHostsInput(""); err != nil {
		t.Errorf("empty input must be valid (direct hosts are optional), got %v", err)
	}
	if err := validateDirectHostsInput("a.ipa.pilot.internal, b.ipa.pilot.internal"); err != nil {
		t.Errorf("valid FQDN list must pass, got %v", err)
	}
	if err := validateDirectHostsInput("not-an-fqdn"); err == nil {
		t.Error("non-FQDN-shaped entry must fail validation")
	}
}

func TestNormalizeDirectHosts_TrimsDedupesSorts(t *testing.T) {
	got := normalizeDirectHosts(" b.ipa.pilot.internal ,a.ipa.pilot.internal, a.ipa.pilot.internal,,")
	want := []string{"a.ipa.pilot.internal", "b.ipa.pilot.internal"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("normalizeDirectHosts() = %v, want %v", got, want)
	}
}

// TestPushRosterHBACGroups_EditingGroupsPreservesUsers is half of spec.md
// §11.5's mandatory sibling-preservation invariant.
func TestPushRosterHBACGroups_EditingGroupsPreservesUsers(t *testing.T) {
	dir, path := writeHBACPolicyRosterFixture(t)
	var router editRouterModel
	pushRosterHBACGroups(&router, dir, path, "r1")
	// Choices are team-x (checked), role-y, access-z in that order; move
	// down once to role-y and check it too, keeping team-x checked.
	next, _ := router.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	router = next.(editRouterModel)
	next, _ = router.Update(tea.KeyPressMsg{Code: tea.KeySpace})
	router = next.(editRouterModel)
	next, _ = router.Update(tea.KeyPressMsg{Code: '\n', Text: "\n"})
	router = next.(editRouterModel)

	rule, found, err := inventory.RosterHBACRule(path, "r1")
	if err != nil || !found {
		t.Fatalf("read updated HBAC rule: found=%t err=%v", found, err)
	}
	sub := rosterSubmap(rule, "subjects")
	if got := sortedCopy(rosterStringSlice(sub, "groups")); strings.Join(got, ",") != "role-y,team-x" {
		t.Fatalf("subjects.groups = %v, want [role-y team-x]", got)
	}
	if got := rosterStringSlice(sub, "users"); len(got) != 1 || got[0] != "bob" {
		t.Fatalf("editing subjects.groups must preserve subjects.users, got %v", got)
	}
}

// TestPushRosterHBACUsers_EditingUsersPreservesGroups is the other half.
func TestPushRosterHBACUsers_EditingUsersPreservesGroups(t *testing.T) {
	dir, path := writeHBACPolicyRosterFixture(t)
	var router editRouterModel
	pushRosterHBACUsers(&router, dir, path, "r1")
	// Choices are admin, alice, bob (checked) — the widget focuses the
	// already-checked item (bob, last) on open, so move up to alice and
	// check it too, keeping bob checked.
	next, _ := router.Update(tea.KeyPressMsg{Code: tea.KeyUp})
	router = next.(editRouterModel)
	next, _ = router.Update(tea.KeyPressMsg{Code: tea.KeySpace})
	router = next.(editRouterModel)
	next, _ = router.Update(tea.KeyPressMsg{Code: '\n', Text: "\n"})
	router = next.(editRouterModel)

	rule, found, err := inventory.RosterHBACRule(path, "r1")
	if err != nil || !found {
		t.Fatalf("read updated HBAC rule: found=%t err=%v", found, err)
	}
	sub := rosterSubmap(rule, "subjects")
	if got := sortedCopy(rosterStringSlice(sub, "users")); strings.Join(got, ",") != "alice,bob" {
		t.Fatalf("subjects.users = %v, want [alice bob]", got)
	}
	if got := rosterStringSlice(sub, "groups"); len(got) != 1 || got[0] != "team-x" {
		t.Fatalf("editing subjects.users must preserve subjects.groups, got %v", got)
	}
}

// TestPushRosterHBACTargets_EditingHostgroupsPreservesDirectHosts locks the
// spec.md §3.3/§11.5 data-loss bug fix: this screen used to hard-reset
// targets.hosts to [] on every save.
func TestPushRosterHBACTargets_EditingHostgroupsPreservesDirectHosts(t *testing.T) {
	dir, path := writeHBACPolicyRosterFixture(t)
	var router editRouterModel
	pushRosterHBACTargets(&router, dir, path, "r1")
	// Choices are hg1 (checked), hg2. Add hg2, keeping hg1 checked.
	next, _ := router.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	router = next.(editRouterModel)
	next, _ = router.Update(tea.KeyPressMsg{Code: tea.KeySpace})
	router = next.(editRouterModel)
	next, _ = router.Update(tea.KeyPressMsg{Code: '\n', Text: "\n"})
	router = next.(editRouterModel)

	rule, found, err := inventory.RosterHBACRule(path, "r1")
	if err != nil || !found {
		t.Fatalf("read updated HBAC rule: found=%t err=%v", found, err)
	}
	tar := rosterSubmap(rule, "targets")
	if got := sortedCopy(rosterStringSlice(tar, "hostgroups")); strings.Join(got, ",") != "hg1,hg2" {
		t.Fatalf("targets.hostgroups = %v, want [hg1 hg2]", got)
	}
	if got := rosterStringSlice(tar, "hosts"); len(got) != 1 || got[0] != "extra.ipa.pilot.internal" {
		t.Fatalf("editing targets.hostgroups must preserve targets.hosts, got %v (this is the spec.md §3.3 data-loss bug if empty)", got)
	}
}

// TestPushRosterHBACHosts_EditingHostsPreservesHostgroups is targets.hosts's
// side of the same §11.5 invariant, driven through the automationDriver's
// typeText/enter helpers (a full clear-then-retype, exactly like real
// automation replay) rather than raw keys, since Huh input cursor
// positioning over a prefilled default is an implementation detail this
// test shouldn't depend on.
func TestPushRosterHBACHosts_EditingHostsPreservesHostgroups(t *testing.T) {
	dir, path := writeHBACPolicyRosterFixture(t)
	var router editRouterModel
	pushRosterHBACHosts(&router, dir, path, "r1")

	d := automationDriver{}
	if err := d.typeText(&router, "extra.ipa.pilot.internal, second.ipa.pilot.internal", true); err != nil {
		t.Fatalf("typeText() error = %v", err)
	}
	if err := d.enter(&router); err != nil {
		t.Fatalf("enter() error = %v", err)
	}

	rule, found, err := inventory.RosterHBACRule(path, "r1")
	if err != nil || !found {
		t.Fatalf("read updated HBAC rule: found=%t err=%v", found, err)
	}
	tar := rosterSubmap(rule, "targets")
	if got := sortedCopy(rosterStringSlice(tar, "hosts")); strings.Join(got, ",") != "extra.ipa.pilot.internal,second.ipa.pilot.internal" {
		t.Fatalf("targets.hosts = %v, want [extra.ipa.pilot.internal second.ipa.pilot.internal]", got)
	}
	if got := rosterStringSlice(tar, "hostgroups"); len(got) != 1 || got[0] != "hg1" {
		t.Fatalf("editing targets.hosts must preserve targets.hostgroups, got %v", got)
	}
}

// TestPushRosterGroupDetail_AccessGroupRemainsEditableWithDeprecationNote
// covers spec.md §10: an existing access group stays visible, its category
// stays read-only, and the detail screen shows a presentation-only
// deprecation note without changing the underlying data.
func TestPushRosterGroupDetail_AccessGroupRemainsEditableWithDeprecationNote(t *testing.T) {
	dir, path := writeHBACPolicyRosterFixture(t)
	var router editRouterModel
	pushRosterGroupDetail(&router, dir, path, "access-z", "")
	view := viewContent(router.View())
	if !strings.Contains(view, "legacy") {
		t.Fatalf("access group detail screen must show a legacy deprecation note, got:\n%s", view)
	}

	// The category field (index 2) must stay read-only.
	next, _ := router.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	router = next.(editRouterModel)
	next, _ = router.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	router = next.(editRouterModel)
	next, _ = router.Update(tea.KeyPressMsg{Code: '\n', Text: "\n"})
	router = next.(editRouterModel)
	if !strings.Contains(viewContent(router.View()), "不可修改") {
		t.Fatalf("category field must remain read-only, got:\n%s", viewContent(router.View()))
	}

	g, found, err := inventory.RosterGroup(path, "access-z")
	if err != nil || !found {
		t.Fatalf("read access-z: found=%t err=%v", found, err)
	}
	if got := rosterStringOr(g, "category", ""); got != "access" {
		t.Fatalf("access-z category = %q, must remain access (unchanged)", got)
	}
}
