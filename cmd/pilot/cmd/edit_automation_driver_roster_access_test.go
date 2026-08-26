package cmd

import (
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
)

func TestEditAutomationDriverRosterAccessFlow_HostgroupAndHBAC(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_group", Name: "team-web", Category: "team"},
			{Action: "create_hostgroup", Name: "webhosts"},
			{Action: "set_hostgroup_field", Name: "webhosts", Field: "description", Value: "web tier"},
			{Action: "set_hostgroup_field", Name: "webhosts", Field: "membership.hosts", Value: "web1.ipa.pilot.internal, web2.ipa.pilot.internal"},
			{Action: "create_hbac_rule", Name: "web-login", Groups: []string{"team-web"}, Hostgroups: []string{"webhosts"}, Services: []string{"sshd"}},
			{Action: "set_hbac_services", Name: "web-login", Services: []string{"sshd", "sudo"}},
			{Action: "set_hbac_disable_allow_all", Value: "true"},
			{Action: "set_hbac_disable_allow_all", Value: "true"}, // idempotent: already true, must not toggle back
		},
	}

	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	for _, event := range events {
		if event.Result != "ok" {
			t.Fatalf("bad trace event: %+v", event)
		}
	}

	hg, found, err := inventory.RosterHostgroup(path, "webhosts")
	if err != nil {
		t.Fatalf("RosterHostgroup() error = %v", err)
	}
	if !found {
		t.Fatal("expected hostgroup webhosts to exist")
	}
	if hg["description"] != "web tier" {
		t.Fatalf("description = %v, want web tier", hg["description"])
	}
	mem, _ := hg["membership"].(map[string]any)
	hosts, _ := mem["hosts"].([]any)
	if len(hosts) != 2 {
		t.Fatalf("membership.hosts = %+v, want 2 entries", hosts)
	}

	rule, found, err := inventory.RosterHBACRule(path, "web-login")
	if err != nil {
		t.Fatalf("RosterHBACRule() error = %v", err)
	}
	if !found {
		t.Fatal("expected HBAC rule web-login to exist")
	}
	subjects, _ := rule["subjects"].(map[string]any)
	groups, _ := subjects["groups"].([]any)
	if len(groups) != 1 || groups[0] != "team-web" {
		t.Fatalf("subjects.groups = %+v, want [team-web]", groups)
	}
	targets, _ := rule["targets"].(map[string]any)
	hostgroups, _ := targets["hostgroups"].([]any)
	if len(hostgroups) != 1 || hostgroups[0] != "webhosts" {
		t.Fatalf("targets.hostgroups = %+v, want [webhosts]", hostgroups)
	}
	services, _ := rule["services"].([]any)
	if len(services) != 2 {
		t.Fatalf("services = %+v, want 2 entries", services)
	}

	disabled, err := inventory.RosterHBACDisableAllowAll(path)
	if err != nil {
		t.Fatalf("RosterHBACDisableAllowAll() error = %v", err)
	}
	if !disabled {
		t.Fatal("expected hbac.disable_allow_all = true")
	}
}

// TestEditAutomationDriverRosterAccessFlow_HostgroupNestedMembership covers
// the roster-schema-v2 migration spec's §8 requirement: hostgroup nested
// membership (membership.hostgroups) is now a real, editable, reconciled
// field, not just something freeipa-identity-apply.yml silently ignored.
func TestEditAutomationDriverRosterAccessFlow_HostgroupNestedMembership(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_hostgroup", Name: "hg-child"},
			{Action: "create_hostgroup", Name: "hg-parent"},
			{Action: "set_hostgroup_hostgroups", Name: "hg-parent", Hostgroups: []string{"hg-child"}},
		},
	}

	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	for _, event := range events {
		if event.Result != "ok" {
			t.Fatalf("bad trace event: %+v", event)
		}
	}

	hg, found, err := inventory.RosterHostgroup(path, "hg-parent")
	if err != nil {
		t.Fatalf("RosterHostgroup() error = %v", err)
	}
	if !found {
		t.Fatal("expected hostgroup hg-parent to exist")
	}
	mem, _ := hg["membership"].(map[string]any)
	hostgroups, _ := mem["hostgroups"].([]any)
	if len(hostgroups) != 1 || hostgroups[0] != "hg-child" {
		t.Fatalf("membership.hostgroups = %+v, want [hg-child]", hostgroups)
	}
}

// TestPushRosterHostgroupHostgroups_ExcludesSelfFromChoices proves the
// picker never offers a hostgroup as its own nested member — there's no
// roster/Ansible validation gate rejecting a direct self-reference here
// (unlike netgroups), so the UI is the only thing preventing it.
func TestPushRosterHostgroupHostgroups_ExcludesSelfFromChoices(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)
	if err := inventory.AppendRosterHostgroup(path, "hg-a"); err != nil {
		t.Fatal(err)
	}
	if err := inventory.AppendRosterHostgroup(path, "hg-b"); err != nil {
		t.Fatal(err)
	}

	var router editRouterModel
	pushRosterHostgroupHostgroups(&router, dir, path, "hg-a", nil)

	// Inspected through the typed-interface / AutomationState contract
	// rather than a concrete type assertion: checklist() now builds its
	// screen through r.uiFactory() (Huh-backed in production), so the
	// concrete type is deliberately no longer this package's
	// multiSelectModel. The offered choices themselves are unchanged.
	list, ok := router.current.(tui.MultiSelectScreen)
	if !ok {
		t.Fatalf("router.current = %T, want tui.MultiSelectScreen", router.current)
	}
	items := list.AutomationState().Items
	for _, item := range items {
		if item.Label == "hg-a" {
			t.Fatalf("choices included hg-a itself: %+v", items)
		}
	}
	if len(items) != 1 || items[0].Label != "hg-b" {
		t.Fatalf("choices = %+v, want just [hg-b]", items)
	}
}

func TestEditAutomationDriverRosterAccessFlow_SudoCommandGroupsAndRules(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_group", Name: "role-web", Category: "role"},
			{Action: "create_sudo_command_group", Name: "web-restart", Value: "systemctl restart nginx, systemctl restart php-fpm"},
			{Action: "create_sudo_rule", Name: "web-sudo", Groups: []string{"role-web"}, CommandGroups: []string{"web-restart"}},
			{Action: "set_sudo_rule_commands", Name: "web-sudo", Value: "systemctl status nginx"},
		},
	}

	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	for _, event := range events {
		if event.Result != "ok" {
			t.Fatalf("bad trace event: %+v", event)
		}
	}

	cg, found, err := inventory.RosterSudoCommandGroup(path, "web-restart")
	if err != nil {
		t.Fatalf("RosterSudoCommandGroup() error = %v", err)
	}
	if !found {
		t.Fatal("expected sudo command group web-restart to exist")
	}
	commands, _ := cg["commands"].([]any)
	if len(commands) != 2 {
		t.Fatalf("commands = %+v, want 2 entries", commands)
	}

	rule, found, err := inventory.RosterSudoRule(path, "web-sudo")
	if err != nil {
		t.Fatalf("RosterSudoRule() error = %v", err)
	}
	if !found {
		t.Fatal("expected sudo rule web-sudo to exist")
	}
	subjects, _ := rule["subjects"].(map[string]any)
	groups, _ := subjects["groups"].([]any)
	if len(groups) != 1 || groups[0] != "role-web" {
		t.Fatalf("subjects.groups = %+v, want [role-web]", groups)
	}
	allow, _ := rule["allow"].(map[string]any)
	commandGroups, _ := allow["command_groups"].([]any)
	if len(commandGroups) != 1 || commandGroups[0] != "web-restart" {
		t.Fatalf("allow.command_groups = %+v, want [web-restart]", commandGroups)
	}
	allowCommands, _ := allow["commands"].([]any)
	if len(allowCommands) != 1 || allowCommands[0] != "systemctl status nginx" {
		t.Fatalf("allow.commands = %+v, want [systemctl status nginx]", allowCommands)
	}
	if allow["command_category"] != nil {
		t.Fatalf("allow.command_category = %v, want unset (restricted mode from creation)", allow["command_category"])
	}
}

func TestEditAutomationDriverRosterAccessFlow_SetSudoRuleAllowModeAll(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_group", Name: "role-web", Category: "role"},
			{Action: "create_sudo_command_group", Name: "web-restart", Value: "systemctl restart nginx"},
			{Action: "create_sudo_rule", Name: "web-sudo", Groups: []string{"role-web"}, CommandGroups: []string{"web-restart"}},
			{Action: "set_sudo_rule_allow_mode", Name: "web-sudo", Value: "all"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	rule, _, err := inventory.RosterSudoRule(path, "web-sudo")
	if err != nil {
		t.Fatalf("RosterSudoRule() error = %v", err)
	}
	allow, _ := rule["allow"].(map[string]any)
	if allow["command_category"] != "all" {
		t.Fatalf("allow.command_category = %v, want all", allow["command_category"])
	}
}

func TestEditAutomationDriverRosterAccessFlow_ValidationRejectsBadInput(t *testing.T) {
	if err := validateEntityNameOnly("create_hostgroup")(editAction{Action: "create_hostgroup"}); err == nil {
		t.Fatal("expected create_hostgroup validation to reject an empty name")
	}
	if err := validateHostgroupField(editAction{Action: "set_hostgroup_field", Name: "x", Field: "not_a_field", Value: "y"}); err == nil {
		t.Fatal("expected validateHostgroupField to reject an unknown field")
	}
	if err := validateBoolValueAction("set_hbac_disable_allow_all")(editAction{Action: "set_hbac_disable_allow_all", Value: "yes"}); err == nil {
		t.Fatal("expected validateBoolValueAction to reject a non-bool value")
	}
	if err := validateSudoRuleAllowMode(editAction{Action: "set_sudo_rule_allow_mode", Name: "x", Value: "everything"}); err == nil {
		t.Fatal("expected validateSudoRuleAllowMode to reject an unsupported value")
	}
	if err := validateEntityNameAndHosts("create_hbac_rule")(editAction{Action: "create_hbac_rule", Name: "x", Hosts: []string{"not-an-fqdn"}}); err == nil {
		t.Fatal("expected validateEntityNameAndHosts to reject a non-FQDN hosts entry")
	}
}

// TestCreateHBACRule_MixedUsersGroupsHostsHostgroups is spec.md §18.4's
// scenario: create_hbac_rule must accept and persist every relationship
// dimension (direct users, subject groups, direct hosts, hostgroups,
// services) in one structured action.
func TestCreateHBACRule_MixedUsersGroupsHostsHostgroups(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "alice"},
		{Action: "create_group", Name: "team-developers", Category: "team"},
		{Action: "create_group", Name: "role-ops", Category: "role"},
		{Action: "create_hostgroup", Name: "production"},
		{
			Action:     "create_hbac_rule",
			Name:       "mixed",
			Users:      []string{"alice"},
			Groups:     []string{"team-developers", "role-ops"},
			Hosts:      []string{"special.ipa.pilot.internal"},
			Hostgroups: []string{"production"},
			Services:   []string{"sshd"},
		},
	}}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	rule, found, err := inventory.RosterHBACRule(path, "mixed")
	if err != nil || !found {
		t.Fatalf("read HBAC rule mixed: found=%t err=%v", found, err)
	}
	sub := rosterSubmap(rule, "subjects")
	tar := rosterSubmap(rule, "targets")
	if got := sortedCopy(rosterStringSlice(sub, "users")); strings.Join(got, ",") != "alice" {
		t.Errorf("subjects.users = %v, want [alice]", got)
	}
	if got := sortedCopy(rosterStringSlice(sub, "groups")); strings.Join(got, ",") != "role-ops,team-developers" {
		t.Errorf("subjects.groups = %v, want [role-ops team-developers]", got)
	}
	if got := rosterStringSlice(tar, "hosts"); len(got) != 1 || got[0] != "special.ipa.pilot.internal" {
		t.Errorf("targets.hosts = %v, want [special.ipa.pilot.internal]", got)
	}
	if got := rosterStringSlice(tar, "hostgroups"); len(got) != 1 || got[0] != "production" {
		t.Errorf("targets.hostgroups = %v, want [production]", got)
	}
}

// TestCreateHBACRule_LegacyGroupsHostgroupsOnlyScenarioStillPasses locks
// spec.md §12.7/§20.2: an old scenario that only ever populated
// groups/hostgroups/services (no users/hosts fields existed yet) must
// still replay unchanged, including a reference to a pre-existing legacy
// access-category group that sanctioned creation can no longer author.
func TestCreateHBACRule_LegacyGroupsHostgroupsOnlyScenarioStillPasses(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)
	if err := inventory.AppendRosterGroup(path, "access-old", "access"); err != nil {
		t.Fatalf("seed legacy access-old group: %v", err)
	}

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_hostgroup", Name: "webhosts"},
		{Action: "create_hbac_rule", Name: "legacy-flow", Groups: []string{"access-old"}, Hostgroups: []string{"webhosts"}, Services: []string{"sshd"}},
	}}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	rule, found, err := inventory.RosterHBACRule(path, "legacy-flow")
	if err != nil || !found {
		t.Fatalf("read HBAC rule legacy-flow: found=%t err=%v", found, err)
	}
	sub := rosterSubmap(rule, "subjects")
	if got := rosterStringSlice(sub, "groups"); len(got) != 1 || got[0] != "access-old" {
		t.Fatalf("subjects.groups = %v, want [access-old]", got)
	}
	if got := rosterStringSlice(sub, "users"); len(got) != 0 {
		t.Fatalf("subjects.users = %v, want empty", got)
	}
}

// TestSetHBACUsers_BulkReplacesUsersPreservesGroups covers the new
// set_hbac_users action (spec.md §12.3).
func TestSetHBACUsers_BulkReplacesUsersPreservesGroups(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "alice"},
		{Action: "create_user", User: "bob"},
		{Action: "create_group", Name: "team-x", Category: "team"},
		{Action: "create_hostgroup", Name: "webhosts"},
		{Action: "create_hbac_rule", Name: "r1", Groups: []string{"team-x"}, Hostgroups: []string{"webhosts"}, Services: []string{"sshd"}},
		{Action: "set_hbac_users", Name: "r1", Users: []string{"alice", "bob"}},
	}}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	rule, found, err := inventory.RosterHBACRule(path, "r1")
	if err != nil || !found {
		t.Fatalf("read HBAC rule r1: found=%t err=%v", found, err)
	}
	sub := rosterSubmap(rule, "subjects")
	if got := sortedCopy(rosterStringSlice(sub, "users")); strings.Join(got, ",") != "alice,bob" {
		t.Fatalf("subjects.users = %v, want [alice bob]", got)
	}
	if got := rosterStringSlice(sub, "groups"); len(got) != 1 || got[0] != "team-x" {
		t.Fatalf("set_hbac_users must preserve subjects.groups, got %v", got)
	}
}

// TestSetHBACTargets_ExtendedBulkReplacesHostsAndHostgroups covers the
// extended set_hbac_targets action (spec.md §12.5): passing both hosts and
// hostgroups bulk-replaces both, and passing only hostgroups still resets
// hosts to empty — the same explicit hostgroup-only target set this action
// produced before hosts existed as a field.
func TestSetHBACTargets_ExtendedBulkReplacesHostsAndHostgroups(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_group", Name: "team-x", Category: "team"},
		{Action: "create_hostgroup", Name: "webhosts"},
		{Action: "create_hbac_rule", Name: "r1", Groups: []string{"team-x"}, Hostgroups: []string{"webhosts"}, Services: []string{"sshd"}},
		{Action: "set_hbac_targets", Name: "r1", Hostgroups: []string{"webhosts"}, Hosts: []string{"extra.ipa.pilot.internal"}},
	}}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	rule, found, err := inventory.RosterHBACRule(path, "r1")
	if err != nil || !found {
		t.Fatalf("read HBAC rule r1: found=%t err=%v", found, err)
	}
	tar := rosterSubmap(rule, "targets")
	if got := rosterStringSlice(tar, "hosts"); len(got) != 1 || got[0] != "extra.ipa.pilot.internal" {
		t.Fatalf("targets.hosts = %v, want [extra.ipa.pilot.internal]", got)
	}

	// A second call passing only hostgroups (the pre-existing contract)
	// must reset hosts back to empty.
	scenario2 := editScenario{Version: 1, Steps: []editAction{
		{Action: "set_hbac_targets", Name: "r1", Hostgroups: []string{"webhosts"}},
	}}
	r2 := newEditRouterModel(dir)
	if err := d.run(&r2, scenario2); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	rule, found, err = inventory.RosterHBACRule(path, "r1")
	if err != nil || !found {
		t.Fatalf("read HBAC rule r1 after hostgroups-only replay: found=%t err=%v", found, err)
	}
	tar = rosterSubmap(rule, "targets")
	if got := rosterStringSlice(tar, "hosts"); len(got) != 0 {
		t.Fatalf("hostgroups-only set_hbac_targets must reset targets.hosts to empty, got %v", got)
	}
	if got := rosterStringSlice(tar, "hostgroups"); len(got) != 1 || got[0] != "webhosts" {
		t.Fatalf("targets.hostgroups = %v, want [webhosts]", got)
	}
}
