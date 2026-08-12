package cmd

import (
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestEditAutomationDriverRosterAccessFlow_HostgroupAndHBAC(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_group", Name: "access-web", Category: "access"},
			{Action: "create_hostgroup", Name: "webhosts"},
			{Action: "set_hostgroup_field", Name: "webhosts", Field: "description", Value: "web tier"},
			{Action: "set_hostgroup_field", Name: "webhosts", Field: "membership.hosts", Value: "web1.ipa.pilot.internal, web2.ipa.pilot.internal"},
			{Action: "create_hbac_rule", Name: "web-login", Groups: []string{"access-web"}, Hostgroups: []string{"webhosts"}, Services: []string{"sshd"}},
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
	if len(groups) != 1 || groups[0] != "access-web" {
		t.Fatalf("subjects.groups = %+v, want [access-web]", groups)
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

	list, ok := router.current.(multiSelectModel)
	if !ok {
		t.Fatalf("router.current = %T, want multiSelectModel", router.current)
	}
	for _, item := range list.items {
		if item.Label == "hg-a" {
			t.Fatalf("choices included hg-a itself: %+v", list.items)
		}
	}
	if len(list.items) != 1 || list.items[0].Label != "hg-b" {
		t.Fatalf("choices = %+v, want just [hg-b]", list.items)
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
}
