package cmd

import (
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestEditAutomationDriverRosterGroupsFlow_CreateAndSetFields(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_user", User: "alice"},
			{Action: "create_group", Name: "team-eng", Category: "team"},
			{Action: "set_group_field", Name: "team-eng", Field: "description", Value: "engineering team"},
			{Action: "set_group_field", Name: "team-eng", Field: "gid", Value: "20001"},
			{Action: "set_group_field", Name: "team-eng", Field: "type", Value: "nonposix"},
			{Action: "set_group_field", Name: "team-eng", Field: "membership.authoritative", Value: "false"},
			{Action: "set_group_members_users", Name: "team-eng", Users: []string{"alice"}},
			{Action: "create_group", Name: "team-other", Category: "team"},
			{Action: "set_group_members_groups", Name: "team-eng", Groups: []string{"team-other"}},
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

	fields, found, err := inventory.RosterGroup(path, "team-eng")
	if err != nil {
		t.Fatalf("RosterGroup() error = %v", err)
	}
	if !found {
		t.Fatal("expected group team-eng to exist")
	}
	if fields["description"] != "engineering team" {
		t.Fatalf("description = %v, want engineering team", fields["description"])
	}
	if gid, ok := fields["gid"].(int); !ok || gid != 20001 {
		t.Fatalf("gid = %v (%T), want int 20001", fields["gid"], fields["gid"])
	}
	if fields["type"] != "nonposix" {
		t.Fatalf("type = %v, want nonposix", fields["type"])
	}
	mem, _ := fields["membership"].(map[string]any)
	if mem == nil || mem["authoritative"] != false {
		t.Fatalf("membership.authoritative = %+v, want false", mem)
	}
	users, _ := mem["users"].([]any)
	if len(users) != 1 || users[0] != "alice" {
		t.Fatalf("membership.users = %+v, want [alice]", users)
	}
	groups, _ := mem["groups"].([]any)
	if len(groups) != 1 || groups[0] != "team-other" {
		t.Fatalf("membership.groups = %+v, want [team-other]", groups)
	}
}

func TestEditAutomationDriverRosterGroupsFlow_ValidationRejectsBadInput(t *testing.T) {
	if err := validateCreateGroup(editAction{Action: "create_group"}); err == nil {
		t.Fatal("expected validateCreateGroup to reject an empty name")
	}
	if err := validateCreateGroup(editAction{Action: "create_group", Name: "x", Category: "not-a-category"}); err == nil {
		t.Fatal("expected validateCreateGroup to reject an unknown category")
	}
	// spec.md §20.1: create_group must reject the deprecated access
	// category with a message pointing authors at team/role instead.
	err := validateCreateGroup(editAction{Action: "create_group", Name: "access-new", Category: "access"})
	if err == nil {
		t.Fatal("expected validateCreateGroup to reject the deprecated access category")
	}
	if !strings.Contains(err.Error(), "deprecated") || !strings.Contains(err.Error(), "team or role") {
		t.Fatalf("validateCreateGroup(access) error = %q, want it to mention deprecated + team or role", err)
	}
	cases := []editAction{
		{Action: "set_group_field", Name: "x", Field: "not_a_real_field", Value: "y"},
		{Action: "set_group_field", Name: "x", Field: "gid", Value: "not-a-number"},
		{Action: "set_group_field", Name: "x", Field: "type", Value: "not-a-type"},
		{Action: "set_group_field", Name: "x", Field: "membership.authoritative", Value: "yes"},
	}
	for _, step := range cases {
		if err := validateSetGroupField(step); err == nil {
			t.Fatalf("expected validateSetGroupField to reject %+v", step)
		}
	}
	if err := validateGroupNameOnly("set_group_members_users")(editAction{Action: "set_group_members_users"}); err == nil {
		t.Fatal("expected validateGroupNameOnly to reject an empty name")
	}
}
