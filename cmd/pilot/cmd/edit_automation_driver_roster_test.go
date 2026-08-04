package cmd

import (
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

// writeMinimalRosterFixture seeds dir's default roster path
// (.vault/ipa-identity.yaml, matching pushRosterPathPrompt's prefilled
// default — automation only ever accepts that default in this
// increment) with a minimal, valid, empty-users roster.
func writeMinimalRosterFixture(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	fixture := "schema_version: 1\nfreeipa: {domain: ipa.pilot.internal}\nusers: []\n"
	writeTestFile(t, path, fixture)
	return path
}

func TestEditAutomationDriverRosterFlow_CreateUserAndSetFields(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_user", User: "alice"},
			{Action: "set_user_field", User: "alice", Field: "email", Value: "alice@example.com"},
			{Action: "set_user_field", User: "alice", Field: "uid", Value: "10001"},
			{Action: "set_user_field", User: "alice", Field: "enabled", Value: "false"},
			{Action: "set_user_field", User: "alice", Field: "state", Value: "disabled"},
		},
	}

	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	if len(events) != len(scenario.Steps) {
		t.Fatalf("trace events = %d, want %d", len(events), len(scenario.Steps))
	}
	for _, event := range events {
		if event.Result != "ok" {
			t.Fatalf("bad trace event: %+v", event)
		}
	}

	fields, found, err := inventory.RosterUser(path, "alice")
	if err != nil {
		t.Fatalf("RosterUser() error = %v", err)
	}
	if !found {
		t.Fatal("expected user alice to exist after create_user")
	}
	if fields["email"] != "alice@example.com" {
		t.Fatalf("email = %v, want alice@example.com", fields["email"])
	}
	if uid, ok := fields["uid"].(int); !ok || uid != 10001 {
		t.Fatalf("uid = %v (%T), want int 10001", fields["uid"], fields["uid"])
	}
	if fields["enabled"] != false {
		t.Fatalf("enabled = %v, want false", fields["enabled"])
	}
	if fields["state"] != "disabled" {
		t.Fatalf("state = %v, want disabled", fields["state"])
	}
}

func TestEditAutomationDriverRosterFlow_SetUserFieldRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	writeMinimalRosterFixture(t, dir)

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "bob"},
		{Action: "set_user_field", User: "bob", Field: "not_a_real_field", Value: "x"},
	}}
	err := validateEditScenario(scenario)
	if err == nil {
		t.Fatal("expected validateEditScenario to reject an unknown user field")
	}
}

func TestEditAutomationDriverRosterFlow_SetUserFieldRejectsBadEnumValues(t *testing.T) {
	cases := []editAction{
		{Action: "set_user_field", User: "x", Field: "state", Value: "absent"}, // not offered by this wizard
		{Action: "set_user_field", User: "x", Field: "enabled", Value: "yes"},
		{Action: "set_user_field", User: "x", Field: "uid", Value: "not-a-number"},
	}
	for _, step := range cases {
		if err := validateSetUserField(step); err == nil {
			t.Fatalf("expected validateSetUserField to reject %+v", step)
		}
	}
}

func TestEditAutomationDriverRosterFlow_CreateUserRejectsEmptyName(t *testing.T) {
	if err := validateCreateUser(editAction{Action: "create_user"}); err == nil {
		t.Fatal("expected validateCreateUser to reject an empty user name")
	}
}
