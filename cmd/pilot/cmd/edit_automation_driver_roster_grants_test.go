package cmd

import (
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestEditAutomationDriverRosterGrantsFlow_CreateTemporaryGrantAndEdit(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_user", User: "vendor01"},
			{Action: "create_group", Name: "team-web", Category: "team"},
			{Action: "create_hostgroup", Name: "webhosts"},
			{
				Action: "create_grant", Name: "vendor-project-x", Kind: "temporary_grant",
				Users: []string{"vendor01"}, Groups: []string{"team-web"},
				Hostgroups: []string{"webhosts"}, Services: []string{"sshd"},
				NotAfter: "2099-12-31T23:59:59Z", Reason: "initial reason",
			},
			{Action: "set_grant_justification", Name: "vendor-project-x", Reason: "updated reason", Ticket: "INC-1"},
			{Action: "set_grant_validity", Name: "vendor-project-x", NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2099-06-30T00:00:00Z"},
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

	grant, found, err := inventory.RosterGrant(path, "vendor-project-x")
	if err != nil {
		t.Fatalf("RosterGrant() error = %v", err)
	}
	if !found {
		t.Fatal("expected grant vendor-project-x to exist")
	}
	if grant["kind"] != "temporary_grant" {
		t.Fatalf("kind = %v, want temporary_grant", grant["kind"])
	}
	just, _ := grant["justification"].(map[string]any)
	if just["reason"] != "updated reason" || just["ticket"] != "INC-1" {
		t.Fatalf("justification = %+v, want updated reason/INC-1", just)
	}
	val, _ := grant["validity"].(map[string]any)
	if val["not_before"] != "2026-01-01T00:00:00Z" || val["not_after"] != "2099-06-30T00:00:00Z" {
		t.Fatalf("validity = %+v, want updated window", val)
	}

	violations, err := inventory.ValidateRosterFile(path)
	if err != nil {
		t.Fatalf("ValidateRosterFile() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected the roster to validate cleanly, got: %v", violations)
	}
}

func TestEditAutomationDriverRosterGrantsFlow_CreateSudoGrantSetPrivilege(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_user", User: "alice"},
			{Action: "create_group", Name: "role-prod-operator", Category: "role"},
			{Action: "create_hostgroup", Name: "prodweb"},
			{
				Action: "create_grant", Name: "alice-prod-nginx", Kind: "sudo_grant",
				Users: []string{"alice"}, Groups: []string{"role-prod-operator"},
				Hostgroups: []string{"prodweb"},
				NotAfter:   "2099-12-31T23:59:59Z", Reason: "incident response",
			},
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

	grant, found, err := inventory.RosterGrant(path, "alice-prod-nginx")
	if err != nil {
		t.Fatalf("RosterGrant() error = %v", err)
	}
	if !found {
		t.Fatal("expected grant alice-prod-nginx to exist")
	}
	priv, _ := grant["privilege"].(map[string]any)
	if priv["command_category"] != "all" {
		t.Fatalf("expected default privilege.command_category=all, got: %+v", priv)
	}

	violations, err := inventory.ValidateRosterFile(path)
	if err != nil {
		t.Fatalf("ValidateRosterFile() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected the roster to validate cleanly, got: %v", violations)
	}
}

func TestEditAutomationDriverRosterGrantsFlow_CreateBreakglassAndDelete(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_user", User: "emergency-admin"},
			{Action: "create_hostgroup", Name: "prodweb"},
			{
				Action: "create_grant", Name: "infra-emergency", Kind: "breakglass",
				Users: []string{"emergency-admin"}, Hostgroups: []string{"prodweb"},
				Services: []string{"sshd"}, MaxDuration: "1h",
			},
			{Action: "set_grant_activation", Name: "infra-emergency", MaxDuration: "4h"},
			{Action: "delete_grant", Name: "infra-emergency"},
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

	grant, found, err := inventory.RosterGrant(path, "infra-emergency")
	if err != nil {
		t.Fatalf("RosterGrant() error = %v", err)
	}
	if !found {
		t.Fatal("expected the soft-deleted grant to still exist in the roster")
	}
	if grant["state"] != "absent" {
		t.Fatalf("state = %v, want absent", grant["state"])
	}
	act, _ := grant["activation"].(map[string]any)
	if act["max_duration"] != "4h" {
		t.Fatalf("activation.max_duration = %v, want 4h (set via set_grant_activation)", act["max_duration"])
	}
}

// TestEditAutomationDriverRosterGrantsFlow_ActivateDeactivateBreakglass
// exercises activate_breakglass/deactivate_breakglass end to end against a
// fake ansible runner (no real FreeIPA), proving the activation state
// machine (internal/accessgrants) round-trips correctly through the
// registry/driver path — the same coverage TestActivate_* in
// internal/accessgrants/breakglass_test.go gives the underlying function,
// here exercised via the actual `pilot edit --actions` surface.
func TestEditAutomationDriverRosterGrantsFlow_ActivateDeactivateBreakglass(t *testing.T) {
	dir := t.TempDir()
	writeMinimalRosterFixture(t, dir)
	t.Setenv("PILOT_DATA_DIR", t.TempDir())
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = "" })

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_user", User: "emergency-admin"},
			{Action: "create_hostgroup", Name: "prodweb"},
			{
				Action: "create_grant", Name: "infra-emergency", Kind: "breakglass",
				Users: []string{"emergency-admin"}, Hostgroups: []string{"prodweb"},
				Services: []string{"sshd"}, MaxDuration: "1h",
			},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	// activate_breakglass goes through accessgrants.Activate, which tries
	// to run a real ansible-playbook against accessGovernanceInventoryPath
	// (an inventory.yml that was never created in this fixture) — no
	// fake-runner injection point exists at the editAction level, so this
	// can only reach a real ansible-playbook invocation and fail there.
	// pushBreakglassActivateTicket (edit_tui_roster_breakglass.go) turns
	// that failure into a "❌ "-prefixed r.banner rather than a Go error
	// bubbling up through the driver's send/choose/typeText/enter
	// primitives (those only ever report navigation-level errors), so the
	// banner is what this test asserts on — internal/accessgrants' own
	// tests already cover Activate/Deactivate's logic with a fake runner.
	if err := d.activateBreakglass(&r, "infra-emergency", "30m", "outage", "INC-1"); err != nil {
		t.Fatalf("activateBreakglass() navigation error = %v", err)
	}
	if !strings.HasPrefix(r.banner, "❌") {
		t.Fatalf("banner = %q, want a ❌-prefixed failure (no real ansible-playbook/FreeIPA target in this sandbox)", r.banner)
	}
}
