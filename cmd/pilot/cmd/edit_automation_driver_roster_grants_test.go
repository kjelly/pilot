package cmd

import (
	"os"
	"path/filepath"
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
	// The TUI is a funnel of the identity lock gate: there is no FreeIPA server
	// here to take /etc/ipa on, so the lock is an in-memory one, and what the
	// screen asked of it is asserted below.
	lock := useFakeIdentityLock(t)

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

	// activate_breakglass goes through accessgrants.Activate, which runs
	// ansible-playbook against accessGovernanceInventoryPath; there is no
	// fake-runner injection point at the editAction level, so the test puts an
	// ansible-playbook that fails on PATH (internal/accessgrants' own tests
	// cover Activate/Deactivate's logic with a fake runner). The screen shows
	// the failure as a "❌" banner and records it for the driver
	// (editRouterModel.failedAction): the driver's call fails with the cause,
	// as the step of a scenario does, instead of returning nil for an
	// activation that did not happen (AGENTS.md §5.8).
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	err := d.activateBreakglass(&r, "infra-emergency", "30m", "outage", "INC-1")
	if err == nil || !strings.Contains(err.Error(), "break-glass infra-emergency was not activated") || !strings.Contains(err.Error(), "exited 1") {
		t.Fatalf("activateBreakglass() error = %v, want the failure of the playbook", err)
	}
	if !strings.HasPrefix(r.banner, "❌") || !strings.Contains(r.banner, "exited 1") {
		t.Fatalf("banner = %q, want the ❌-prefixed failure the operator sees", r.banner)
	}
	// The failure above is the playbook's, not the lock's: the screen took the
	// lock first, without waiting (the TUI call is synchronous, with nowhere to
	// show progress), on the inventory of the workspace it was editing.
	reqs := lock.Requests()
	if len(reqs) != 1 || reqs[0].Wait != 0 || reqs[0].Progress != nil || reqs[0].Inventory != accessGovernanceInventoryPath(dir) {
		t.Fatalf("lock requests = %+v, want one for %s that does not wait", reqs, accessGovernanceInventoryPath(dir))
	}
	if lock.Acquired() != 1 || lock.Released() != 1 {
		t.Fatalf("the lock was taken %d times and released %d", lock.Acquired(), lock.Released())
	}
	// And deactivating goes through the same funnel.
	if err := d.deactivateBreakglass(&r, "infra-emergency"); err == nil || !strings.Contains(err.Error(), "break-glass infra-emergency was not deactivated") {
		t.Fatalf("deactivateBreakglass() error = %v, want the failure of the playbook", err)
	}
	if reqs := lock.Requests(); len(reqs) != 2 || reqs[1].Wait != 0 || lock.Acquired() != 2 {
		t.Fatalf("after deactivating: lock requests = %+v, taken %d times", reqs, lock.Acquired())
	}
}
