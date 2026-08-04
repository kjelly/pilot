// edit_automation_driver_screenid_test.go covers the Phase 1 ID-based
// navigation primitives (itemIndexByID, automationDriver.chooseByID) —
// see docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md's
// "Stable Automation Identity" section. No production driver method
// calls chooseByID yet (Phase 1 only ships the primitive and the IDs to
// target — see edit_agent_session.go's package doc comment), so these
// tests exercise it directly against hand-built screens rather than
// through a push*/automationDriver method.
package cmd

import (
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

// TestAutomationDriver_TraceRecordsDistinctContextualScreenIDs drives a
// real scenario through the actual router (not a hand-built screen, as
// the tests above use) and checks the contextual screenIDs wired at
// each push* call site in edit_tui.go — the same automationTraceEvent
// existing tests already capture via d.trace already carries
// automationScreenID(r), so this needs no new instrumentation.
func TestAutomationDriver_TraceRecordsDistinctContextualScreenIDs(t *testing.T) {
	dir := t.TempDir()
	role := inventory.Roles()[0].Name
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "enable_role", Host: "web-1", Role: role},
			{Action: "save_hosts"},
		},
	}
	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(e automationTraceEvent) { events = append(events, e) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	want := []string{"hosts.item", "hosts.item", "edit.top"}
	if len(events) != len(want) {
		t.Fatalf("got %d trace events, want %d", len(events), len(want))
	}
	for i, w := range want {
		if events[i].ScreenID != w {
			t.Fatalf("step %d (%s) screen_id = %q, want %q", i+1, scenario.Steps[i].Action, events[i].ScreenID, w)
		}
	}
}

func TestItemIndexByID_UniqueMatch(t *testing.T) {
	items := []selectItem{{ID: "a", Label: "Alpha"}, {ID: "b", Label: "Beta"}}
	idx, err := itemIndexByID(items, "b")
	if err != nil || idx != 1 {
		t.Fatalf("itemIndexByID(b) = (%d, %v), want (1, nil)", idx, err)
	}
}

func TestItemIndexByID_Ambiguous(t *testing.T) {
	items := []selectItem{{ID: "dup", Label: "one"}, {ID: "dup", Label: "two"}}
	if _, err := itemIndexByID(items, "dup"); err == nil {
		t.Fatal("expected an error for a duplicated ID")
	}
}

func TestItemIndexByID_Missing(t *testing.T) {
	items := []selectItem{{ID: "a", Label: "Alpha"}}
	if _, err := itemIndexByID(items, "nope"); err == nil {
		t.Fatal("expected an error for an ID with no match")
	}
}

func TestItemIndexByID_EmptyIDRejectedEvenIfAnItemHasOne(t *testing.T) {
	// An item with ID == "" (the common case — most items never get an
	// AutomationID) must never be reachable by passing "" as the target:
	// that would let an unset ID silently match, defeating fail-closed.
	items := []selectItem{{ID: "", Label: "no id"}, {ID: "b", Label: "Beta"}}
	if _, err := itemIndexByID(items, ""); err == nil {
		t.Fatal("expected an error when the target ID itself is empty")
	}
}

func TestChooseByID_WrongScreenFailsClosed(t *testing.T) {
	items := []selectItem{{ID: "hosts.create", Label: "➕ 新增主機"}}
	r := editRouterModel{current: newSelectModelWithIDs("hosts.list", "t", items)}
	d := automationDriver{}
	if err := d.chooseByID(&r, "hosts.item", "hosts.create"); err == nil {
		t.Fatal("expected an error when wantScreenID doesn't match the current screen")
	}
}

func TestChooseByID_NonSelectScreenFailsClosed(t *testing.T) {
	r := editRouterModel{current: newConfirmModelWithScreenID("confirm.discard", "q", false)}
	d := automationDriver{}
	if err := d.chooseByID(&r, "confirm.discard", "anything"); err == nil {
		t.Fatal("expected an error targeting an item on a non-select screen")
	}
}

func TestChooseByID_UnknownItemIDFailsClosed(t *testing.T) {
	items := []selectItem{{ID: "hosts.create", Label: "➕ 新增主機"}}
	r := editRouterModel{current: newSelectModelWithIDs("hosts.list", "t", items)}
	d := automationDriver{}
	if err := d.chooseByID(&r, "hosts.list", "no-such-id"); err == nil {
		t.Fatal("expected an error for an item ID that isn't present")
	}
}

func TestChooseByID_MovesCursorAndSelects(t *testing.T) {
	items := []selectItem{{ID: "a", Label: "a"}, {ID: "hosts.create", Label: "➕ 新增主機"}, {ID: "c", Label: "c"}}
	r := editRouterModel{current: newSelectModelWithIDs("hosts.list", "t", items)}
	d := automationDriver{}
	if err := d.chooseByID(&r, "hosts.list", "hosts.create"); err != nil {
		t.Fatalf("chooseByID() error = %v", err)
	}
	list, ok := r.current.(selectModel)
	if !ok || !list.Finished() || list.Canceled() {
		t.Fatalf("expected a finished, non-canceled selectModel, got %#v", r.current)
	}
	if got := list.Selected(); got != 1 {
		t.Fatalf("Selected() = %d, want 1", got)
	}
}
