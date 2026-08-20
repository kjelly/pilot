package cmd

import (
	"testing"

	"github.com/kjelly/pilot/internal/tui"
)

// These compile-time assertions are the enforcement mechanism for
// Core Invariant 2/3 during the migration: as long as each concrete
// primitive satisfies the corresponding tui.*Screen interface, router
// callbacks and the automation driver can be converted from
// `x.(selectModel)` to `x.(tui.SelectScreen)` (etc.) one call site at a
// time without any of them losing observable capability.
var (
	_ tui.Screen            = selectModel{}
	_ tui.SelectScreen      = selectModel{}
	_ tui.Screen            = multiSelectModel{}
	_ tui.MultiSelectScreen = multiSelectModel{}
	_ tui.Screen            = textInputModel{}
	_ tui.InputScreen       = textInputModel{}
	_ tui.Screen            = confirmModel{}
	_ tui.ConfirmScreen     = confirmModel{}
)

func TestSelectModel_AutomationStateReflectsFilterAndFocus(t *testing.T) {
	m := newSelectModelWithIDs("hosts.list", "選一台主機", []selectItem{
		{ID: "host-a", Label: "host-a"},
		{ID: "host-b", Label: "host-b"},
	})
	st := m.AutomationState()
	if st.ScreenID != "hosts.list" || st.Kind != tui.ScreenSelect || st.Title != "選一台主機" {
		t.Fatalf("unexpected base state: %+v", st)
	}
	if len(st.Items) != 2 || st.Items[0].ID != "host-a" || st.Items[1].ID != "host-b" {
		t.Fatalf("unexpected items: %+v", st.Items)
	}
	if st.FocusedIndex != 0 {
		t.Fatalf("expected initial focus 0, got %d", st.FocusedIndex)
	}

	m.cursor = 1
	st = m.AutomationState()
	if st.FocusedIndex != 1 {
		t.Fatalf("expected focus to follow cursor, got %d", st.FocusedIndex)
	}
	if m.Selected() != 1 || m.SelectedID() != "host-b" {
		t.Fatalf("expected SelectedID/Selected to resolve host-b, got %q/%d", m.SelectedID(), m.Selected())
	}
}

func TestSelectModel_AutomationStateFilterActiveWhileSearching(t *testing.T) {
	m := newSelectModelWithScreenID("hosts.list", "t", []string{"a", "b"})
	m.searching = true
	if !m.AutomationState().FilterActive {
		t.Fatal("expected FilterActive true while searching")
	}
}

func TestMultiSelectModel_AutomationStateExposesCheckedWithoutPrivateFields(t *testing.T) {
	m := newMultiSelectModelWithScreenID("roles.checklist", "角色", []multiSelectItem{
		{ID: "dns", Label: "dns", Checked: true},
		{ID: "ntp", Label: "ntp", Checked: false},
	})
	st := m.AutomationState()
	if st.Kind != tui.ScreenMultiSelect {
		t.Fatalf("unexpected kind: %v", st.Kind)
	}
	if len(st.Items) != 2 || !st.Items[0].Checked || st.Items[1].Checked {
		t.Fatalf("unexpected checked state: %+v", st.Items)
	}
	ids := m.CheckedIDs()
	if len(ids) != 1 || ids[0] != "dns" {
		t.Fatalf("expected CheckedIDs=[dns], got %v", ids)
	}
}

func TestTextInputModel_AutomationStateNeverExposesSecretValue(t *testing.T) {
	m := newSecretTextInputModelWithScreenID("vault.value", "密碼", "", nil)
	m.input.SetValue("super-secret-sentinel")
	st := m.AutomationState()
	if !st.Secret {
		t.Fatal("expected Secret=true for a secret input screen")
	}
	if !st.HasValue {
		t.Fatal("expected HasValue=true once a value is typed")
	}
	// AutomationState carries no field capable of holding the literal
	// value; this is enforced by the struct shape, not a runtime check.
	// Confirm the plaintext still reaches Value() for the real save path.
	if m.Value() != "super-secret-sentinel" {
		t.Fatal("expected Value() to still return the real typed secret for the save callback")
	}
}

func TestConfirmModel_AutomationStateStable(t *testing.T) {
	m := newConfirmModelWithScreenID("hosts.delete_confirm", "確定刪除？", false)
	st := m.AutomationState()
	if st.Kind != tui.ScreenConfirm || st.Title != "確定刪除？" || st.ScreenID != "hosts.delete_confirm" {
		t.Fatalf("unexpected state: %+v", st)
	}
}
