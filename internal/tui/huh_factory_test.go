package tui

import (
	"strings"
	"testing"
)

func TestHuhFactoryBuildsEveryScreenKind(t *testing.T) {
	f := NewHuhFactory()

	sel := f.Select(fruitSpec())
	if got := sel.AutomationState().Kind; got != ScreenSelect {
		t.Fatalf("Select kind=%q", got)
	}
	ms := f.MultiSelect(rolesSpec())
	if got := ms.AutomationState().Kind; got != ScreenMultiSelect {
		t.Fatalf("MultiSelect kind=%q", got)
	}
	in := f.Input(InputSpec{ScreenID: "x.input", Title: "X"})
	if got := in.AutomationState().Kind; got != ScreenInput {
		t.Fatalf("Input kind=%q", got)
	}
	cf := f.Confirm(ConfirmSpec{ScreenID: "x.confirm", Title: "X?"})
	if got := cf.AutomationState().Kind; got != ScreenConfirm {
		t.Fatalf("Confirm kind=%q", got)
	}

	// Every product is a live Screen: initialisable, renderable, and
	// not finished before the user does anything.
	for name, s := range map[string]Screen{"select": sel, "multi-select": ms, "input": in, "confirm": cf} {
		s.Init()
		if s.Finished() {
			t.Fatalf("%s: Finished()=true before any key", name)
		}
		if s.View().Content == "" {
			t.Fatalf("%s: rendered an empty view", name)
		}
	}
}

func TestHuhFactorySecretInputIsMarkedSecret(t *testing.T) {
	in := NewHuhFactory().Input(InputSpec{ScreenID: "vault.pw", Title: "Password", Secret: true})
	in.Init()
	const sentinel = "factory-secret-77"
	typeText(t, in, sentinel)
	if !in.AutomationState().Secret {
		t.Fatalf("Secret=false on a Secret spec")
	}
	if strings.Contains(in.View().Content, sentinel) {
		t.Fatalf("factory-built secret input leaked its value")
	}
}

// A whole wizard step driven only through the Pilot-owned contract:
// no test here names a Huh type, which is the point of Core Invariant 2.
func TestHuhFactoryDrivesAScreenThroughTheContractOnly(t *testing.T) {
	var f Factory = NewHuhFactory()

	var sel SelectScreen = f.Select(SelectSpec{
		ScreenID:  "hosts.list",
		Title:     "選擇主機",
		Choices:   []Choice{{ID: "h1", Label: "ipa01"}, {ID: "h2", Label: "web01"}, {ID: "h3", Label: "db01"}},
		InitialID: "h2",
	})
	sel.Init()
	if got := sel.AutomationState().FocusedIndex; got != 1 {
		t.Fatalf("FocusedIndex=%d want 1 from InitialID", got)
	}
	send(t, sel, keyDown)
	send(t, sel, keyEnter)
	if !sel.Finished() || sel.Canceled() || sel.SelectedID() != "h3" {
		t.Fatalf("select outcome: finished=%v canceled=%v id=%q", sel.Finished(), sel.Canceled(), sel.SelectedID())
	}

	var in InputScreen = f.Input(InputSpec{ScreenID: "hosts.ip", Title: "IP", Default: "10.0.0.1"})
	in.Init()
	send(t, in, keyEnter)
	if !in.Finished() || in.Value() != "10.0.0.1" {
		t.Fatalf("input outcome: finished=%v value=%q", in.Finished(), in.Value())
	}

	var cf ConfirmScreen = f.Confirm(ConfirmSpec{ScreenID: "hosts.save", Title: "儲存?", Default: true})
	cf.Init()
	send(t, cf, keyEnter)
	if !cf.Finished() || !cf.Value() || cf.Canceled() {
		t.Fatalf("confirm outcome: finished=%v value=%v canceled=%v", cf.Finished(), cf.Value(), cf.Canceled())
	}
}
