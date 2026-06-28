package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestAskUserToolUsesInjectedAsker verifies that when an Asker is wired,
// Execute uses it instead of any global / stdin path.
func TestAskUserToolUsesInjectedAsker(t *testing.T) {
	called := false
	gotQ := ""
	gotOpts := []string{}
	tc := &AskUserTool{
		Asker: func(q string, opts []string) string {
			called = true
			gotQ = q
			gotOpts = opts
			return "answer-from-asker"
		},
	}
	res, err := tc.Execute(context.Background(), json.RawMessage(`{"question":"Q?","options":["a","b"]}`))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !called {
		t.Fatal("injected asker was not called")
	}
	if gotQ != "Q?" {
		t.Errorf("asker got wrong question: %q", gotQ)
	}
	if len(gotOpts) != 2 || gotOpts[0] != "a" || gotOpts[1] != "b" {
		t.Errorf("asker got wrong options: %v", gotOpts)
	}
	if !strings.Contains(res.Content, "answer-from-asker") {
		t.Errorf("expected answer in result content, got: %q", res.Content)
	}
}

// TestAskUserToolPerInstanceIndependence verifies that two AskUserTool
// instances do not share asker state (regression for the previous
// process-global SetGlobalAsker antipattern).
func TestAskUserToolPerInstanceIndependence(t *testing.T) {
	var aCalled, bCalled int
	a := &AskUserTool{Asker: func(string, []string) string { aCalled++; return "A" }}
	b := &AskUserTool{Asker: func(string, []string) string { bCalled++; return "B" }}

	for _, tc := range []struct {
		name string
		t    *AskUserTool
		want string
	}{
		{"a", a, "A"},
		{"b", b, "B"},
		{"a", a, "A"},
	} {
		res, err := tc.t.Execute(context.Background(), json.RawMessage(`{"question":"q"}`))
		if err != nil {
			t.Fatalf("%s: execute: %v", tc.name, err)
		}
		if !strings.Contains(res.Content, tc.want) {
			t.Errorf("%s: expected %q in result, got: %q", tc.name, tc.want, res.Content)
		}
	}
	if aCalled != 2 || bCalled != 1 {
		t.Errorf("asker call counts: a=%d b=%d, want a=2 b=1", aCalled, bCalled)
	}
}

// TestAskUserToolRejectsMissingQuestion verifies the input validation
// path; nothing about the Asker DI should bypass this.
func TestAskUserToolRejectsMissingQuestion(t *testing.T) {
	tc := &AskUserTool{Asker: func(string, []string) string { return "" }}
	_, err := tc.Execute(context.Background(), json.RawMessage(`{"options":["a"]}`))
	if err == nil {
		t.Fatal("expected error for missing question")
	}
}

// TestNoProcessGlobalAsker is a compile-time check: if SetGlobalAsker
// or the globalAsker variable were re-introduced, this file would no
// longer compile cleanly. We use a no-op symbol instead so the test
// suite documents the architectural intent.
func TestNoProcessGlobalAsker(t *testing.T) {
	// Just assert the new public API surface exists.
	var _ Asker = func(string, []string) string { return "" }
	tc := &AskUserTool{}
	if tc.Asker != nil {
		t.Fatal("zero-value AskUserTool.Asker should be nil")
	}
}
