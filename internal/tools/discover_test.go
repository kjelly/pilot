package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDiscoverTool_InitialStageReturnsQuestions(t *testing.T) {
	tool := &DiscoverTool{}
	res, err := tool.Execute(context.Background(), json.RawMessage(`{"stage":"initial"}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success, got error: %s", res.Content)
	}
	var payload DiscoverOutput
	if err := json.Unmarshal([]byte(res.Content), &payload); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, res.Content)
	}
	if len(payload.Questions) != 4 {
		t.Errorf("expected 4 questions, got %d", len(payload.Questions))
	}
	// Required question IDs must be present
	want := []string{"scope", "cis_level", "focus", "first_action"}
	seen := map[string]bool{}
	for _, q := range payload.Questions {
		seen[q.ID] = true
		if len(q.Options) < 2 {
			t.Errorf("question %s has < 2 options", q.ID)
		}
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("missing question id %q", w)
		}
	}
	if len(payload.SuggestedNextTools) == 0 {
		t.Errorf("expected at least one suggested next tool")
	}
	// ask_user must be among them
	found := false
	for _, s := range payload.SuggestedNextTools {
		if s.Tool == "ask_user" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ask_user in suggested_next_tools")
	}
}

func TestDiscoverTool_FollowupStageNarrower(t *testing.T) {
	tool := &DiscoverTool{}
	res, _ := tool.Execute(context.Background(), json.RawMessage(`{"stage":"followup"}`))
	var payload DiscoverOutput
	_ = json.Unmarshal([]byte(res.Content), &payload)
	if len(payload.Questions) != 2 {
		t.Errorf("followup should have 2 questions, got %d", len(payload.Questions))
	}
	want := []string{"apply_mode", "blast_radius"}
	seen := map[string]bool{}
	for _, q := range payload.Questions {
		seen[q.ID] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("missing followup id %q", w)
		}
	}
}

func TestDiscoverTool_EmptyArgsDefaultsToInitial(t *testing.T) {
	tool := &DiscoverTool{}
	res, _ := tool.Execute(context.Background(), json.RawMessage(`{}`))
	if !strings.Contains(res.Content, `"scope"`) {
		t.Errorf("empty args should default to initial stage; got: %s", res.Content[:min(200, len(res.Content))])
	}
}

func min(a, b int) int { if a < b { return a }; return b }
