package cmd

import (
	"strings"
	"testing"
)

func TestPromptAutomationSelectTextAndConfirm(t *testing.T) {
	confirmed := true
	p := &promptAutomation{
		answers: []promptAnswer{
			{Prompt: "choose", Select: "beta"},
			{Prompt: "name", Text: "new-value"},
			{Prompt: "continue", Confirm: &confirmed},
		},
	}

	idx, err := p.selectPrompt("choose", []string{"alpha", "beta"})
	if err != nil || idx != 1 {
		t.Fatalf("selectPrompt() = %d, %v", idx, err)
	}
	value, err := p.textPrompt("name", "old-value", nil)
	if err != nil || value != "new-value" {
		t.Fatalf("textPrompt() = %q, %v", value, err)
	}
	if got := p.confirmPrompt("continue", false); !got {
		t.Fatal("confirmPrompt() = false, want true")
	}
	if len(p.events) != 3 {
		t.Fatalf("events = %d, want 3", len(p.events))
	}
}

func TestPromptAutomationRejectsUnknownPromptAndAmbiguousChoice(t *testing.T) {
	p := &promptAutomation{answers: []promptAnswer{{Prompt: "choose", Select: "a"}}}
	if _, err := p.selectPrompt("other", []string{"a"}); err == nil || !strings.Contains(err.Error(), "answer") {
		t.Fatalf("unknown prompt error = %v", err)
	}
	p = &promptAutomation{answers: []promptAnswer{{Prompt: "choose", Select: "a"}}}
	if _, err := p.selectPrompt("choose", []string{"a one", "a two"}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous choice error = %v", err)
	}
}
