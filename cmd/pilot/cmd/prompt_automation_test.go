package cmd

import (
	"slices"
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

func TestPromptAutomationMultiSelectSupportsSeveralItems(t *testing.T) {
	p := &promptAutomation{answers: []promptAnswer{{
		Prompt:  "components",
		Selects: []string{"gamma", "alpha"},
	}}}

	indexes, err := p.multiSelectPrompt("components", []string{"alpha", "beta", "gamma"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := indexes, []int{0, 2}; !slices.Equal(got, want) {
		t.Fatalf("multiSelectPrompt() = %v, want %v", got, want)
	}
	if len(p.events) != 1 || p.events[0].Action != "prompt.multi-select" {
		t.Fatalf("events = %+v, want one multi-select trace event", p.events)
	}
}

func TestPromptAutomationMultiSelectKeepsLegacySingleSelectionAnswer(t *testing.T) {
	p := &promptAutomation{answers: []promptAnswer{{Prompt: "components", Select: "beta"}}}
	indexes, err := p.multiSelectPrompt("components", []string{"alpha", "beta"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := indexes, []int{1}; !slices.Equal(got, want) {
		t.Fatalf("multiSelectPrompt() = %v, want %v", got, want)
	}
}

func TestPromptAutomationMultiSelectReusesCommonBatchAnswers(t *testing.T) {
	p := &promptAutomation{answers: []promptAnswer{
		{Prompt: "components", Selects: []string{"alpha", "beta"}},
		{Prompt: "limit", Text: "host-a"},
	}}
	if _, err := p.multiSelectPrompt("components", []string{"alpha", "beta"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		got, err := p.textPrompt("limit", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got != "host-a" {
			t.Fatalf("textPrompt() = %q, want host-a", got)
		}
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

func TestPromptAutomationUsesPromptDefaults(t *testing.T) {
	p := &promptAutomation{useDefaults: true}

	idx, err := p.selectPrompt("choose", []string{"first", "second"})
	if err != nil || idx != 0 {
		t.Fatalf("selectPrompt() = %d, %v; want first option", idx, err)
	}
	value, err := p.textPrompt("name", "default-value", nil)
	if err != nil || value != "default-value" {
		t.Fatalf("textPrompt() = %q, %v; want default-value", value, err)
	}
	if !p.confirmPrompt("yes-by-default", true) {
		t.Fatal("confirmPrompt(yes-by-default) = false")
	}
	if p.confirmPrompt("no-by-default", false) {
		t.Fatal("confirmPrompt(no-by-default) = true")
	}
}

func TestPromptAutomationForceApplyOverridesPostPreviewDefault(t *testing.T) {
	p := &promptAutomation{useDefaults: true, forceApply: true}
	if !p.confirmPrompt("預覽看起來沒問題，要接著套用真正的變更嗎？", false) {
		t.Fatal("force apply must continue after a successful preview")
	}
	if p.confirmPrompt("其他確認", false) {
		t.Fatal("force apply must preserve unrelated false defaults")
	}
}
