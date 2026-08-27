package cmd

import (
	"slices"
	"strings"
	"testing"
)

func TestPromptAutomationSelectTextAndConfirmByID(t *testing.T) {
	confirmed := true
	p := &promptAutomation{answers: []promptAnswer{
		{PromptID: "choose", Select: "beta"},
		{PromptID: "name", Text: "new-value"},
		{PromptID: "continue", Confirm: &confirmed},
	}}

	idx, err := p.selectPrompt("choose", "localized select label", []string{"alpha", "beta"})
	if err != nil || idx != 1 {
		t.Fatalf("selectPrompt() = %d, %v", idx, err)
	}
	value, err := p.textPrompt("name", "localized text label", "old-value", nil)
	if err != nil || value != "new-value" {
		t.Fatalf("textPrompt() = %q, %v", value, err)
	}
	if got := p.confirmPrompt("continue", "localized confirmation", false); !got {
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
	p := &promptAutomation{answers: []promptAnswer{{PromptID: "choose", Select: "a"}}}
	if _, err := p.selectPrompt("other", "other", []string{"a"}); err == nil || !strings.Contains(err.Error(), "answer") {
		t.Fatalf("unknown prompt error = %v", err)
	}
	p = &promptAutomation{answers: []promptAnswer{{PromptID: "choose", Select: "a"}}}
	if _, err := p.selectPrompt("choose", "choose", []string{"a one", "a two"}); err == nil || !strings.Contains(err.Error(), "cannot choose") {
		t.Fatalf("ambiguous choice error = %v", err)
	}
}

func TestPromptAutomationUsesPromptDefaults(t *testing.T) {
	p := &promptAutomation{useDefaults: true}

	idx, err := p.selectPrompt("choose", "choose", []string{"first", "second"})
	if err != nil || idx != 0 {
		t.Fatalf("selectPrompt() = %d, %v; want first option", idx, err)
	}
	value, err := p.textPrompt("name", "name", "default-value", nil)
	if err != nil || value != "default-value" {
		t.Fatalf("textPrompt() = %q, %v; want default-value", value, err)
	}
	if !p.confirmPrompt("yes-by-default", "yes-by-default", true) {
		t.Fatal("confirmPrompt(yes-by-default) = false")
	}
	if p.confirmPrompt("no-by-default", "no-by-default", false) {
		t.Fatal("confirmPrompt(no-by-default) = true")
	}
}

func TestPromptAutomationForceApplyOverridesPostPreviewDefault(t *testing.T) {
	p := &promptAutomation{useDefaults: true, forceApply: true}
	if !p.confirmPrompt(promptExecutionApplyAfterPreview, "changed display text", false) {
		t.Fatal("force apply must continue after a successful preview")
	}
	if p.confirmPrompt("other", "other", false) {
		t.Fatal("force apply must preserve unrelated false defaults")
	}
}

func TestValidatePromptAnswersByIDRejectsContractViolations(t *testing.T) {
	base := []promptAnswer{
		{PromptID: promptInventory, Text: "inventory.yml"},
		{PromptID: promptTopologyPreview, Confirm: boolPtr(false)},
		{PromptID: promptPreflight, Select: "skip"},
		{PromptID: promptScope, Select: "site"},
		{PromptID: promptStage, Select: "sandbox"},
		{PromptID: promptLimit, Text: ""},
		{PromptID: promptTags, Text: ""},
		{PromptID: promptBecomePassword, Confirm: boolPtr(false)},
		{PromptID: promptExtraVars, Text: ""},
		{PromptID: promptExecutionPreview, Confirm: boolPtr(false)},
	}
	if err := validatePromptAnswers("deploy", base); err != nil {
		t.Fatalf("valid ID answers rejected: %v", err)
	}
	for _, tt := range []struct {
		name    string
		answers []promptAnswer
		want    string
	}{
		{"unknown", append(base, promptAnswer{PromptID: "translated.text", Text: ""}), "unknown prompt_id"},
		{"duplicate", append(base, promptAnswer{PromptID: promptInventory, Text: "other.yml"}), "duplicate"},
		{"wrong kind", append(base[:len(base)-1], promptAnswer{PromptID: promptExecutionPreview, Text: "no"}), "requires confirm"},
		{"missing always", base[1:], "missing required"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := validatePromptAnswers("deploy", tt.answers); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validatePromptAnswers() error = %v, want %q", err, tt.want)
			}
		})
	}
	badSelect := append([]promptAnswer(nil), base...)
	badSelect[2].Select = "translated skip"
	if err := validatePromptAnswers("deploy", badSelect); err == nil || !strings.Contains(err.Error(), "does not accept") {
		t.Fatalf("unknown semantic select value error = %v", err)
	}
}

func boolPtr(value bool) *bool { return &value }
