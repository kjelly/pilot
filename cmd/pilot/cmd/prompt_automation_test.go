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

func TestPromptAutomationReusesDeployAnswersForDependencyTransactions(t *testing.T) {
	confirmed := true
	p := &promptAutomation{action: "deploy", reuseAnswers: true, answers: []promptAnswer{
		{PromptID: promptPreflight, Select: "full"},
		{PromptID: promptExecutionPreview, Confirm: &confirmed},
	}}
	preflightChoices := []string{
		"完整前置檢查(含 SSH 連線測試)",
		"只做靜態檢查(機器還沒開機/還連不上時用；不連線)",
		"跳過前置檢查",
	}
	for transaction := 0; transaction < 2; transaction++ {
		index, err := p.selectPrompt(promptPreflight, "要先跑前置檢查(preflight)嗎？", preflightChoices)
		if err != nil || index != 0 {
			t.Fatalf("transaction %d preflight = %d, %v; want full", transaction, index, err)
		}
		if !p.confirmPrompt(promptExecutionPreview, "要先預覽(--check --diff)再決定要不要真的套用嗎？", true) {
			t.Fatalf("transaction %d preview confirmation = false, want true", transaction)
		}
	}
	if len(p.answers) != 0 {
		t.Fatalf("unconsumed answers = %d, want 0", len(p.answers))
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
		{"wrong kind", append(append([]promptAnswer(nil), base[:len(base)-1]...), promptAnswer{PromptID: promptExecutionPreview, Text: "no"}), "requires confirm"},
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

// TestValidatePromptAnswersAllowsLegacyPromptTextOnly guards against a
// regression where bc4d089's "every always-prompt id must be answered"
// completeness check ran unconditionally: every pre-existing deploy
// automation scenario (all label-matched, none using prompt_id) failed
// validation with "missing required prompt_id" before ever reaching a real
// prompt, because those scripts' answers are keyed by literal label text,
// never by the short id constants the check looked for.
func TestValidatePromptAnswersAllowsLegacyPromptTextOnly(t *testing.T) {
	answers := []promptAnswer{
		{Prompt: "Inventory 檔路徑", Text: ""},
		{Prompt: "要不要先看一下這份 inventory 的拓樸圖", Confirm: boolPtr(false)},
		{Prompt: "要先跑前置檢查(preflight)嗎", Select: "完整前置檢查"},
		{Prompt: "要佈署什麼？", Select: "全站部署"},
		{Prompt: "要套用到哪個 stage", Select: "sandbox"},
		{Prompt: "要限定只套用到某台主機嗎？(--limit", Text: ""},
		{Prompt: "要只跑某幾類元件嗎？(--tags", Text: ""},
		{Prompt: "這次佈署要用它當密碼變數檔嗎", Confirm: boolPtr(false)},
		{Prompt: "這次佈署需要密碼變數嗎", Select: "不需要"},
		{Prompt: "這次套用要手動輸入 sudo(become)密碼嗎", Confirm: boolPtr(false)},
		{Prompt: "還有其他 -e 變數要帶嗎", Text: ""},
	}
	if err := validatePromptAnswers("deploy", answers); err != nil {
		t.Fatalf("legacy label-only deploy answers rejected: %v", err)
	}
}

// TestPromptAutomationSelectResolvesSemanticAcceptedValue proves the
// deploy.go/reconcile.go wiring gap is closed: a prompt_id-only answer names
// a promptDefinition.AcceptedValues term (e.g. "static"), which is not a
// substring of the actual displayed (Chinese) choice text, so legacy
// literal-text matching alone could never resolve it. Resolution must go
// through the schema's accepted-value position instead.
func TestPromptAutomationSelectResolvesSemanticAcceptedValue(t *testing.T) {
	p := &promptAutomation{action: "deploy", answers: []promptAnswer{
		{PromptID: promptPreflight, Select: "static"},
	}}
	idx, err := p.selectPrompt(promptPreflight, "要先跑前置檢查(preflight)嗎？", []string{
		"完整前置檢查(含 SSH 連線測試)",
		"只做靜態檢查(機器還沒開機/還連不上時用；不連線)",
		"跳過前置檢查",
	})
	if err != nil || idx != 1 {
		t.Fatalf("selectPrompt() = %d, %v, want 1 (static)", idx, err)
	}
}
