package cmd

import (
	"fmt"
	"io"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/tui"
)

type promptAnswer struct {
	PromptID string   `json:"prompt_id,omitempty"`
	Prompt   string   `json:"prompt"`
	Select   string   `json:"select,omitempty"`
	Selects  []string `json:"selects,omitempty"`
	Text     string   `json:"text,omitempty"`
	Confirm  *bool    `json:"confirm,omitempty"`
}

// promptAutomation answers the existing one-shot deploy/reconcile prompts by
// applying ordinary key messages to the same screen models used interactively.
type promptAutomation struct {
	action       string // "deploy" or "reconcile"; resolves prompt_id -> promptDefinition
	answers      []promptAnswer
	events       []automationTraceEvent
	reusable     map[string]promptAnswer
	err          error
	presentation bool
	out          io.Writer
	useDefaults  bool
	forceApply   bool
	// reuseAnswers permits a deploy action to use the same explicit approval
	// for repeated same-host dependency transactions. Reconcile multi-select
	// workflows use it for the same reason.
	reuseAnswers bool
}

// validatePromptAnswers accepts either automation contract: legacy scripts
// that match prompts by their (localized, UI-only) label text, or scripts
// that opt into the stable prompt_id contract. The "every always-prompt must
// be answered" completeness check only applies once a script actually uses
// prompt_id — a legacy label-only script is already forced to answer every
// prompt it reaches, one at a time, by the "no automation answer for ..."
// runtime error, so re-deriving that same completeness up front from a
// key-space (short ids) the script never populated would just reject every
// pre-existing legacy scenario outright.
func validatePromptAnswers(action string, answers []promptAnswer) error {
	seen := make(map[string]bool, len(answers))
	usesPromptID := false
	for _, answer := range answers {
		if answer.PromptID != "" {
			usesPromptID = true
			definition, ok := promptDefinitionFor(action, answer.PromptID)
			if !ok {
				return fmt.Errorf("unknown prompt_id %q", answer.PromptID)
			}
			if seen[answer.PromptID] {
				return fmt.Errorf("duplicate prompt_id %q", answer.PromptID)
			}
			seen[answer.PromptID] = true
			if err := validatePromptAnswerKind(definition, answer); err != nil {
				return err
			}
			continue
		}
		if strings.TrimSpace(answer.Prompt) == "" {
			return fmt.Errorf("prompt answer requires prompt")
		}
		if seen[answer.Prompt] {
			return fmt.Errorf("duplicate prompt answer")
		}
		seen[answer.Prompt] = true
		if hasSecretName(answer.Prompt) || hasSecretName(answer.Text) {
			return fmt.Errorf("secret values are not accepted in prompt answers")
		}
		if answer.Select != "" && len(answer.Selects) > 0 {
			return fmt.Errorf("prompt answer cannot contain both select and selects")
		}
	}
	if action == "deploy" && usesPromptID {
		for _, id := range []string{promptInventory, promptTopologyPreview, promptPreflight, promptScope, promptStage, promptLimit, promptTags, promptBecomePassword, promptExtraVars, promptExecutionPreview} {
			if !seen[id] {
				return fmt.Errorf("missing required prompt_id %q", id)
			}
		}
	}
	return nil
}

func validatePromptAnswerKind(def promptDefinition, answer promptAnswer) error {
	switch def.Kind {
	case "confirm":
		if answer.Confirm == nil {
			return fmt.Errorf("prompt_id %q requires confirm", def.ID)
		}
	case "text":
		if answer.Confirm != nil || answer.Select != "" || len(answer.Selects) > 0 {
			return fmt.Errorf("prompt_id %q requires text", def.ID)
		}
	case "select":
		if answer.Confirm != nil || (answer.Select == "" && len(answer.Selects) == 0) {
			return fmt.Errorf("prompt_id %q requires select", def.ID)
		}
	}
	if answer.Select != "" && len(answer.Selects) > 0 {
		return fmt.Errorf("prompt answer cannot contain both select and selects")
	}
	if answer.PromptID != "" && hasSecretName(answer.Text) {
		return fmt.Errorf("secret values are not accepted in prompt answers")
	}
	if len(def.AcceptedValues) > 0 && answer.Select != "" {
		for _, value := range def.AcceptedValues {
			if value == answer.Select {
				return nil
			}
		}
		return fmt.Errorf("prompt_id %q does not accept %q", def.ID, answer.Select)
	}
	return nil
}

var activePromptAutomation *promptAutomation

// promptWorkflowAllowsNonTTY reports whether a wizard may run without a
// terminal attached. Normal deploy/reconcile use terminal widgets; the
// --actions path has already installed a driver that feeds those same widgets
// deterministically, so it must be admitted in a non-interactive process.
func promptWorkflowAllowsNonTTY(isTerminal bool) bool {
	return isTerminal || activePromptAutomation != nil
}

func (p *promptAutomation) answer(kind, id, prompt string) (promptAnswer, bool) {
	for i, answer := range p.answers {
		if (id != "" && answer.PromptID == id) || answer.Prompt == prompt || (answer.Prompt != "" && strings.Contains(prompt, answer.Prompt)) {
			p.answers = append(p.answers[:i], p.answers[i+1:]...)
			if p.reuseAnswers {
				if p.reusable == nil {
					p.reusable = make(map[string]promptAnswer)
				}
				p.reusable[prompt] = answer
			}
			return answer, true
		}
	}
	if p.reuseAnswers && p.reusable != nil {
		if answer, ok := p.reusable[prompt]; ok {
			return answer, true
		}
	}
	return promptAnswer{}, false
}

func (p *promptAutomation) selectPrompt(id, prompt string, items []string) (int, error) {
	if p.useDefaults {
		return 0, nil
	}
	answer, ok := p.answer("select", id, prompt)
	if !ok {
		return 0, fmt.Errorf("no automation answer for select prompt")
	}
	index, err := p.resolveSelectIndex(answer, items)
	if err != nil {
		return 0, fmt.Errorf("cannot choose %q: %w", answer.Select, err)
	}
	choices := make([]tui.Choice, len(items))
	for i, it := range items {
		choices[i] = tui.Choice{Label: it}
	}
	m := standaloneScreen{s: deployUIFactory.Select(tui.SelectSpec{Title: prompt, Choices: choices})}
	if err := initStandaloneScreen(&m); err != nil {
		return 0, err
	}
	p.render(prompt, viewContent(m.View()))
	keys := make([]string, 0, index+1)
	for i := 0; i < index; i++ {
		if err := applyStandaloneKey(&m, keyDown()); err != nil {
			return 0, err
		}
		keys = append(keys, "down")
	}
	if err := applyStandaloneKey(&m, keyEnter()); err != nil {
		return 0, err
	}
	keys = append(keys, "enter")
	p.render(prompt, viewContent(m.View()))
	if p.tracePrompt("select", prompt, viewContent(m.View()), keys, "ok"); p.err != nil {
		return 0, p.err
	}
	return m.s.(tui.SelectScreen).Selected(), nil
}

// resolveSelectIndex maps an answer's Select value to an item index. A
// prompt_id-based answer names one of promptDefinition.AcceptedValues — a
// short, stable value (e.g. "sandbox") that is not necessarily a substring
// of the actual (localized, reworded-without-notice) displayed choice text.
// When the schema's AcceptedValues line up 1:1 with what was actually
// offered (same count), resolve by position in that list instead. Anything
// else (a legacy label-matched answer, or a prompt whose live choice set can
// shrink — e.g. experimental components filtered out) falls back to the
// original literal-text matching, which is exactly right for those cases:
// their Select value already is the stable identifier (a hostname, role
// name, component key, ...) rather than a schema-declared semantic value.
func (p *promptAutomation) resolveSelectIndex(answer promptAnswer, items []string) (int, error) {
	if answer.PromptID != "" && p.action != "" {
		if definition, ok := promptDefinitionFor(p.action, answer.PromptID); ok && len(definition.AcceptedValues) == len(items) {
			for i, value := range definition.AcceptedValues {
				if value == answer.Select {
					return i, nil
				}
			}
		}
	}
	return uniqueItemIndex(items, answer.Select)
}

func (p *promptAutomation) multiSelectPrompt(prompt string, items []string) ([]int, error) {
	if p.useDefaults {
		return []int{0}, nil
	}
	answer, ok := p.answer("multi-select", "", prompt)
	if !ok {
		return nil, fmt.Errorf("no automation answer for multi-select prompt")
	}
	labels := append([]string(nil), answer.Selects...)
	if len(labels) == 0 && answer.Select != "" {
		// Keep existing single-select scenario files valid when they are used
		// against a reconcile wizard that now has one checklist prompt.
		labels = []string{answer.Select}
	}
	if len(labels) == 0 {
		return nil, fmt.Errorf("multi-select prompt requires select or selects")
	}
	// Keep compatibility with component-specific prompts that may still recur
	// during a multi-component workflow. Batch-wide inputs are collected once
	// by the reconcile flow itself; this fallback is only for prompts whose
	// literal text is repeated by a component-specific path.
	p.reuseAnswers = len(labels) > 1
	indexes := make([]int, 0, len(labels))
	checked := make(map[int]bool, len(labels))
	for _, label := range labels {
		index, err := uniqueItemIndex(items, label)
		if err != nil {
			return nil, fmt.Errorf("cannot choose %q: %w", label, err)
		}
		if checked[index] {
			return nil, fmt.Errorf("multi-select item %q was selected more than once", label)
		}
		checked[index] = true
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	choices := make([]tui.MultiSelectChoice, len(items))
	for i, item := range items {
		choices[i] = tui.MultiSelectChoice{
			Choice:  tui.Choice{ID: fmt.Sprintf("%d", i), Label: item},
			Checked: checked[i],
		}
	}
	m := standaloneScreen{s: deployUIFactory.MultiSelect(tui.MultiSelectSpec{
		Title:   prompt + "（space 勾選、enter 完成）",
		Choices: choices,
	})}
	if err := initStandaloneScreen(&m); err != nil {
		return nil, err
	}
	p.render(prompt, viewContent(m.View()))
	if err := applyStandaloneKey(&m, keyEnter()); err != nil {
		return nil, err
	}
	p.tracePrompt("multi-select", prompt, viewContent(m.View()), []string{"enter"}, "ok")
	p.render(prompt, viewContent(m.View()))
	return indexes, nil
}

func (p *promptAutomation) textPrompt(args ...any) (string, error) {
	var id, prompt, def string
	var validate func(string) error
	if len(args) == 4 {
		id, _ = args[0].(string)
		prompt, _ = args[1].(string)
		def, _ = args[2].(string)
		validate, _ = args[3].(func(string) error)
	} else if len(args) == 3 {
		// Legacy tests/callers omitted the stable ID; match by label.
		prompt, _ = args[0].(string)
		def, _ = args[1].(string)
		validate, _ = args[2].(func(string) error)
	} else {
		return "", fmt.Errorf("text prompt requires id, prompt, default, validator")
	}
	if p.useDefaults {
		return def, nil
	}
	answer, ok := p.answer("text", id, prompt)
	if !ok {
		return "", fmt.Errorf("no automation answer for text prompt")
	}
	m := standaloneScreen{s: deployUIFactory.Input(tui.InputSpec{Title: prompt, Default: def, Validate: validate})}
	if err := initStandaloneScreen(&m); err != nil {
		return "", err
	}
	p.render(prompt, viewContent(m.View()))
	keys := make([]string, 0, 3)
	if answer.Text != "" {
		if err := applyStandaloneKey(&m, keyCtrlU()); err != nil {
			return "", err
		}
		keys = append(keys, "ctrl+u")
		if err := applyStandaloneKey(&m, keyTextMsg(answer.Text)); err != nil {
			return "", err
		}
		keys = append(keys, "text")
	}
	if err := applyStandaloneKey(&m, keyEnter()); err != nil {
		return "", err
	}
	keys = append(keys, "enter")
	value := m.s.(tui.InputScreen).Value()
	if !m.s.(tui.InputScreen).Finished() {
		return "", fmt.Errorf("automation text answer failed validation")
	}
	p.tracePrompt("text", prompt, viewContent(m.View()), keys, "ok")
	p.render(prompt, viewContent(m.View()))
	return value, nil
}

func (p *promptAutomation) confirmPrompt(id, prompt string, defaultYes bool) bool {
	if p.forceApply && (id == promptExecutionApplyAfterPreview || id == promptExecutionConfirmApply || strings.Contains(prompt, "預覽看起來沒問題，要接著套用真正的變更嗎？")) {
		return true
	}
	if p.useDefaults {
		return defaultYes
	}
	answer, ok := p.answer("confirm", id, prompt)
	if !ok || answer.Confirm == nil {
		p.err = fmt.Errorf("no automation answer for confirm prompt")
		return false
	}
	m := standaloneScreen{s: deployUIFactory.Confirm(tui.ConfirmSpec{Title: prompt, Default: defaultYes})}
	if err := initStandaloneScreen(&m); err != nil {
		p.err = err
		return false
	}
	p.render(prompt, viewContent(m.View()))
	key := keyRuneMsg('n')
	if *answer.Confirm {
		key = keyRuneMsg('y')
	}
	if err := applyStandaloneKey(&m, key); err != nil {
		p.err = err
		return false
	}
	p.tracePrompt("confirm", prompt, viewContent(m.View()), []string{key.String()}, "ok")
	p.render(prompt, viewContent(m.View()))
	return m.s.(tui.ConfirmScreen).Value()
}

func (p *promptAutomation) render(prompt, view string) {
	if p.presentation && p.out != nil {
		fmt.Fprintf(p.out, "\n── %s ──\n%s", prompt, view)
	}
}

func (p *promptAutomation) tracePrompt(kind, prompt, _ string, keys []string, result string) {
	p.events = append(p.events, automationTraceEvent{
		Step:     len(p.events) + 1,
		Action:   "prompt." + kind,
		ScreenID: kind,
		Keys:     append([]string(nil), keys...),
		Result:   result,
	})
}

func applyStandaloneKey(m *standaloneScreen, msg tea.KeyPressMsg) error {
	next, _ := m.Update(msg)
	updated, ok := next.(standaloneScreen)
	if !ok {
		return fmt.Errorf("prompt returned unexpected model")
	}
	*m = updated
	return nil
}

// initStandaloneScreen runs m's Init() and drains whatever tea.Cmd
// cascade it returns, feeding each resulting message straight back into
// Update — exactly what a real tea.Program's event loop already does
// for deploy_tui.go's runSelectProgram/runTextProgram/runConfirmProgram
// (which construct a real Program and call .Run()). This automation
// path drives a standaloneScreen directly instead, so nothing else ever
// calls Init() for it. The hand-written primitives tolerated that
// (their Update logic doesn't depend on Init having run), but a Huh
// screen does: Init() is what activates the wrapped Form's first group
// and focuses its field — skip it and every key this function sends is
// silently dropped, since nothing is listening yet. The 10-iteration
// bound matches the deepest real cascade observed (Huh's own
// nextFieldMsg -> nextGroupMsg chain is 2 steps); it exists only so a
// future cascade that never terminates can't hang this call forever.
func initStandaloneScreen(m *standaloneScreen) error {
	cmd := m.Init()
	for i := 0; cmd != nil && i < 10; i++ {
		msg := cmd()
		if msg == nil {
			return nil
		}
		next, c := m.Update(msg)
		updated, ok := next.(standaloneScreen)
		if !ok {
			return fmt.Errorf("prompt returned unexpected model")
		}
		*m = updated
		cmd = c
	}
	return nil
}
