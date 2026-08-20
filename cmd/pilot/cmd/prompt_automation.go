package cmd

import (
	"fmt"
	"io"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/tui"
)

type promptAnswer struct {
	Prompt  string `json:"prompt"`
	Select  string `json:"select,omitempty"`
	Text    string `json:"text,omitempty"`
	Confirm *bool  `json:"confirm,omitempty"`
}

// promptAutomation answers the existing one-shot deploy/reconcile prompts by
// applying ordinary key messages to the same screen models used interactively.
type promptAutomation struct {
	answers      []promptAnswer
	events       []automationTraceEvent
	err          error
	presentation bool
	out          io.Writer
	useDefaults  bool
	forceApply   bool
}

func validatePromptAnswers(answers []promptAnswer) error {
	seen := make(map[string]bool, len(answers))
	for _, answer := range answers {
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
	}
	return nil
}

var activePromptAutomation *promptAutomation

func (p *promptAutomation) answer(kind, prompt string) (promptAnswer, bool) {
	for i, answer := range p.answers {
		if answer.Prompt == prompt || strings.Contains(prompt, answer.Prompt) {
			p.answers = append(p.answers[:i], p.answers[i+1:]...)
			return answer, true
		}
	}
	return promptAnswer{}, false
}

func (p *promptAutomation) selectPrompt(prompt string, items []string) (int, error) {
	if p.useDefaults {
		return 0, nil
	}
	answer, ok := p.answer("select", prompt)
	if !ok {
		return 0, fmt.Errorf("no automation answer for select prompt")
	}
	index, err := uniqueItemIndex(items, answer.Select)
	if err != nil {
		return 0, err
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

func (p *promptAutomation) textPrompt(prompt, def string, validate func(string) error) (string, error) {
	if p.useDefaults {
		return def, nil
	}
	answer, ok := p.answer("text", prompt)
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

func (p *promptAutomation) confirmPrompt(prompt string, defaultYes bool) bool {
	if p.forceApply && strings.Contains(prompt, "預覽看起來沒問題，要接著套用真正的變更嗎？") {
		return true
	}
	if p.useDefaults {
		return defaultYes
	}
	answer, ok := p.answer("confirm", prompt)
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
