package cmd

import (
	"fmt"
	"io"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
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
	answer, ok := p.answer("select", prompt)
	if !ok {
		return 0, fmt.Errorf("no automation answer for select prompt")
	}
	index, err := uniqueItemIndex(items, answer.Select)
	if err != nil {
		return 0, err
	}
	m := standaloneScreen{s: newSelectModel(prompt, items)}
	p.render(prompt, m.View())
	keys := make([]string, 0, index+1)
	for i := 0; i < index; i++ {
		if err := applyStandaloneKey(&m, tea.KeyMsg{Type: tea.KeyDown}); err != nil {
			return 0, err
		}
		keys = append(keys, "down")
	}
	if err := applyStandaloneKey(&m, tea.KeyMsg{Type: tea.KeyEnter}); err != nil {
		return 0, err
	}
	keys = append(keys, "enter")
	p.render(prompt, m.View())
	if p.tracePrompt("select", prompt, m.View(), keys, "ok"); p.err != nil {
		return 0, p.err
	}
	return m.s.(selectModel).Selected(), nil
}

func (p *promptAutomation) textPrompt(prompt, def string, validate func(string) error) (string, error) {
	answer, ok := p.answer("text", prompt)
	if !ok {
		return "", fmt.Errorf("no automation answer for text prompt")
	}
	m := standaloneScreen{s: newTextInputModel(prompt, def, validate)}
	p.render(prompt, m.View())
	keys := make([]string, 0, 3)
	if answer.Text != "" {
		if err := applyStandaloneKey(&m, tea.KeyMsg{Type: tea.KeyCtrlU}); err != nil {
			return "", err
		}
		keys = append(keys, "ctrl+u")
		if err := applyStandaloneKey(&m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(answer.Text)}); err != nil {
			return "", err
		}
		keys = append(keys, "text")
	}
	if err := applyStandaloneKey(&m, tea.KeyMsg{Type: tea.KeyEnter}); err != nil {
		return "", err
	}
	keys = append(keys, "enter")
	value := m.s.(textInputModel).Value()
	if !m.s.(textInputModel).Finished() {
		return "", fmt.Errorf("automation text answer failed validation")
	}
	p.tracePrompt("text", prompt, m.View(), keys, "ok")
	p.render(prompt, m.View())
	return value, nil
}

func (p *promptAutomation) confirmPrompt(prompt string, defaultYes bool) bool {
	answer, ok := p.answer("confirm", prompt)
	if !ok || answer.Confirm == nil {
		p.err = fmt.Errorf("no automation answer for confirm prompt")
		return false
	}
	m := standaloneScreen{s: newConfirmModel(prompt, defaultYes)}
	p.render(prompt, m.View())
	key := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")}
	if *answer.Confirm {
		key = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")}
	}
	if err := applyStandaloneKey(&m, key); err != nil {
		p.err = err
		return false
	}
	p.tracePrompt("confirm", prompt, m.View(), []string{key.String()}, "ok")
	p.render(prompt, m.View())
	return m.s.(confirmModel).Value()
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

func applyStandaloneKey(m *standaloneScreen, msg tea.KeyMsg) error {
	next, _ := m.Update(msg)
	updated, ok := next.(standaloneScreen)
	if !ok {
		return fmt.Errorf("prompt returned unexpected model")
	}
	*m = updated
	return nil
}
