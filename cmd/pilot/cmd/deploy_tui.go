// deploy_tui.go implements `pilot deploy`'s prompt primitives on top
// of the shared Bubble Tea screens (tui_select.go/tui_textinput.go/
// tui_confirm.go), replacing the old promptui-based
// promptSelectIndex/promptText/promptConfirm (deploy.go used to define
// these directly on promptui; pilot edit's equivalents are
// runSelectProgram/runTextProgram/runConfirmProgram's cousins,
// selectModel/textInputModel/confirmModel embedded in a router).
//
// Unlike pilot edit's router (edit_tui.go), pilot deploy does NOT use
// one continuous tea.Program for the whole invocation. Its flow is a
// long, strictly linear sequence of one-shot prompts (no revisitable
// menus — deploy.go's own control flow never loops back to an earlier
// step) punctuated by a few real `ansible-playbook`/`ansible-inventory`
// subprocess runs with live streaming output (preflight, preview,
// apply) that must happen with no Bubble Tea Program active at all,
// exactly as before this rewrite — internal/ansible.Runner streams
// straight to a configured io.Writer, not through any terminal-raw-
// mode-aware library, and reimplementing that here was out of scope
// (deploy.go's own header comment: "It does not reimplement any
// deployment logic"). So each individual prompt gets its own short-
// lived tea.Program (mirroring exactly what promptSelectIndex/
// promptText/promptConfirm's blocking promptui.Run() calls already
// did), and the rest of deploy.go's control flow (runDeploy,
// runPreflight, promptStageDecision, promptSeaweedfsS3Config,
// promptAutoHostVar, promptVault, executeDeployment, runSiteDeploy,
// runSinglePlaybookDeploy) is otherwise untouched from the pre-rewrite
// version — deliberately: deploy.go doesn't have edit.go's
// revisitable-menu structure that benefited from consolidating into
// one router, and duplicating that machinery here would only add risk
// to a long, business-logic-heavy file for no benefit.
package cmd

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

// runSelectProgram is promptSelectIndex's Bubble Tea equivalent. It
// runs selectModel wrapped in standaloneScreen (tui_screen.go) since
// selectModel itself never calls tea.Quit — only a router (or, here,
// standaloneScreen standing in for one) decides when a one-shot
// prompt's Program should actually exit.
func runSelectProgram(label string, items []string) (int, error) {
	if activePromptAutomation != nil {
		return activePromptAutomation.selectPrompt(label, items)
	}
	m := standaloneScreen{s: newSelectModel(label, items)}
	final, err := tea.NewProgram(m, tea.WithOutput(os.Stdout)).Run()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errDeployAborted, err)
	}
	fm := final.(standaloneScreen).s.(selectModel)
	if fm.Canceled() {
		return 0, errDeployAborted
	}
	return fm.Selected(), nil
}

// runTextProgram is promptText's Bubble Tea equivalent.
func runTextProgram(label, def string, validate func(string) error) (string, error) {
	if activePromptAutomation != nil {
		return activePromptAutomation.textPrompt(label, def, validate)
	}
	m := standaloneScreen{s: newTextInputModel(label, def, validate)}
	final, err := tea.NewProgram(m, tea.WithOutput(os.Stdout)).Run()
	if err != nil {
		return "", fmt.Errorf("%w: %v", errDeployAborted, err)
	}
	fm := final.(standaloneScreen).s.(textInputModel)
	if fm.Canceled() {
		return "", errDeployAborted
	}
	return fm.Value(), nil
}

// runConfirmProgram is promptConfirm's Bubble Tea equivalent — it
// matches promptConfirm's existing contract exactly: it never returns
// an error, and esc/ctrl+c resolves to "no" (confirmModel.Canceled()
// is always false; see tui_confirm.go's doc comment), not a
// wizard-level abort.
func runConfirmProgram(question string, defaultYes bool) bool {
	if activePromptAutomation != nil {
		return activePromptAutomation.confirmPrompt(question, defaultYes)
	}
	m := standaloneScreen{s: newConfirmModel(question, defaultYes)}
	final, err := tea.NewProgram(m, tea.WithOutput(os.Stdout)).Run()
	if err != nil {
		return false
	}
	return final.(standaloneScreen).s.(confirmModel).Value()
}
