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
//
// Known tradeoff of the per-prompt-Program design: between one Program's
// Run() returning and the next one's Run() re-entering raw mode, the
// terminal briefly reverts to cooked/echoed mode. A keystroke that arrives
// in that gap (a fast typist, a paste, or any scripted driver) can be
// swallowed into the kernel's line-buffered input instead of delivered to
// the new screen, and resurface later as garbled echoed text once some
// later reader (even a spawned subprocess with no active raw-mode reader)
// finally consumes it — confirmed and documented in
// deploy_tui_pty_test.go's newProgramSettle and in
// .agents/skills/pilot-trec-verification/SKILL.md. This was weighed and
// accepted, not overlooked, when this file replaced promptui: a real human
// is naturally slow enough (reads before typing) to rarely hit it, and a
// single continuous tea.Program (edit_tui.go's router) was rejected above
// for unrelated reasons. Anything driving pilot deploy at high speed —
// trec, a very low key-delay, or another scripted PTY client — should
// settle briefly after each new prompt appears before sending its first
// keystroke, the same discipline newProgramSettle already applies in tests.
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
