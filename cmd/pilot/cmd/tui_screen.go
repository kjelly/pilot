// tui_screen.go defines the shared contract every embedded wizard
// screen (selectModel, multiSelectModel, textInputModel, confirmModel)
// satisfies, plus the list-window scrolling math selectModel and
// multiSelectModel both need.
//
// Unlike a standalone `tea.NewProgram(...).Run()` invocation (the
// pattern the old per-screen promptui/bubbletea call sites used —
// e.g. today's promptRoleChecklist), these screens run embedded
// inside one long-lived router Program (editRouterModel /
// deployWizardModel) — so pressing enter/esc on a screen must never
// return tea.Quit: that would end the whole wizard session, not just
// this one screen. Instead a screen marks itself Finished() and the
// router reads its result, then decides the next screen to show.
package cmd

import (
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/tui"
)

// tuiKeyName normalizes the control-code form of Return. Most terminals
// deliver Return as CR (KeyEnter), but some PTY/tmux combinations deliver LF
// (Ctrl-J). All embedded screens should use this helper so navigation keys
// behave consistently across terminals.
//
// Bubble Tea v2's tea.KeyPressMsg has no v1-style Type enum — a key press is
// just a Code rune plus a Mod bitmask — so the v1 "switch msg.Type" dispatch
// becomes an explicit Code/Mod comparison here. Unlike v1, v2 does not
// auto-unify Ctrl+[ with Esc, so that unification (like Ctrl-J/Return above)
// is preserved explicitly by the msg.String() fallback switch below rather
// than being automatic — see the migration spec's "Keyboard Migration" /
// "Return / Ctrl-J Compatibility" sections.
func tuiKeyName(msg tea.KeyPressMsg) string {
	switch {
	case msg.Code == tea.KeyEnter, msg.Code == 'j' && msg.Mod == tea.ModCtrl:
		return "enter"
	case msg.Code == tea.KeyEsc:
		return "esc"
	case msg.Code == 'c' && msg.Mod == tea.ModCtrl:
		return "ctrl+c"
	}
	// A few terminal/PTY layers leave CR, LF, or ESC as a rune key rather
	// than converting it to Bubble Tea's named key type.
	switch msg.String() {
	case "\r", "\n":
		return "enter"
	case "\x1b", "ctrl+[":
		return "esc"
	default:
		return msg.String()
	}
}

// screen is the contract a router-embedded wizard screen satisfies in
// addition to tea.Model. It embeds tui.Screen (Finished/Canceled/
// AutomationState) — the Pilot-owned UI contract from internal/tui —
// so router callbacks and the automation driver can introspect a
// screen via AutomationState() or a typed result interface
// (tui.SelectScreen etc.) instead of asserting one of this package's
// concrete types (selectModel, multiSelectModel, textInputModel,
// confirmModel). automationScreenID stays as a same-package-only
// method for now; it always agrees with AutomationState().ScreenID.
type screen interface {
	tui.Screen
	// automationScreenID identifies the primitive screen type for the
	// semantic automation driver without changing the rendered UI.
	automationScreenID() string
}

// listChromeLines is how many lines a scrollable list screen
// (selectModel, multiSelectModel) spends on title, help text, and the
// two always-reserved scroll-indicator rows — subtracted from
// terminal height to size the visible item window.
const listChromeLines = 6

// listVisibleRows is how many item rows fit on screen at once. Before
// the terminal size is known (height == 0, i.e. no WindowSizeMsg yet)
// it falls back to a reasonable default rather than aggressively
// clamping to a tiny window on the first frame.
func listVisibleRows(itemCount, height int) int {
	if height == 0 {
		return min(itemCount, 15)
	}
	return min(itemCount, max(height-listChromeLines, 3))
}

// standaloneScreen wraps a single `screen` in its own tea.Program,
// quitting once it reports Finished() — for one-shot prompts run
// outside any router (see deploy_tui.go's runSelectProgram/
// runTextProgram/runConfirmProgram). The screen primitives themselves
// deliberately never call tea.Quit (see the package doc comment
// above) because pilot edit's router needs to keep its single
// continuous Program alive across screen transitions; a standalone
// prompt has no router to do that job, so this wrapper does it
// instead.
type standaloneScreen struct {
	s screen
}

func (h standaloneScreen) Init() tea.Cmd { return h.s.Init() }

func (h standaloneScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := h.s.Update(msg)
	h.s = next.(screen)
	if h.s.Finished() {
		return h, tea.Quit
	}
	return h, cmd
}

func (h standaloneScreen) View() tea.View { return h.s.View() }

// listClampWindow returns a new windowStart that keeps cursor inside
// [windowStart, windowStart+rows) and windowStart itself inside a
// valid range — call after every cursor move or resize so scrolling
// follows the cursor instead of leaving it to run off either edge of
// the visible window.
func listClampWindow(cursor, windowStart, itemCount, height int) int {
	rows := listVisibleRows(itemCount, height)
	if cursor < windowStart {
		windowStart = cursor
	}
	if cursor >= windowStart+rows {
		windowStart = cursor - rows + 1
	}
	windowStart = min(windowStart, max(itemCount-rows, 0))
	windowStart = max(windowStart, 0)
	return windowStart
}

// listMoveCursor moves one or more positions through a list, wrapping at
// either end. An empty list always keeps its cursor at zero so callers can
// safely pass every navigation key through this helper.
func listMoveCursor(cursor, itemCount, delta int) int {
	if itemCount <= 0 {
		return 0
	}
	cursor = (cursor + delta) % itemCount
	if cursor < 0 {
		cursor += itemCount
	}
	return cursor
}

// listFilterIndices returns the original item indexes whose labels fuzzy-match
// query. A fuzzy match is case-insensitive and allows unmatched characters
// between query characters, so "fas" matches "freeipa-server".
func listFilterIndices(items []string, query string) []int {
	var matches []int
	for i, item := range items {
		if listFuzzyMatches(query, item) {
			matches = append(matches, i)
		}
	}
	return matches
}

func listFuzzyMatches(query, item string) bool {
	queryRunes := listSearchRunes(query)
	if len(queryRunes) == 0 {
		return true
	}
	itemRunes := listSearchRunes(item)
	queryAt := 0
	for _, r := range itemRunes {
		if r == queryRunes[queryAt] {
			queryAt++
			if queryAt == len(queryRunes) {
				return true
			}
		}
	}
	return false
}

func listSearchRunes(value string) []rune {
	var out []rune
	for _, r := range []rune(strings.ToLower(value)) {
		if !unicode.IsSpace(r) {
			out = append(out, r)
		}
	}
	return out
}

// updateListSearch consumes keys while a list search is active. Enter or Tab
// leaves search mode while preserving the result set; Esc clears the query
// and leaves search mode, so a second Esc keeps the normal cancel behavior.
func updateListSearch(query string, searching bool, msg tea.KeyPressMsg) (nextQuery string, nextSearching, handled bool) {
	key := tuiKeyName(msg)
	if key == "/" && !searching {
		return query, true, true
	}
	if !searching {
		return query, false, false
	}

	switch key {
	case "esc":
		return "", false, true
	case "enter", "tab":
		return query, false, true
	case "backspace", "ctrl+h":
		return string(dropLastRune([]rune(query))), true, true
	case "ctrl+u":
		return "", true, true
	}
	// v2 populates Text only for keys that represent printable character(s)
	// (see tea.Key's doc comment) — the direct equivalent of v1's
	// Type == tea.KeyRunes check, and (per the migration spec's
	// "Keyboard Migration" requirements) still correctly consumes a
	// multi-rune Text in one message, exactly like v1's []rune Runes did.
	if msg.Text != "" {
		return query + msg.Text, true, true
	}
	return query, true, false
}

func dropLastRune(value []rune) []rune {
	if len(value) == 0 {
		return value
	}
	return value[:len(value)-1]
}

func listSearchHint(query string, searching bool) string {
	switch {
	case searching:
		return "搜尋：" + query + "（enter/tab 套用　esc 清除）"
	case query != "":
		return "搜尋：" + query + "（/ 修改　esc 清除）"
	default:
		return "搜尋：按 / 開始"
	}
}
