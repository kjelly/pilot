// huh_common.go holds the pieces every Huh v2-backed screen in this
// package shares: the huh.Model <-> tea.Model bridge, Pilot's key-name
// normalization, the machine-facing option value type, display-key
// construction, and the filter mirror the list screens report their
// AutomationState from.
//
// Why a bridge is needed at all: neither *huh.Form nor any huh.Field
// implements tea.Model. huh.Model is a public alias for huh's own
// bubbletea-v1-shaped interface — Update returns (huh.Model, tea.Cmd)
// and View returns string, not (tea.Model, tea.Cmd) / tea.View. huh's
// own compat.ViewModel adapter is in an internal package and cannot be
// imported, so each Pilot screen below owns the ~10 lines that re-wrap
// the result of huh's Update and lift its string View into a tea.View.
package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	huh "charm.land/huh/v2"
)

// choiceValue is the machine-facing value bound to every Huh option
// this package builds. It carries the caller's stable Pilot ID (Core
// Invariant 5 — never the human label), plus the choice's position in
// the original spec so a Huh selection maps back to an original-choice
// index for the transitional index-keyed callers SelectScreen.Selected
// exists for.
//
// Index is part of the value (rather than derived from the ID) because
// Pilot's existing call sites are allowed to leave Choice.ID empty or
// duplicated — 77 production selectModel call sites do exactly that
// today. Huh matches options by value equality, so an all-empty-ID
// option set would be ambiguous; pairing the ID with the index keeps
// every option value distinct without inventing a synthetic identity
// that automation would then see instead of the real Pilot ID.
type choiceValue struct {
	Index int
	ID    string
}

// huhKeyName normalizes a key press to the same names Pilot's
// hand-written screens use (see tuiKeyName in cmd/pilot/cmd/tui_screen.go):
// Return may arrive as CR or as Ctrl-J depending on the PTY/tmux layer,
// and Bubble Tea v2 no longer unifies Ctrl+[ with Esc. The duplication
// is deliberate — internal/tui must not import cmd/pilot/cmd (that is
// the dependency direction the whole migration exists to remove).
func huhKeyName(msg tea.KeyPressMsg) string {
	switch {
	case msg.Code == tea.KeyEnter, msg.Code == 'j' && msg.Mod == tea.ModCtrl:
		return "enter"
	case msg.Code == tea.KeyEsc:
		return "esc"
	case msg.Code == 'c' && msg.Mod == tea.ModCtrl:
		return "ctrl+c"
	}
	switch msg.String() {
	case "\r", "\n":
		return "enter"
	case "\x1b", "ctrl+[":
		return "esc"
	default:
		return msg.String()
	}
}

// Canonical key presses forwarded to Huh in place of the raw message
// when Pilot normalized the key first. Forwarding the raw message would
// mean handing Huh a Ctrl-J that Pilot already decided means Return —
// and Huh's Select keymap binds Ctrl-J to "move down".
var (
	huhEnterKey = tea.KeyPressMsg{Code: tea.KeyEnter}
	huhEscKey   = tea.KeyPressMsg{Code: tea.KeyEsc}
)

// huhOptionKey builds the string Huh displays for one option.
//
// Design decision — per-option Description handling: huh.Option[T] has
// only Key (display) and Value (machine identity); there is no
// per-option Description field. Pilot folds Description into the
// displayed Key instead of surfacing it through Select.DescriptionFunc
// (which can only ever show the *hovered* row's description, as a
// single line above the list). Folding is chosen because:
//
//   - it reproduces what multiSelectModel renders today — label,
//     padded, then description on the same row, for every row at once —
//     so the migration is not a visible regression;
//   - Huh filters on Option.Key, and multiSelectModel filters on
//     "Label + Description", so folding keeps filter semantics matching
//     as well as rendering; and
//   - AutomationState still reports ID / Label / Description as three
//     separate fields, so the machine-facing contract is unaffected by
//     how the row happens to be drawn (Core Invariant 5).
func huhOptionKey(label, description string) string {
	if description == "" {
		return label
	}
	const labelColumn = 24
	pad := labelColumn - len([]rune(label))
	if pad < 1 {
		pad = 1
	}
	return label + strings.Repeat(" ", pad) + description
}

// huhUniqueKeys makes every display key distinct by padding duplicates
// with trailing spaces (invisible in a terminal list, and irrelevant to
// Huh's substring filter unless the user types trailing spaces).
//
// This is load-bearing, not cosmetic: huh's MultiSelect toggles options
// by comparing Option.Key, so two rows sharing a display string would
// toggle together even though Pilot considers them distinct items with
// distinct IDs. Distinct IDs must stay independently checkable.
func huhUniqueKeys(keys []string) []string {
	seen := make(map[string]bool, len(keys))
	out := make([]string, len(keys))
	for i, k := range keys {
		candidate := k
		for seen[candidate] {
			candidate += " "
		}
		seen[candidate] = true
		out[i] = candidate
	}
	return out
}

// huhListFilter mirrors the filter query a Huh Select/MultiSelect holds
// in its unexported textinput.
//
// Huh exposes GetFiltering() (is the filter capturing keystrokes?) but
// neither the query text nor the resulting visible option subset. Both
// are needed for AutomationState: Items must be the currently visible
// result set and FocusedIndex an offset into it, because that is what
// automation counts Up/Down presses against. Rather than reflecting
// into Huh's unexported state (explicitly forbidden by the migration
// spec) Pilot mirrors the query as keys are forwarded, and reproduces
// Huh's own filter predicate — case-insensitive substring over the
// option's display key.
//
// The mirror is self-checking in practice: FocusedIndex is derived by
// locating the field's Hovered() value inside the mirrored subset, so a
// drifted mirror surfaces as a missing hover rather than a silently
// wrong index.
type huhListFilter struct {
	// keys are the display keys Huh filters against, in original spec
	// order.
	keys []string
	// query mirrors Huh's filter textinput contents.
	query string
}

// matches returns the indices, in original spec order, of the options
// currently visible under the mirrored query.
func (f *huhListFilter) matches() []int {
	out := make([]int, 0, len(f.keys))
	if f.query == "" {
		for i := range f.keys {
			out = append(out, i)
		}
		return out
	}
	needle := strings.ToLower(f.query)
	for i, k := range f.keys {
		if strings.Contains(strings.ToLower(k), needle) {
			out = append(out, i)
		}
	}
	return out
}

// applyKey advances the mirrored query for one key press, and must be
// called before the key is forwarded to Huh (Huh's "esc on a
// zero-result filter also clears the query" branch inspects the
// pre-key result set).
//
// filtering is the field's GetFiltering() as observed before
// forwarding. enterSetsFilter reports whether this field's keymap binds
// Return to "set filter" while filtering — huh's MultiSelect does
// (Return leaves filter-capture mode), huh's Select does not.
func (f *huhListFilter) applyKey(name string, msg tea.KeyPressMsg, filtering, enterSetsFilter bool) {
	if !filtering {
		// Only reached for an Esc the screen decided to forward, i.e.
		// one with a query left to clear (huh's ClearFilter binding).
		if name == "esc" {
			f.query = ""
		}
		return
	}
	switch name {
	case "esc":
		// huh clears a query that matched nothing before leaving
		// filter-capture mode; otherwise the query survives.
		if len(f.matches()) == 0 {
			f.query = ""
		}
	case "enter":
		if enterSetsFilter && len(f.matches()) == 0 {
			f.query = ""
		}
	case "backspace", "ctrl+h":
		f.query = dropLastRune(f.query)
	case "ctrl+u":
		f.query = ""
	default:
		// Bubble Tea v2 populates Text only for key presses that
		// represent printable character(s) — the same test Pilot's
		// hand-written updateListSearch uses, and it still consumes a
		// multi-rune Text in one message.
		if msg.Text != "" {
			f.query += msg.Text
		}
	}
}

func dropLastRune(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return ""
	}
	return string(r[:len(r)-1])
}

// huhFormBridge is the huh.Model -> tea.Model adapter every screen in
// this package embeds. Huh's Update returns huh.Model, so the concrete
// *huh.Form has to be recovered on every call; View returns a string,
// so it has to be lifted into a tea.View.
type huhFormBridge struct {
	form *huh.Form
}

// update forwards one message to the wrapped Form and re-establishes
// the concrete type. The returned tea.Cmd is handed back to the caller,
// which decides whether it is safe to surface to the router — see
// each screen's Update for why field-advance commands are swallowed.
func (b *huhFormBridge) update(msg tea.Msg) tea.Cmd {
	m, cmd := b.form.Update(msg)
	if f, ok := m.(*huh.Form); ok {
		b.form = f
	}
	return cmd
}

func (b *huhFormBridge) view() tea.View {
	return tea.NewView(b.form.View())
}

// screenIDOr returns the caller-supplied screen ID, or the generic
// per-kind fallback the hand-written primitives report when a call site
// did not name the screen.
func screenIDOr(id, fallback string) string {
	if id != "" {
		return id
	}
	return fallback
}
