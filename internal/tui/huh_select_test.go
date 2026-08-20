package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestHuhSelectChooseFirstMiddleLast(t *testing.T) {
	for _, tc := range []struct {
		name    string
		presses []tea.KeyPressMsg
		wantID  string
		wantIdx int
	}{
		{"first", nil, "a", 0},
		{"middle", []tea.KeyPressMsg{keyDown}, "b", 1},
		{"last", []tea.KeyPressMsg{keyDown, keyDown}, "g", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewHuhSelect(fruitSpec())
			s.Init()
			sendKeys(t, s, tc.presses...)
			if s.Finished() {
				t.Fatalf("screen finished before enter")
			}
			send(t, s, keyEnter)
			if !s.Finished() || s.Canceled() {
				t.Fatalf("finished=%v canceled=%v, want finished and not canceled", s.Finished(), s.Canceled())
			}
			if got := s.SelectedID(); got != tc.wantID {
				t.Fatalf("SelectedID=%q want %q", got, tc.wantID)
			}
			if got := s.Selected(); got != tc.wantIdx {
				t.Fatalf("Selected=%d want %d", got, tc.wantIdx)
			}
		})
	}
}

// Enter must resolve the screen inside the single Update that handled
// it, and must not hand the router any command: huh completes a form
// through a nextField -> nextGroup command cascade, and the router
// forwards every message to whatever screen is current, so a surviving
// cascade command would be delivered to the *next* screen's form and
// complete it with no user input at all.
func TestHuhSelectEnterFinishesSynchronouslyAndLeaksNoCommand(t *testing.T) {
	s := NewHuhSelect(fruitSpec())
	s.Init()
	cmd := send(t, s, keyEnter)
	if !s.Finished() {
		t.Fatalf("Finished()=false immediately after enter; adapter must not defer completion to a command cascade")
	}
	if cmd != nil {
		t.Fatalf("enter returned a non-nil command; huh's field-advance cascade must be swallowed")
	}
}

func TestHuhSelectUpDownWrapAround(t *testing.T) {
	s := NewHuhSelect(fruitSpec())
	s.Init()
	// Up from the first item wraps to the last.
	send(t, s, keyUp)
	if got := s.SelectedID(); got != "g" {
		t.Fatalf("after up from first: SelectedID=%q want %q", got, "g")
	}
	// Down from the last wraps back to the first.
	send(t, s, keyDown)
	if got := s.SelectedID(); got != "a" {
		t.Fatalf("after down from last: SelectedID=%q want %q", got, "a")
	}
	// j/k navigate too.
	sendKeys(t, s, runeKey('j'), runeKey('j'))
	if got := s.SelectedID(); got != "g" {
		t.Fatalf("after jj: SelectedID=%q want %q", got, "g")
	}
	sendKeys(t, s, runeKey('k'))
	if got := s.SelectedID(); got != "b" {
		t.Fatalf("after k: SelectedID=%q want %q", got, "b")
	}
}

func TestHuhSelectFilterNarrowsAutomationItems(t *testing.T) {
	s := NewHuhSelect(fruitSpec())
	s.Init()
	if st := s.AutomationState(); st.FilterActive {
		t.Fatalf("FilterActive=true before any filter key")
	}
	send(t, s, keySlash)
	typeText(t, s, "Bet")

	st := s.AutomationState()
	if !st.FilterActive {
		t.Fatalf("FilterActive=false while filtering")
	}
	if !equalStrings(itemIDs(st), []string{"b"}) {
		t.Fatalf("filtered item IDs=%v want [b]", itemIDs(st))
	}
	if st.FocusedIndex != 0 {
		t.Fatalf("FocusedIndex=%d want 0", st.FocusedIndex)
	}
	// The filter must never rewrite an item's machine identity.
	if st.Items[0].Label != "Beta" {
		t.Fatalf("filtered label=%q want Beta", st.Items[0].Label)
	}
}

func TestHuhSelectFilterNoResultKeepsEnterInert(t *testing.T) {
	s := NewHuhSelect(fruitSpec())
	s.Init()
	send(t, s, keySlash)
	typeText(t, s, "zzz")

	st := s.AutomationState()
	if len(st.Items) != 0 {
		t.Fatalf("zero-result filter still shows %d items", len(st.Items))
	}
	if st.FocusedIndex != -1 {
		t.Fatalf("FocusedIndex=%d want -1 with nothing visible", st.FocusedIndex)
	}
	send(t, s, keyEnter)
	if s.Finished() {
		t.Fatalf("enter on a zero-result filter fabricated a selection")
	}
}

func TestHuhSelectClearFilterRestoresEveryItem(t *testing.T) {
	s := NewHuhSelect(fruitSpec())
	s.Init()
	send(t, s, keySlash)
	typeText(t, s, "Bet")
	if got := len(s.AutomationState().Items); got != 1 {
		t.Fatalf("filtered item count=%d want 1", got)
	}

	// Huh clears a filter in two steps: leave filter-capture mode, then
	// drop the query. Neither step may cancel the screen.
	send(t, s, keyEsc)
	if s.Finished() {
		t.Fatalf("first esc while filtering canceled the screen")
	}
	if got := len(s.AutomationState().Items); got != 1 {
		t.Fatalf("after leaving filter capture: item count=%d want the query still applied (1)", got)
	}

	send(t, s, keyEsc)
	if s.Finished() {
		t.Fatalf("second esc (clear filter) canceled the screen")
	}
	st := s.AutomationState()
	if !equalStrings(itemIDs(st), []string{"a", "b", "g"}) {
		t.Fatalf("after clear filter: IDs=%v want all three", itemIDs(st))
	}
	if st.FilterActive {
		t.Fatalf("FilterActive=true after the query was cleared")
	}

	// Only now, with no filter left, does esc cancel.
	send(t, s, keyEsc)
	if !s.Finished() || !s.Canceled() {
		t.Fatalf("clean esc: finished=%v canceled=%v, want both true", s.Finished(), s.Canceled())
	}
}

func TestHuhSelectFilterThenSelectMapsStableID(t *testing.T) {
	s := NewHuhSelect(fruitSpec())
	s.Init()
	send(t, s, keySlash)
	typeText(t, s, "amm") // matches only "Gamma"
	send(t, s, keyEsc)    // leave filter capture, query still applied
	send(t, s, keyEnter)

	if !s.Finished() || s.Canceled() {
		t.Fatalf("finished=%v canceled=%v", s.Finished(), s.Canceled())
	}
	if got := s.SelectedID(); got != "g" {
		t.Fatalf("SelectedID=%q want %q", got, "g")
	}
	if got := s.Selected(); got != 2 {
		t.Fatalf("Selected=%d want the original-choice index 2", got)
	}
}

// While a search is being typed, Return commits the search rather than
// the row — the same behavior updateListSearch gives the hand-written
// screens.
func TestHuhSelectEnterWhileFilteringOnlyLeavesFilterMode(t *testing.T) {
	s := NewHuhSelect(fruitSpec())
	s.Init()
	send(t, s, keySlash)
	typeText(t, s, "Bet")
	send(t, s, keyEnter)
	if s.Finished() {
		t.Fatalf("enter while filtering selected a row instead of committing the search")
	}
	if st := s.AutomationState(); !equalStrings(itemIDs(st), []string{"b"}) {
		t.Fatalf("query lost after enter: IDs=%v want [b]", itemIDs(st))
	}
	send(t, s, keyEnter)
	if !s.Finished() || s.SelectedID() != "b" {
		t.Fatalf("second enter: finished=%v id=%q", s.Finished(), s.SelectedID())
	}
}

func TestHuhSelectBackspaceEditsFilterQuery(t *testing.T) {
	s := NewHuhSelect(fruitSpec())
	s.Init()
	send(t, s, keySlash)
	typeText(t, s, "Bex")
	if got := len(s.AutomationState().Items); got != 0 {
		t.Fatalf("item count=%d want 0 for query 'Bex'", got)
	}
	send(t, s, keyBackspce)
	if got := itemIDs(s.AutomationState()); !equalStrings(got, []string{"b"}) {
		t.Fatalf("after backspace: IDs=%v want [b]", got)
	}
	send(t, s, keyBackspce)
	send(t, s, keyBackspce)
	st := s.AutomationState()
	if !equalStrings(itemIDs(st), []string{"a", "b", "g"}) {
		t.Fatalf("after emptying the query: IDs=%v want all three", itemIDs(st))
	}
	if !st.FilterActive {
		t.Fatalf("FilterActive=false while still capturing filter keystrokes")
	}
}

func TestHuhSelectEmptyListEnterDoesNotFinish(t *testing.T) {
	s := NewHuhSelect(SelectSpec{ScreenID: "empty.list", Title: "Nothing here"})
	s.Init()
	send(t, s, keyEnter)
	if s.Finished() {
		t.Fatalf("enter on an empty source list fabricated a selection")
	}
	if got := s.SelectedID(); got != "" {
		t.Fatalf("SelectedID=%q want empty", got)
	}
	if got := s.Selected(); got != -1 {
		t.Fatalf("Selected=%d want -1", got)
	}
	st := s.AutomationState()
	if len(st.Items) != 0 || st.FocusedIndex != -1 {
		t.Fatalf("AutomationState=%+v want no items and FocusedIndex -1", st)
	}
}

func TestHuhSelectEscCancels(t *testing.T) {
	s := NewHuhSelect(fruitSpec())
	s.Init()
	cmd := send(t, s, keyEsc)
	if !s.Finished() || !s.Canceled() {
		t.Fatalf("finished=%v canceled=%v, want both true", s.Finished(), s.Canceled())
	}
	if cmd != nil {
		t.Fatalf("esc returned a command; cancel must stay entirely inside the adapter")
	}
}

func TestHuhSelectCtrlCCancels(t *testing.T) {
	s := NewHuhSelect(fruitSpec())
	s.Init()
	cmd := send(t, s, keyCtrlC)
	if !s.Finished() || !s.Canceled() {
		t.Fatalf("finished=%v canceled=%v, want both true", s.Finished(), s.Canceled())
	}
	if cmd != nil {
		t.Fatalf("ctrl+c returned a command; huh's abort must not reach the router")
	}
}

func TestHuhSelectFinishedScreenIgnoresFurtherKeys(t *testing.T) {
	s := NewHuhSelect(fruitSpec())
	s.Init()
	send(t, s, keyEnter)
	sendKeys(t, s, keyDown, keyEsc, keyCtrlC)
	if s.Canceled() {
		t.Fatalf("a confirmed screen was retroactively canceled")
	}
	if got := s.SelectedID(); got != "a" {
		t.Fatalf("SelectedID=%q changed after the screen finished", got)
	}
}

func TestHuhSelectResizeLongList(t *testing.T) {
	choices := make([]Choice, 40)
	for i := range choices {
		choices[i] = Choice{ID: string(rune('a'+i%26)) + string(rune('0'+i/26)), Label: "row-" + string(rune('A'+i%26))}
	}
	s := NewHuhSelect(SelectSpec{ScreenID: "long.list", Title: "Long", Choices: choices})
	s.Init()

	send(t, s, tea.WindowSizeMsg{Width: 80, Height: 30})
	large := s.View().Content
	if large == "" {
		t.Fatalf("view empty after resize to 30 rows")
	}
	send(t, s, tea.WindowSizeMsg{Width: 80, Height: 10})
	small := s.View().Content
	if small == "" {
		t.Fatalf("view empty after resize to 10 rows")
	}
	if strings.Count(small, "\n") >= strings.Count(large, "\n") {
		t.Fatalf("shorter terminal did not shrink the rendered list: small=%d large=%d",
			strings.Count(small, "\n"), strings.Count(large, "\n"))
	}
	// Scrolling past the visible window still resolves to the right item.
	for i := 0; i < 39; i++ {
		send(t, s, keyDown)
	}
	send(t, s, keyEnter)
	if got := s.Selected(); got != 39 {
		t.Fatalf("Selected=%d want 39 after scrolling the whole list", got)
	}
	if got, want := s.SelectedID(), choices[39].ID; got != want {
		t.Fatalf("SelectedID=%q want %q", got, want)
	}
}

func TestHuhSelectChineseAndEmojiLabels(t *testing.T) {
	spec := SelectSpec{
		ScreenID: "i18n.list",
		Title:    "選單",
		Choices: []Choice{
			{ID: "host-a", Label: "新增主機 🖥"},
			{ID: "host-b", Label: "刪除主機 🗑"},
			{ID: "host-c", Label: "編輯角色 ⚙️"},
		},
	}
	s := NewHuhSelect(spec)
	s.Init()

	st := s.AutomationState()
	if !equalStrings(itemIDs(st), []string{"host-a", "host-b", "host-c"}) {
		t.Fatalf("IDs=%v", itemIDs(st))
	}
	if st.Items[0].Label != "新增主機 🖥" {
		t.Fatalf("label round-trip failed: %q", st.Items[0].Label)
	}

	// Filtering by a Chinese substring must still resolve to the stable
	// ASCII ID, never to the rendered label.
	send(t, s, keySlash)
	typeText(t, s, "刪除")
	if got := itemIDs(s.AutomationState()); !equalStrings(got, []string{"host-b"}) {
		t.Fatalf("filtered IDs=%v want [host-b]", got)
	}
	send(t, s, keyEsc)
	send(t, s, keyEnter)
	if got := s.SelectedID(); got != "host-b" {
		t.Fatalf("SelectedID=%q want host-b", got)
	}
	if got := s.Selected(); got != 1 {
		t.Fatalf("Selected=%d want 1", got)
	}
}

func TestHuhSelectInitialIDStartsOnThatChoice(t *testing.T) {
	spec := fruitSpec()
	spec.InitialID = "g"
	s := NewHuhSelect(spec)
	s.Init()
	if got := s.SelectedID(); got != "g" {
		t.Fatalf("SelectedID=%q want the InitialID g", got)
	}
	if got := s.AutomationState().FocusedIndex; got != 2 {
		t.Fatalf("FocusedIndex=%d want 2", got)
	}
	send(t, s, keyEnter)
	if got := s.Selected(); got != 2 {
		t.Fatalf("Selected=%d want 2", got)
	}
}

func TestHuhSelectAutomationStateShape(t *testing.T) {
	spec := SelectSpec{
		Title: "Roles",
		Choices: []Choice{
			{ID: "freeipa", Label: "FreeIPA", Description: "identity server"},
			{ID: "docker", Label: "Docker", Description: "container runtime"},
		},
	}
	s := NewHuhSelect(spec)
	s.Init()
	st := s.AutomationState()
	if st.ScreenID != "select" {
		t.Fatalf("ScreenID=%q want the generic fallback %q", st.ScreenID, "select")
	}
	if st.Kind != ScreenSelect {
		t.Fatalf("Kind=%q want %q", st.Kind, ScreenSelect)
	}
	if st.Title != "Roles" {
		t.Fatalf("Title=%q", st.Title)
	}
	if st.Secret || st.HasValue || st.ValidationError != "" {
		t.Fatalf("select screen reported input-only fields: %+v", st)
	}
	if st.Items[0].Description != "identity server" {
		t.Fatalf("Description=%q", st.Items[0].Description)
	}
	// The description is folded into the rendered row but must not
	// become part of the item identity.
	if st.Items[0].ID != "freeipa" || st.Items[0].Label != "FreeIPA" {
		t.Fatalf("description leaked into ID/Label: %+v", st.Items[0])
	}
	if !strings.Contains(s.View().Content, "identity server") {
		t.Fatalf("description not rendered in the view")
	}
}

func TestHuhSelectDuplicateLabelsStayIndependentlyAddressable(t *testing.T) {
	spec := SelectSpec{
		Title: "Same name twice",
		Choices: []Choice{
			{ID: "first", Label: "web"},
			{ID: "second", Label: "web"},
		},
	}
	s := NewHuhSelect(spec)
	s.Init()
	if got := s.SelectedID(); got != "first" {
		t.Fatalf("SelectedID=%q want first", got)
	}
	send(t, s, keyDown)
	if got := s.SelectedID(); got != "second" {
		t.Fatalf("after down: SelectedID=%q want second", got)
	}
	send(t, s, keyEnter)
	if got := s.Selected(); got != 1 {
		t.Fatalf("Selected=%d want 1", got)
	}
}

func TestHuhSelectEmptyChoiceIDsStillNavigable(t *testing.T) {
	// 77 production call sites build select rows with no per-item ID at
	// all; every option value would collide if the ID alone were bound.
	spec := SelectSpec{
		Title:   "No IDs",
		Choices: []Choice{{Label: "one"}, {Label: "two"}, {Label: "three"}},
	}
	s := NewHuhSelect(spec)
	s.Init()
	send(t, s, keyDown)
	send(t, s, keyDown)
	send(t, s, keyEnter)
	if got := s.Selected(); got != 2 {
		t.Fatalf("Selected=%d want 2", got)
	}
}

func TestHuhSelectTabIsInert(t *testing.T) {
	s := NewHuhSelect(fruitSpec())
	s.Init()
	cmd := send(t, s, keyTab)
	if s.Finished() {
		t.Fatalf("tab finished the screen")
	}
	if cmd != nil {
		t.Fatalf("tab returned a command; field-advance must not reach the router")
	}
}
