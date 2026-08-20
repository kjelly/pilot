package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func rolesSpec() MultiSelectSpec {
	return MultiSelectSpec{
		ScreenID: "roles.checklist",
		Title:    "Pick roles",
		Choices: []MultiSelectChoice{
			{Choice: Choice{ID: "freeipa", Label: "FreeIPA", Description: "identity server"}},
			{Choice: Choice{ID: "docker", Label: "Docker", Description: "container runtime"}, Checked: true},
			{Choice: Choice{ID: "wazuh", Label: "Wazuh", Description: "security monitoring"}},
		},
	}
}

func TestHuhMultiSelectInitialCheckedState(t *testing.T) {
	m := NewHuhMultiSelect(rolesSpec())
	m.Init()
	if got := m.CheckedIDs(); !equalStrings(got, []string{"docker"}) {
		t.Fatalf("CheckedIDs=%v want [docker]", got)
	}
	if got := m.CheckedLabels(); !equalStrings(got, []string{"Docker"}) {
		t.Fatalf("CheckedLabels=%v want [Docker]", got)
	}
	st := m.AutomationState()
	if !equalStrings(checkedIDsOf(st), []string{"docker"}) {
		t.Fatalf("AutomationState checked=%v want [docker]", checkedIDsOf(st))
	}
	if st.Kind != ScreenMultiSelect || st.ScreenID != "roles.checklist" {
		t.Fatalf("unexpected snapshot header: %+v", st)
	}
	// huh parks the cursor on the first pre-checked option rather than
	// on row 0; automation reads FocusedIndex to know how far to move.
	if st.FocusedIndex != 1 {
		t.Fatalf("FocusedIndex=%d want 1 (the first pre-checked row)", st.FocusedIndex)
	}
}

func TestHuhMultiSelectToggleOnAndOff(t *testing.T) {
	m := NewHuhMultiSelect(rolesSpec())
	m.Init()
	// Park on the first row, then check it.
	send(t, m, keyUp)
	send(t, m, keyUp)
	send(t, m, keySpace)
	if got := m.CheckedIDs(); !equalStrings(got, []string{"freeipa", "docker"}) {
		t.Fatalf("CheckedIDs=%v want [freeipa docker]", got)
	}
	// Toggling the same row off again.
	send(t, m, keySpace)
	if got := m.CheckedIDs(); !equalStrings(got, []string{"docker"}) {
		t.Fatalf("CheckedIDs=%v want [docker]", got)
	}
}

func TestHuhMultiSelectMultipleValuesCommit(t *testing.T) {
	m := NewHuhMultiSelect(rolesSpec())
	m.Init()
	send(t, m, keyUp)
	send(t, m, keyUp) // first row
	send(t, m, keySpace)
	send(t, m, keyDown)
	send(t, m, keyDown) // third row
	send(t, m, keySpace)

	cmd := send(t, m, keyEnter)
	if !m.Finished() || m.Canceled() {
		t.Fatalf("finished=%v canceled=%v", m.Finished(), m.Canceled())
	}
	if cmd != nil {
		t.Fatalf("enter returned a command; huh's field-advance cascade must be swallowed")
	}
	if got := m.CheckedIDs(); !equalStrings(got, []string{"freeipa", "docker", "wazuh"}) {
		t.Fatalf("CheckedIDs=%v want all three in spec order", got)
	}
	if got := m.CheckedLabels(); !equalStrings(got, []string{"FreeIPA", "Docker", "Wazuh"}) {
		t.Fatalf("CheckedLabels=%v", got)
	}
}

func TestHuhMultiSelectZeroValuesIsLegal(t *testing.T) {
	spec := rolesSpec()
	spec.Choices[1].Checked = false
	m := NewHuhMultiSelect(spec)
	m.Init()
	if got := m.CheckedIDs(); got != nil {
		t.Fatalf("CheckedIDs=%v want nil before any toggle", got)
	}
	send(t, m, keyEnter)
	if !m.Finished() || m.Canceled() {
		t.Fatalf("finished=%v canceled=%v; zero selected must be a legal answer", m.Finished(), m.Canceled())
	}
	if got := m.CheckedIDs(); got != nil {
		t.Fatalf("CheckedIDs=%v want nil", got)
	}
}

// An empty *source* list is a legal answer for an optional checklist —
// and huh's MultiSelect already commits it natively (unlike its Select,
// which refuses Return with nothing to select), so this needs no
// adapter intervention beyond mirroring the hand-written screens'
// guard.
func TestHuhMultiSelectEmptySourceListCommits(t *testing.T) {
	m := NewHuhMultiSelect(MultiSelectSpec{ScreenID: "cmdgroups.checklist", Title: "Command groups"})
	m.Init()
	send(t, m, keyEnter)
	if !m.Finished() || m.Canceled() {
		t.Fatalf("finished=%v canceled=%v; an empty optional checklist must commit", m.Finished(), m.Canceled())
	}
	if got := m.CheckedIDs(); got != nil {
		t.Fatalf("CheckedIDs=%v want nil", got)
	}
	st := m.AutomationState()
	if len(st.Items) != 0 || st.FocusedIndex != -1 {
		t.Fatalf("AutomationState=%+v want no items and FocusedIndex -1", st)
	}
}

func TestHuhMultiSelectFilterPreservesCheckedState(t *testing.T) {
	m := NewHuhMultiSelect(rolesSpec())
	m.Init()

	send(t, m, keySlash)
	typeText(t, m, "Wazuh")
	st := m.AutomationState()
	if !equalStrings(itemIDs(st), []string{"wazuh"}) {
		t.Fatalf("filtered IDs=%v want [wazuh]", itemIDs(st))
	}
	if !st.FilterActive {
		t.Fatalf("FilterActive=false while filtering")
	}
	// The row hidden by the filter keeps its checked state, and the
	// canonical checked set still reports it.
	if got := m.CheckedIDs(); !equalStrings(got, []string{"docker"}) {
		t.Fatalf("CheckedIDs=%v while filtered; want the hidden [docker] preserved", got)
	}

	// Leave filter capture (huh binds enter as well as esc to that for
	// MultiSelect) and toggle the one visible row.
	send(t, m, keyEsc)
	send(t, m, keySpace)
	if got := m.CheckedIDs(); !equalStrings(got, []string{"docker", "wazuh"}) {
		t.Fatalf("CheckedIDs=%v want [docker wazuh]", got)
	}

	// Clearing the filter restores every row with checked state intact.
	send(t, m, keyEsc)
	st = m.AutomationState()
	if !equalStrings(itemIDs(st), []string{"freeipa", "docker", "wazuh"}) {
		t.Fatalf("after clear filter IDs=%v", itemIDs(st))
	}
	if !equalStrings(checkedIDsOf(st), []string{"docker", "wazuh"}) {
		t.Fatalf("after clear filter checked=%v", checkedIDsOf(st))
	}
	if st.FilterActive {
		t.Fatalf("FilterActive=true after the query was cleared")
	}
}

func TestHuhMultiSelectFilterMatchesDescriptionButNotIdentity(t *testing.T) {
	m := NewHuhMultiSelect(rolesSpec())
	m.Init()
	// "security monitoring" only appears in Wazuh's description.
	send(t, m, keySlash)
	typeText(t, m, "security")
	st := m.AutomationState()
	if !equalStrings(itemIDs(st), []string{"wazuh"}) {
		t.Fatalf("filtered IDs=%v want [wazuh]", itemIDs(st))
	}
	if st.Items[0].Label != "Wazuh" || st.Items[0].Description != "security monitoring" {
		t.Fatalf("folding the description into the rendered row changed the item: %+v", st.Items[0])
	}
	if !strings.Contains(m.View().Content, "security monitoring") {
		t.Fatalf("description not rendered")
	}
}

func TestHuhMultiSelectFilterZeroResultEnterDoesNotCommit(t *testing.T) {
	m := NewHuhMultiSelect(rolesSpec())
	m.Init()
	send(t, m, keySlash)
	typeText(t, m, "zzz")
	if got := len(m.AutomationState().Items); got != 0 {
		t.Fatalf("zero-result filter still shows %d items", got)
	}
	send(t, m, keyEnter)
	if m.Finished() {
		t.Fatalf("enter on a zero-result filter committed a typo")
	}
	// huh drops a query that matched nothing when it leaves filter
	// capture, so the full list is back and a second enter commits.
	st := m.AutomationState()
	if !equalStrings(itemIDs(st), []string{"freeipa", "docker", "wazuh"}) {
		t.Fatalf("after leaving a zero-result filter: IDs=%v", itemIDs(st))
	}
	if st.FilterActive {
		t.Fatalf("FilterActive=true after a zero-result query was dropped")
	}
	send(t, m, keyEnter)
	if !m.Finished() {
		t.Fatalf("second enter did not commit")
	}
}

// ctrl+a is huh's select-all/select-none. It rewrites the bound
// accessor wholesale, which is the path the canonical checked set is
// read back from, so it is worth proving the adapter stays in sync.
func TestHuhMultiSelectSelectAllAndNone(t *testing.T) {
	m := NewHuhMultiSelect(rolesSpec())
	m.Init()
	send(t, m, tea.KeyPressMsg{Code: 'a', Mod: tea.ModCtrl})
	if got := m.CheckedIDs(); !equalStrings(got, []string{"freeipa", "docker", "wazuh"}) {
		t.Fatalf("after select-all: CheckedIDs=%v", got)
	}
	if got := checkedIDsOf(m.AutomationState()); !equalStrings(got, []string{"freeipa", "docker", "wazuh"}) {
		t.Fatalf("after select-all: snapshot checked=%v", got)
	}
	send(t, m, tea.KeyPressMsg{Code: 'a', Mod: tea.ModCtrl})
	if got := m.CheckedIDs(); got != nil {
		t.Fatalf("after select-none: CheckedIDs=%v want nil", got)
	}
}

func TestHuhMultiSelectEscCancels(t *testing.T) {
	m := NewHuhMultiSelect(rolesSpec())
	m.Init()
	cmd := send(t, m, keyEsc)
	if !m.Finished() || !m.Canceled() {
		t.Fatalf("finished=%v canceled=%v, want both true", m.Finished(), m.Canceled())
	}
	if cmd != nil {
		t.Fatalf("esc returned a command")
	}
}

func TestHuhMultiSelectCtrlCCancels(t *testing.T) {
	m := NewHuhMultiSelect(rolesSpec())
	m.Init()
	cmd := send(t, m, keyCtrlC)
	if !m.Finished() || !m.Canceled() {
		t.Fatalf("finished=%v canceled=%v, want both true", m.Finished(), m.Canceled())
	}
	if cmd != nil {
		t.Fatalf("ctrl+c returned a command")
	}
}

// Two rows may share a display string while being distinct Pilot items.
// huh toggles MultiSelect options by comparing Option.Key, so the
// adapter has to keep those keys distinct or both rows would check
// together.
func TestHuhMultiSelectDuplicateLabelsToggleIndependently(t *testing.T) {
	m := NewHuhMultiSelect(MultiSelectSpec{
		Title: "Same label twice",
		Choices: []MultiSelectChoice{
			{Choice: Choice{ID: "first", Label: "web"}},
			{Choice: Choice{ID: "second", Label: "web"}},
		},
	})
	m.Init()
	send(t, m, keySpace)
	if got := m.CheckedIDs(); !equalStrings(got, []string{"first"}) {
		t.Fatalf("CheckedIDs=%v want only [first]", got)
	}
	send(t, m, keyDown)
	send(t, m, keySpace)
	if got := m.CheckedIDs(); !equalStrings(got, []string{"first", "second"}) {
		t.Fatalf("CheckedIDs=%v want [first second]", got)
	}
	send(t, m, keySpace)
	if got := m.CheckedIDs(); !equalStrings(got, []string{"first"}) {
		t.Fatalf("CheckedIDs=%v want [first] after untoggling the second row", got)
	}
}

func TestHuhMultiSelectChineseAndEmojiLabels(t *testing.T) {
	m := NewHuhMultiSelect(MultiSelectSpec{
		ScreenID: "roles.i18n",
		Title:    "角色清單",
		Choices: []MultiSelectChoice{
			{Choice: Choice{ID: "ipa", Label: "身分服務 🔐", Description: "FreeIPA 伺服器"}},
			{Choice: Choice{ID: "mon", Label: "監控 📈", Description: "Prometheus"}},
		},
	})
	m.Init()
	send(t, m, keySlash)
	typeText(t, m, "監控")
	if got := itemIDs(m.AutomationState()); !equalStrings(got, []string{"mon"}) {
		t.Fatalf("filtered IDs=%v want [mon]", got)
	}
	send(t, m, keyEsc)
	send(t, m, keySpace)
	send(t, m, keyEsc) // clear filter
	send(t, m, keyEnter)
	if !m.Finished() || m.Canceled() {
		t.Fatalf("finished=%v canceled=%v", m.Finished(), m.Canceled())
	}
	if got := m.CheckedIDs(); !equalStrings(got, []string{"mon"}) {
		t.Fatalf("CheckedIDs=%v want [mon]", got)
	}
	if got := m.CheckedLabels(); !equalStrings(got, []string{"監控 📈"}) {
		t.Fatalf("CheckedLabels=%v", got)
	}
}

func TestHuhMultiSelectFinishedScreenIgnoresFurtherKeys(t *testing.T) {
	m := NewHuhMultiSelect(rolesSpec())
	m.Init()
	send(t, m, keyEnter)
	before := m.CheckedIDs()
	sendKeys(t, m, keySpace, keyDown, keySpace, keyEsc)
	if m.Canceled() {
		t.Fatalf("a committed checklist was retroactively canceled")
	}
	if got := m.CheckedIDs(); !equalStrings(got, before) {
		t.Fatalf("CheckedIDs changed after commit: %v -> %v", before, got)
	}
}
