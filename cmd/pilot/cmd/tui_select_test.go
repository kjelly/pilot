package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

func newManySelectItems(n int) []string {
	items := make([]string, n)
	for i := range items {
		items[i] = fmt.Sprintf("item-%02d", i)
	}
	return items
}

func TestSelectModel_DownMovesCursor(t *testing.T) {
	m := selectModel{title: "t", items: []string{"a", "b", "c"}}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(selectModel)
	if m.cursor != 1 {
		t.Fatalf("cursor = %d, want 1", m.cursor)
	}
}

func TestSelectModel_CursorClampedAtBounds(t *testing.T) {
	m := selectModel{title: "t", items: []string{"a", "b", "c"}}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = next.(selectModel)
	if m.cursor != 0 {
		t.Fatalf("cursor = %d, want 0 (clamped)", m.cursor)
	}
	for i := 0; i < 10; i++ {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = next.(selectModel)
	}
	if m.cursor != 2 {
		t.Fatalf("cursor = %d, want 2 (clamped)", m.cursor)
	}
}

func TestSelectModel_EnterConfirmsWithoutCanceling(t *testing.T) {
	m := selectModel{title: "t", items: []string{"a", "b"}}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(selectModel)
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(selectModel)
	if !m.Finished() || m.Canceled() {
		t.Fatalf("expected finished+not-canceled after enter, got finished=%v canceled=%v", m.Finished(), m.Canceled())
	}
	if m.Selected() != 1 {
		t.Fatalf("Selected() = %d, want 1", m.Selected())
	}
}

func TestSelectModel_EnterOnEmptyListDoesNothing(t *testing.T) {
	m := selectModel{title: "t"}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(selectModel)
	if m.Finished() {
		t.Fatal("enter on an empty list should not finish the screen")
	}
}

func TestSelectModel_EscCancels(t *testing.T) {
	m := selectModel{title: "t", items: []string{"a"}}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(selectModel)
	if !m.Finished() || !m.Canceled() {
		t.Fatal("expected finished+canceled after esc")
	}
}

func TestSelectModel_ViewShowsTitleAndItems(t *testing.T) {
	m := selectModel{title: "選單標題", items: []string{"alpha", "beta"}}
	view := m.View()
	for _, want := range []string{"選單標題", "alpha", "beta", "▸"} {
		if !strings.Contains(view, want) {
			t.Fatalf("view missing %q:\n%s", want, view)
		}
	}
}

func TestSelectModel_ScrollIndicatorReflectsHiddenItems(t *testing.T) {
	m := selectModel{title: "t", items: newManySelectItems(20)}
	next, _ := m.Update(tea.WindowSizeMsg{Height: 10}) // rows = 4
	m = next.(selectModel)
	if !strings.Contains(m.View(), "還有 16 項在下面") {
		t.Fatalf("expected below-indicator for remaining 16 items:\n%s", m.View())
	}
}

func TestNewSelectModel_DumpsMenuUnderDebugEnv(t *testing.T) {
	t.Setenv("PILOT_DEBUG_MENU", "1")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	_ = newSelectModel("dump 測試", []string{"only-item"})
	w.Close()
	os.Stderr = orig

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "only-item") {
		t.Fatalf("expected PILOT_DEBUG_MENU=1 to dump menu items to stderr, got:\n%s", out)
	}
}

func TestSelectModel_Teatest_HappyPath(t *testing.T) {
	m := screenTestHarness{s: selectModel{title: "t", items: []string{"a", "b", "c"}}}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Type("jj") // cursor -> index 2
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	got := final.(screenTestHarness).s.(selectModel)
	if got.Canceled() {
		t.Fatal("enter should not cancel")
	}
	if got.Selected() != 2 {
		t.Fatalf("Selected() = %d, want 2", got.Selected())
	}
}

func TestSelectModel_Teatest_EscCancels(t *testing.T) {
	m := screenTestHarness{s: selectModel{title: "t", items: []string{"a", "b"}}}
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	got := final.(screenTestHarness).s.(selectModel)
	if !got.Canceled() {
		t.Fatal("expected canceled after esc")
	}
}
