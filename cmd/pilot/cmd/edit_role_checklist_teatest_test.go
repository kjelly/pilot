// L3 integration tests: drive the full tea.Program loop (not just
// Update in isolation) through teatest, covering multi-step keyboard
// flows, resize while running, and rapid repeated input.
package cmd

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

func TestRoleChecklist_Teatest_HappyPath(t *testing.T) {
	m := newTestChecklist() // dns(unchecked), ntp(checked), docker(unchecked)
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Type("jj") // cursor: dns -> ntp -> docker
	tm.Type(" ")  // toggle docker on
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	got, ok := final.(roleChecklistModel)
	if !ok {
		t.Fatalf("final model = %T, want roleChecklistModel", final)
	}
	if got.canceled {
		t.Fatal("enter should not cancel")
	}
	want := map[string]bool{"dns": false, "ntp": true, "docker": true}
	for _, it := range got.items {
		if it.Checked != want[it.Name] {
			t.Fatalf("item %s: checked = %v, want %v (final items: %+v)", it.Name, it.Checked, want[it.Name], got.items)
		}
	}
}

func TestRoleChecklist_Teatest_ValidationlessInputStillTogglesUnderCursor(t *testing.T) {
	// "typing" past the last item's key must not move the cursor
	// beyond bounds or crash the running program.
	m := newTestChecklist()
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	for i := 0; i < 10; i++ {
		tm.Type("j")
	}
	tm.Type(" ")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	got := final.(roleChecklistModel)
	if !got.items[len(got.items)-1].Checked {
		t.Fatalf("expected the last item to be toggled after cursor clamped at the bottom, got %+v", got.items)
	}
}

func TestRoleChecklist_Teatest_CancelFlow(t *testing.T) {
	m := newTestChecklist()
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Type("j")
	tm.Type(" ") // toggle ntp off — must not survive since we cancel
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	got := final.(roleChecklistModel)
	if !got.canceled {
		t.Fatal("esc should set canceled")
	}
}

func TestRoleChecklist_Teatest_ResizeMidSessionUpdatesVisibleWindow(t *testing.T) {
	m := newManyItemChecklist(20)
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	// Shrink the terminal after the program is already running.
	tm.Send(tea.WindowSizeMsg{Height: 10, Width: 50}) // rows = 4

	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return strings.Contains(string(b), "還有 16 項在下面")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))

	for i := 0; i < 6; i++ {
		tm.Type("j")
	}
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return strings.Contains(string(b), "在上面")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	got := final.(roleChecklistModel)
	if !got.canceled {
		t.Fatal("expected a clean cancel after resize + navigation")
	}
}

func TestRoleChecklist_Teatest_RapidKeysDoNotPanicAndProgramExitsInTime(t *testing.T) {
	m := newManyItemChecklist(20)
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	// Alternate direction rapidly, including spaces, then quit — this
	// must neither panic nor hang the program.
	for i := 0; i < 40; i++ {
		if i%7 == 0 {
			tm.Type(" ")
			continue
		}
		if i%2 == 0 {
			tm.Type("j")
		} else {
			tm.Type("k")
		}
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}
