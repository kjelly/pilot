package cmd

import "testing"

func TestListVisibleRows_FallsBackWhenHeightUnknown(t *testing.T) {
	if got := listVisibleRows(20, 0); got != 15 {
		t.Fatalf("listVisibleRows(20, 0) = %d, want 15 (fallback default)", got)
	}
}

func TestListVisibleRows_ComputedFromHeight(t *testing.T) {
	if got := listVisibleRows(20, 10); got != 4 { // listChromeLines=6 -> 10-6=4
		t.Fatalf("listVisibleRows(20, 10) = %d, want 4", got)
	}
}

func TestListVisibleRows_NeverExceedsItemCount(t *testing.T) {
	if got := listVisibleRows(3, 100); got != 3 {
		t.Fatalf("listVisibleRows(3, 100) = %d, want 3", got)
	}
}

func TestListVisibleRows_HasAFloorOnTinyTerminals(t *testing.T) {
	if got := listVisibleRows(20, 1); got != 3 { // 1-6 would be negative without the floor
		t.Fatalf("listVisibleRows(20, 1) = %d, want the 3-row floor", got)
	}
}

func TestListClampWindow_FollowsCursorPastBottom(t *testing.T) {
	windowStart := 0
	for cursor := 0; cursor <= 6; cursor++ {
		windowStart = listClampWindow(cursor, windowStart, 20, 10) // rows=4
	}
	if 6 < windowStart || 6 >= windowStart+listVisibleRows(20, 10) {
		t.Fatalf("cursor 6 fell outside window [%d, %d)", windowStart, windowStart+listVisibleRows(20, 10))
	}
	if windowStart == 0 {
		t.Fatal("expected the window to have scrolled down from the top")
	}
}

func TestListClampWindow_ScrollsBackUpToZero(t *testing.T) {
	windowStart := 0
	cursor := 0
	for cursor < 10 {
		cursor++
		windowStart = listClampWindow(cursor, windowStart, 20, 10)
	}
	for cursor > 0 {
		cursor--
		windowStart = listClampWindow(cursor, windowStart, 20, 10)
	}
	if windowStart != 0 {
		t.Fatalf("windowStart = %d, want 0 after scrolling all the way back up", windowStart)
	}
}

func TestListClampWindow_NeverNegative(t *testing.T) {
	if got := listClampWindow(0, 0, 0, 10); got != 0 {
		t.Fatalf("listClampWindow with 0 items = %d, want 0", got)
	}
}
