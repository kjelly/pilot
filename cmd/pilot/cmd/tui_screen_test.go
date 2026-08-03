package cmd

import (
	"reflect"
	"testing"
)

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

func TestListMoveCursorWrapsAndHandlesEmptyLists(t *testing.T) {
	tests := []struct {
		name      string
		cursor    int
		itemCount int
		delta     int
		want      int
	}{
		{name: "up from first wraps to last", cursor: 0, itemCount: 3, delta: -1, want: 2},
		{name: "down from last wraps to first", cursor: 2, itemCount: 3, delta: 1, want: 0},
		{name: "empty list remains at zero", cursor: 0, itemCount: 0, delta: -1, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := listMoveCursor(tt.cursor, tt.itemCount, tt.delta); got != tt.want {
				t.Fatalf("listMoveCursor(%d, %d, %d) = %d, want %d", tt.cursor, tt.itemCount, tt.delta, got, tt.want)
			}
		})
	}
}

func TestListFilterIndicesUsesCaseInsensitiveFuzzyMatching(t *testing.T) {
	items := []string{"alpha", "FreeIPA Server", "freeipa-client", "beta"}
	if got, want := listFilterIndices(items, "fas"), []int{1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("listFilterIndices() = %v, want %v", got, want)
	}
	if got, want := listFilterIndices(items, "F C"), []int{2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("listFilterIndices() = %v, want %v", got, want)
	}
}
