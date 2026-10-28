package secretpath

import (
	"os"
	"testing"
	"time"
)

// A directory some other user owns is not this user's to remove, held or
// not.
func TestSweepLeavesADirectoryAnotherUserOwns(t *testing.T) {
	tmp := t.TempDir()
	const prefix = "pilot-roster-scope"
	dead := deadPID(t)
	markerless := mkPrivate(t, tmp, prefix, dead, "markerless", time.Hour)
	unlocked := mkPrivate(t, tmp, prefix, dead, "unlocked", time.Hour)
	if err := os.WriteFile(unlocked+"/"+markerName, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	sweepPrivateTempDirsAs(tmp, prefix, os.Getuid()+1)
	if gone(markerless) || gone(unlocked) {
		t.Fatal("a directory owned by another user was removed")
	}
	sweepPrivateTempDirsAs(tmp, prefix, os.Getuid())
	if !gone(markerless) || !gone(unlocked) {
		t.Fatal("this user's dead directories survived their own sweep")
	}
}

// The caller removes its directory itself; the descriptor holding the lock
// is let go by the next PrivateTempDir, so a long-running pilot does not
// accumulate one per plan.
func TestRemovedDirectoriesReleaseTheirLock(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	held := func() int {
		heldMarkers.Lock()
		defer heldMarkers.Unlock()
		return len(heldMarkers.byDir)
	}
	base := held()
	var dirs []string
	for range 5 {
		d, err := PrivateTempDir("pilot-edit-plan")
		if err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, d)
	}
	if got := held(); got != base+5 {
		t.Fatalf("held %d markers, want %d", got, base+5)
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			t.Fatal(err)
		}
	}
	last, err := PrivateTempDir("pilot-edit-plan")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(last)
	if got := held(); got != base+1 {
		t.Fatalf("after removal and one more directory: %d markers held, want %d", got, base+1)
	}
}
