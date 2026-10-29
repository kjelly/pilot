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

// A marker some other user owns is not a holder this user can judge: the
// directory is kept although the marker is unlocked, old and its pid dead —
// and the sweep still removes it for its own owner. The directory is this
// user's, so removeIfDead is asked with an owner other than the marker's.
func TestSweepKeepsADirectoryWhoseMarkerAnotherUserOwns(t *testing.T) {
	tmp := t.TempDir()
	const prefix = "pilot-roster-scope"
	dir := mkPrivate(t, tmp, prefix, deadPID(t), "foreign-marker", time.Hour)
	if err := os.WriteFile(dir+"/"+markerName, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	age(t, dir, time.Hour)
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}

	removeIfDead(dir, info, deadPID(t), os.Getpid(), os.Getuid()+1)
	if gone(dir) {
		t.Fatal("a directory whose marker another user owns was removed")
	}
	removeIfDead(dir, info, deadPID(t), os.Getpid(), os.Getuid())
	if !gone(dir) {
		t.Fatal("the same dead directory survived a sweep by its own owner")
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
	// Directories an earlier test removed but nothing has reaped yet are
	// still held: let them go first, so the baseline is this test's own.
	reapReleasedMarkers()
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
