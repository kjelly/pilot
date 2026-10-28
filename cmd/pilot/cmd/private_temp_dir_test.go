package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// deadPID returns the pid of a process that has exited.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return cmd.ProcessState.Pid()
}

// ageDir makes p look an hour old: a directory without a liveness marker
// (what a pilot from before the marker left) is swept only once it is old.
func ageDir(t *testing.T, p string) {
	t.Helper()
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
}

// A plan's scratch workspace and a simulated roster write copy secrets to
// the temp directory; the copies a killed pilot left are removed the next
// time one is made — only this user's, only for a pid no longer running,
// never through a symlink (PR #148 round 6, P3-4).
func TestPrivateTempDirSweepsWhatADeadPilotLeft(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	const prefix = "pilot-roster-scope"
	dead := deadPID(t)
	mk := func(name string) string {
		p := filepath.Join(tmp, name)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "ipa-identity.yaml"), []byte("password: secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		ageDir(t, p)
		return p
	}
	stale := mk(fmt.Sprintf("%s-%d-abc", prefix, dead))
	keep := []string{
		mk(fmt.Sprintf("%s-%d-own", prefix, os.Getpid())),
		mk(fmt.Sprintf("%s-%d-live", prefix, os.Getppid())),
		mk(prefix + "-notapid-x"),
		mk(fmt.Sprintf("pilot-edit-plan-%d-other-prefix", dead)),
	}
	elsewhere := mk("elsewhere")
	link := filepath.Join(tmp, fmt.Sprintf("%s-%d-link", prefix, dead))
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	keep = append(keep, link, elsewhere)
	if os.Geteuid() == 0 {
		other := mk(fmt.Sprintf("%s-%d-other-user", prefix, dead))
		if err := os.Chown(other, 12345, 12345); err != nil {
			t.Fatal(err)
		}
		keep = append(keep, other)
	}

	dir, err := privateTempDir(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Errorf("a dead pilot's copy survived (err=%v)", err)
	}
	for _, p := range keep {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s removed: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(elsewhere, "ipa-identity.yaml")); err != nil {
		t.Errorf("the sweep followed a symlink: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 || !strings.HasPrefix(filepath.Base(dir), fmt.Sprintf("%s-%d-", prefix, os.Getpid())) {
		t.Fatalf("new dir %s: %v %v", dir, info, err)
	}
}

// Both secret-copying scratch areas use privateTempDir.
func TestSecretScratchDirsArePrivateTempDirs(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	dead := deadPID(t)
	for _, prefix := range []string{"pilot-edit-plan", "pilot-roster-scope"} {
		p := filepath.Join(tmp, fmt.Sprintf("%s-%d-x", prefix, dead))
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		ageDir(t, p)
	}
	dir, cleanup, err := copyManagedFilesToTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if !strings.HasPrefix(dir, filepath.Join(tmp, fmt.Sprintf("pilot-edit-plan-%d-", os.Getpid()))) {
		t.Errorf("plan workspace %s is not a private temp dir", dir)
	}
	if _, _, err := simulateRosterWrite(filepath.Join(t.TempDir(), "missing.yaml"), func(string) (struct{}, error) { return struct{}{}, nil }); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"pilot-edit-plan", "pilot-roster-scope"} {
		if _, err := os.Stat(filepath.Join(tmp, fmt.Sprintf("%s-%d-x", prefix, dead))); !os.IsNotExist(err) {
			t.Errorf("%s: a dead pilot's copy survived (err=%v)", prefix, err)
		}
	}
}
