package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// rosterHelperEnv, set in a re-executed test binary's environment, makes
// TestMain add the user named by rosterHelperUserEnv to the roster it
// names with AppendRosterUser, as whoever the binary runs as, instead of
// running the tests: how a root-only test plays several users writing one
// roster.
const (
	rosterHelperEnv     = "PILOT_TEST_ROSTER_APPEND_TO"
	rosterHelperUserEnv = "PILOT_TEST_ROSTER_APPEND_USER"
)

// Exit codes of the roster helper process: which refusal it met.
const (
	helperWrote       = 0
	helperOtherError  = 1
	helperNotWritable = 2
	helperLockFile    = 3
	helperLocked      = 4
)

func TestMain(m *testing.M) {
	if path := os.Getenv(rosterHelperEnv); path != "" {
		os.Exit(runRosterHelper(path, os.Getenv(rosterHelperUserEnv)))
	}
	os.Exit(m.Run())
}

// runRosterHelper is the helper process: umask 077, the strictest a
// writer may have, so the lock files' modes are what pilot chose.
func runRosterHelper(path, user string) int {
	syscall.Umask(0o077)
	err := AppendRosterUser(path, user)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	switch {
	case err == nil:
		return helperWrote
	case errors.Is(err, ErrRosterNotWritable):
		return helperNotWritable
	case errors.Is(err, ErrRosterLockFile):
		return helperLockFile
	case errors.Is(err, ErrMutationLocked):
		return helperLocked
	}
	return helperOtherError
}

// sharedTempDir is a new directory every user may enter (t.TempDir's
// parents are root's own 0700 directories), removed when t ends.
func sharedTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pilot-roster-users-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// testBinaryFor copies this test binary where every user may run it.
func testBinaryFor(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	bin := filepath.Join(sharedTempDir(t), "inventory.test")
	dst, err := os.OpenFile(bin, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	return bin
}

// testUser is a uid with its own primary group and the shared group team.
type testUser struct {
	name string
	uid  uint32
}

const rosterTeamGID = 12346

// appendAs runs AppendRosterUser(path, user) as u (runRosterHelper) and
// returns the helper's exit code.
func appendAs(t *testing.T, bin string, u testUser, path, user string) int {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Dir = filepath.Dir(bin)
	cmd.Env = append(os.Environ(), rosterHelperEnv+"="+path, rosterHelperUserEnv+"="+user)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: u.uid, Gid: u.uid, Groups: []uint32{rosterTeamGID}}}
	err := cmd.Run()
	code := cmd.ProcessState.ExitCode()
	if err != nil && code < 0 {
		t.Fatalf("run the test binary as %s: %v", u.name, err)
	}
	t.Logf("%s: AppendRosterUser(%s) exit %d %s", u.name, user, code, strings.TrimSpace(stderr.String()))
	return code
}

// Two users of one group share a roster they may both write: whichever
// writes first, the other is not locked out by the lock files the first
// left, and neither takes the roster from its owner. A member who may only
// read the roster is refused before creating any lock file, so the
// owner's next write still goes through. Before, every lock file was 0600
// and created before the roster was checked, so both failed with
// ErrRosterLockFile (PR #148 review, P2-1). Run as root to play the users.
func TestRosterWritersSharingAGroupDoNotLockEachOtherOut(t *testing.T) {
	requireRoot(t)
	alice, bob := testUser{"alice", 12345}, testUser{"bob", 12347}
	bin := testBinaryFor(t)
	// newRoster is a roster owned by alice and the team, in a directory
	// they may all write, with mode.
	newRoster := func(t *testing.T, mode os.FileMode) string {
		dir := filepath.Join(sharedTempDir(t), "vault")
		if err := os.Mkdir(dir, 0o770); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "roster.yaml")
		if err := os.WriteFile(path, []byte(lockTestRoster), mode); err != nil {
			t.Fatal(err)
		}
		for p, mode := range map[string]os.FileMode{dir: 0o770, path: mode} {
			if err := os.Chown(p, int(alice.uid), rosterTeamGID); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
		}
		return path
	}
	for _, order := range [][2]testUser{{alice, bob}, {bob, alice}} {
		t.Run("both may write: "+order[0].name+" first", func(t *testing.T) {
			path := newRoster(t, 0o660)
			for i, u := range order {
				user := fmt.Sprintf("user%d", i)
				if code := appendAs(t, bin, u, path, user); code != helperWrote {
					t.Fatalf("%s's write failed (exit %d)", u.name, code)
				}
				if !bytes.Contains(mustRead(t, path), []byte("name: "+user)) {
					t.Fatalf("%s's write is not in the roster", u.name)
				}
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if st := info.Sys().(*syscall.Stat_t); st.Uid != alice.uid || st.Gid != rosterTeamGID || info.Mode().Perm() != 0o660 {
				t.Fatalf("roster is %d:%d %v after the writes, want %d:%d 0660", st.Uid, st.Gid, info.Mode().Perm(), alice.uid, rosterTeamGID)
			}
		})
	}
	t.Run("a member who may only read leaves no lock file", func(t *testing.T) {
		path := newRoster(t, 0o640)
		if code := appendAs(t, bin, bob, path, "frank"); code != helperNotWritable {
			t.Fatalf("bob's write of a 0640 roster: exit %d, want ErrRosterNotWritable (%d)", code, helperNotWritable)
		}
		assertNoLockFiles(t, path)
		if code := appendAs(t, bin, alice, path, "erin"); code != helperWrote {
			t.Fatalf("alice's write after bob's refusal failed (exit %d)", code)
		}
		if !bytes.Contains(mustRead(t, path), []byte("name: erin")) || bytes.Contains(mustRead(t, path), []byte("name: frank")) {
			t.Fatalf("roster after the writes:\n%s", mustRead(t, path))
		}
	})
}
