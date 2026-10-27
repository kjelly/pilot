package inventory

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// writeLockTestRoster writes lockTestRoster in its own directory.
func writeLockTestRoster(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "roster.yaml")
	if err := os.WriteFile(path, []byte(lockTestRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A roster's lock file is never followed through a symlink nor shared with
// another name: as root (pilot-cli under `docker run`) the pid written into
// it, and the chown, would land on whatever file the link names. Run as
// any user: the writer refuses, says why, and leaves the link's target and
// the roster alone (PR #148 re-review, F3).
func TestRosterLockFileIsNeverFollowed(t *testing.T) {
	for name, plant := range map[string]func(t *testing.T, lockPath, victim string){
		"symlink": func(t *testing.T, lockPath, victim string) {
			if err := os.Symlink(victim, lockPath); err != nil {
				t.Fatal(err)
			}
		},
		"hard link": func(t *testing.T, lockPath, victim string) {
			if err := os.Link(victim, lockPath); err != nil {
				t.Fatal(err)
			}
		},
	} {
		for _, suffix := range rosterLockSuffixes {
			t.Run(name+suffix, func(t *testing.T) {
				path := writeLockTestRoster(t)
				victim := filepath.Join(t.TempDir(), "victim")
				if err := os.WriteFile(victim, []byte("not a lock file\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				plant(t, path+suffix, victim)
				err := AppendRosterUser(path, "erin")
				if !errors.Is(err, ErrRosterLockFile) || !strings.Contains(err.Error(), path+suffix) {
					t.Fatalf("error = %v, want ErrRosterLockFile naming %s", err, path+suffix)
				}
				if got := mustRead(t, victim); string(got) != "not a lock file\n" {
					t.Fatalf("the link's target was written: %q", got)
				}
				if !bytes.Equal(mustRead(t, path), []byte(lockTestRoster)) {
					t.Fatal("roster changed")
				}
			})
		}
	}
	t.Run("dangling symlink", func(t *testing.T) {
		path := writeLockTestRoster(t)
		victim := filepath.Join(t.TempDir(), "created-through-the-link")
		if err := os.Symlink(victim, path+".pilot-remove.lock"); err != nil {
			t.Fatal(err)
		}
		if err := AppendRosterUser(path, "erin"); !errors.Is(err, ErrRosterLockFile) || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("error = %v, want the symlink refusal", err)
		}
		if _, err := os.Lstat(victim); !os.IsNotExist(err) {
			t.Fatalf("a file was created through the dangling link (lstat err=%v)", err)
		}
	})
}

// As root, a symlinked lock file is refused before anything is chowned:
// the link's target keeps its owner (PR #148 re-review, F3).
func TestRosterLockFileSymlinkIsNotChowned(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("only root can chown another user's file")
	}
	const uid, gid = 12345, 12346
	path := writeLockTestRoster(t)
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("root's\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path+".pilot-remove.lock"); err != nil {
		t.Fatal(err)
	}
	if err := AppendRosterUser(path, "erin"); !errors.Is(err, ErrRosterLockFile) {
		t.Fatalf("error = %v, want ErrRosterLockFile", err)
	}
	info, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if st := info.Sys().(*syscall.Stat_t); st.Uid != 0 || string(mustRead(t, victim)) != "root's\n" {
		t.Fatalf("victim now owned by %d with %q", st.Uid, mustRead(t, victim))
	}
}

// A lock file this user may read but not write — one a root-run pilot
// left with mode 0444, say — still locks: flock needs no write access. The
// writer goes ahead, and the lock still excludes a second writer
// (PR #148 re-review, F4).
func TestRosterLockWorksThroughAReadOnlyLockFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a 0444 file read-write")
	}
	path := writeLockTestRoster(t)
	for _, suffix := range rosterLockSuffixes {
		if err := os.WriteFile(path+suffix, []byte("left by root\n"), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	if err := AppendRosterUser(path, "erin"); err != nil {
		t.Fatalf("AppendRosterUser() with read-only lock files: %v", err)
	}
	if !bytes.Contains(mustRead(t, path), []byte("erin")) {
		t.Fatal("roster not written")
	}
	held, err := lockRosterFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendRosterUser(path, "frank"); !errors.Is(err, ErrMutationLocked) {
		t.Errorf("second writer error = %v, want ErrMutationLocked", err)
	}
	held.release() //nolint:errcheck
	for _, suffix := range rosterLockSuffixes {
		if got := string(mustRead(t, path+suffix)); got != "left by root\n" {
			t.Errorf("read-only lock file %s rewritten: %q", suffix, got)
		}
	}
}

// Each way a lock file cannot be used says what to fix, wraps
// ErrRosterLockFile (not ErrMutationLocked: nothing holds the roster), and
// writes nothing (PR #148 re-review, F4).
func TestRosterLockFileErrorsSayWhatToFix(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens and creates anything")
	}
	for name, tt := range map[string]struct {
		setup func(t *testing.T, path string)
		want  string
	}{
		"directory not writable": {
			setup: func(t *testing.T, path string) {
				if err := os.Chmod(filepath.Dir(path), 0o500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Chmod(filepath.Dir(path), 0o700) }) //nolint:errcheck
			},
			want: "cannot create lock file " + "%s.pilot-migrate.lock; its directory must be writable by this user",
		},
		"lock file not openable": {
			setup: func(t *testing.T, path string) {
				if err := os.WriteFile(path+".pilot-remove.lock", nil, 0o000); err != nil {
					t.Fatal(err)
				}
			},
			want: "lock file %s.pilot-remove.lock exists but this user cannot open it",
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeLockTestRoster(t)
			tt.setup(t, path)
			err := AppendRosterUser(path, "erin")
			if want := strings.ReplaceAll(tt.want, "%s", path); !errors.Is(err, ErrRosterLockFile) || errors.Is(err, ErrMutationLocked) || !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %v, want ErrRosterLockFile saying %q", err, want)
			}
			if !bytes.Equal(mustRead(t, path), []byte(lockTestRoster)) {
				t.Fatal("roster changed")
			}
		})
	}
}

// A roster that needs nothing written takes no lock: deploy's schema
// upgrade and freeipa-client host autofill run on every deploy, and a lock
// file another user left must not make them fail (and warn) on a no-op.
// Once there is something to write, the same lock file is reported
// (PR #148 re-review, F4).
func TestNoOpRosterUpdatesNeedNoLock(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens any lock file")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(lockTestRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".pilot-migrate.lock", nil, 0o000); err != nil {
		t.Fatal(err)
	}
	if result, err := EnsureRosterCurrent(path, RosterMigrationOptions{}); err != nil || result.Changed {
		t.Fatalf("EnsureRosterCurrent(current roster) = %+v, %v; want a no-op", result, err)
	}
	encrypted := filepath.Join(dir, "encrypted.yaml")
	if err := os.WriteFile(encrypted, []byte("$ANSIBLE_VAULT;1.1;AES256\n6162636465\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(encrypted+".pilot-migrate.lock", nil, 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureRosterCurrent(encrypted, RosterMigrationOptions{}); !errors.Is(err, ErrRosterEncrypted) {
		t.Fatalf("EnsureRosterCurrent(encrypted) error = %v, want ErrRosterEncrypted", err)
	}
	hosts := "hosts:\n  db-special.ipa.pilot.internal:\n    ansible_host: 10.0.0.5\n    roles: [freeipa-client]\n"
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(hosts), 0o600); err != nil {
		t.Fatal(err)
	}
	if added, err := AutoFillFreeIPAClientRosterHosts(dir, path); err != nil || len(added) != 0 {
		t.Fatalf("AutoFillFreeIPAClientRosterHosts(nothing missing) = %v, %v; want nothing", added, err)
	}
	hosts += "  web9.ipa.pilot.internal:\n    ansible_host: 10.0.0.9\n    roles: [freeipa-client]\n"
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(hosts), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AutoFillFreeIPAClientRosterHosts(dir, path); !errors.Is(err, ErrRosterLockFile) {
		t.Fatalf("AutoFillFreeIPAClientRosterHosts(a host missing) error = %v, want ErrRosterLockFile", err)
	}
	if !bytes.Equal(mustRead(t, path), []byte(lockTestRoster)) {
		t.Fatal("roster changed")
	}
}

// Run as root, the admin password sync's atomic replace hands the new file
// to the roster's owner through its descriptor (PR #148 re-review, F3).
func TestSyncRosterAdminPasswordKeepsTheOwnerAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("only root can give a file away")
	}
	const uid, gid = 12345, 12346
	path := writeLockTestRoster(t)
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	if got, err := SyncRosterAdminPassword(path, "Old-pass_1", "New-pass_2"); err != nil || got != RosterAdminUpdated {
		t.Fatalf("SyncRosterAdminPassword() = %v, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st := info.Sys().(*syscall.Stat_t); st.Uid != uid || st.Gid != gid {
		t.Fatalf("roster owned by %d:%d, want %d:%d", st.Uid, st.Gid, uid, gid)
	}
}

// pilot edit's rollback puts a roster back only while it holds what the
// session left: changed by another writer since, or held, it is left
// alone; a roster the session created is removed on the same terms
// (PR #148 re-review, F2).
func TestRestoreRosterFileOnlyUndoesTheSessionsOwnWrite(t *testing.T) {
	original, session := []byte(lockTestRoster), []byte(lockTestRoster+"# session\n")
	for name, tt := range map[string]struct {
		current []byte
		hold    bool
		want    error
		after   []byte
	}{
		"unchanged since":  {current: session, after: original},
		"changed since":    {current: append(append([]byte{}, session...), "# another writer\n"...), want: ErrRosterChanged},
		"held by a writer": {current: session, hold: true, want: ErrMutationLocked},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "roster.yaml")
			if err := os.WriteFile(path, tt.current, 0o600); err != nil {
				t.Fatal(err)
			}
			if tt.hold {
				holdRawLocks(t, path, ".pilot-remove.lock")
			}
			err := RestoreRosterFile(path, session, original)
			if tt.want == nil && err != nil || tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("RestoreRosterFile() error = %v, want %v", err, tt.want)
			}
			want := tt.after
			if want == nil {
				want = tt.current
			}
			if got := mustRead(t, path); !bytes.Equal(got, want) {
				t.Fatalf("roster =\n%s\nwant\n%s", got, want)
			}
		})
	}
	t.Run("created by the session", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "roster.yaml")
		if err := os.WriteFile(path, session, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := RemoveRosterFile(path, []byte("something else")); !errors.Is(err, ErrRosterChanged) {
			t.Fatalf("RemoveRosterFile(changed) error = %v, want ErrRosterChanged", err)
		}
		if err := RemoveRosterFile(path, session); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("roster still there (lstat err=%v)", err)
		}
	})
}
