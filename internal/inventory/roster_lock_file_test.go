package inventory

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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
	requireRoot(t)
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
	requireRoot(t)
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

// A FIFO planted as a lock file — one this user may only read, or may
// read and write — is refused at once: opening it never waits for a
// writer (PR #148 re-review).
func TestRosterLockFileFIFOIsRefusedWithoutHanging(t *testing.T) {
	for name, mode := range map[string]uint32{"read-only": 0o444, "read-write": 0o600} {
		t.Run(name, func(t *testing.T) {
			if mode == 0o444 && os.Geteuid() == 0 {
				t.Skip("root opens a 0444 FIFO read-write")
			}
			path := writeLockTestRoster(t)
			if err := syscall.Mkfifo(path+".pilot-migrate.lock", mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path+".pilot-migrate.lock", os.FileMode(mode)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- AppendRosterUser(path, "erin") }()
			select {
			case err := <-done:
				if !errors.Is(err, ErrRosterLockFile) || !strings.Contains(err.Error(), "not a plain file") {
					t.Fatalf("error = %v, want the FIFO refused", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("locking a roster hung on a FIFO lock file")
			}
			if !bytes.Equal(mustRead(t, path), []byte(lockTestRoster)) {
				t.Fatal("roster changed")
			}
		})
	}
}

// ProbeRosterLock tells a plan what the apply's lockRosterFile would find
// on the real roster, without leaving a lock file or holding a lock: free,
// held by another process, or a lock file this user cannot use (PR #148
// round 4: a plan on a scratch copy otherwise passes where the apply is
// refused).
func TestProbeRosterLockReportsWhatTheWriterWouldFind(t *testing.T) {
	t.Run("free: no lock file is created", func(t *testing.T) {
		path := writeLockTestRoster(t)
		if err := ProbeRosterLock(path); err != nil {
			t.Fatalf("ProbeRosterLock() = %v, want nil", err)
		}
		for _, suffix := range rosterLockSuffixes {
			if _, err := os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("probe created %s (err=%v)", path+suffix, err)
			}
		}
	})
	t.Run("free lock files are left free", func(t *testing.T) {
		path := writeLockTestRoster(t)
		lk, err := lockRosterFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lk.release() //nolint:errcheck
		if err := ProbeRosterLock(path); err != nil {
			t.Fatalf("ProbeRosterLock() = %v, want nil", err)
		}
		if err := AppendRosterUser(path, "erin"); err != nil {
			t.Fatalf("a writer after the probe: %v", err)
		}
	})
	for _, suffix := range rosterLockSuffixes {
		t.Run("held "+suffix, func(t *testing.T) {
			path := writeLockTestRoster(t)
			f, err := os.OpenFile(path+suffix, os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			if err := ProbeRosterLock(path); !errors.Is(err, ErrMutationLocked) {
				t.Fatalf("ProbeRosterLock() = %v, want ErrMutationLocked", err)
			}
		})
	}
	t.Run("held through a symlinked roster", func(t *testing.T) {
		path := writeLockTestRoster(t)
		link := filepath.Join(t.TempDir(), "link.yaml")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		lk, err := lockRosterFile(path)
		if err != nil {
			t.Fatal(err)
		}
		defer lk.release() //nolint:errcheck
		if err := ProbeRosterLock(link); !errors.Is(err, ErrMutationLocked) {
			t.Fatalf("ProbeRosterLock(link) = %v, want ErrMutationLocked", err)
		}
	})
	t.Run("lock file is a symlink", func(t *testing.T) {
		path := writeLockTestRoster(t)
		if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), path+rosterLockSuffixes[0]); err != nil {
			t.Fatal(err)
		}
		if err := ProbeRosterLock(path); !errors.Is(err, ErrRosterLockFile) {
			t.Fatalf("ProbeRosterLock() = %v, want ErrRosterLockFile", err)
		}
	})
	t.Run("lock file not openable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root opens any lock file")
		}
		path := writeLockTestRoster(t)
		if err := os.WriteFile(path+rosterLockSuffixes[1], nil, 0o000); err != nil {
			t.Fatal(err)
		}
		if err := ProbeRosterLock(path); !errors.Is(err, ErrRosterLockFile) {
			t.Fatalf("ProbeRosterLock() = %v, want ErrRosterLockFile", err)
		}
		if _, err := lockRosterFile(path); !errors.Is(err, ErrRosterLockFile) {
			t.Fatalf("lockRosterFile() = %v; the probe and the writer disagree", err)
		}
	})
	t.Run("lock file cannot be created", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes any directory")
		}
		path := writeLockTestRoster(t)
		dir := filepath.Dir(path)
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0o700) }) //nolint:errcheck
		if err := ProbeRosterLock(path); !errors.Is(err, ErrRosterLockFile) {
			t.Fatalf("ProbeRosterLock() = %v, want ErrRosterLockFile", err)
		}
		if _, err := lockRosterFile(path); !errors.Is(err, ErrRosterLockFile) {
			t.Fatalf("lockRosterFile() = %v; the probe and the writer disagree", err)
		}
	})
}
