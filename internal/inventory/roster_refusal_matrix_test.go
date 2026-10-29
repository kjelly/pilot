package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// rosterRefusalCause is one way a roster that must be written cannot be:
// setup arranges it for the roster at path (or returns a fault to inject)
// and want is the error class every writer reports for it (nil: none, but
// still an error).
type rosterRefusalCause struct {
	want     error
	skipRoot string
	setup    func(t *testing.T, path string) func(op, p string) error
	noProbe  string // why ProbeRosterWrite cannot see this cause
}

func holdFlock(t *testing.T, lock string) {
	t.Helper()
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
}

func faultOn(op, suffix string, errno syscall.Errno) func(string, string) error {
	return func(o, p string) error {
		if o == op && strings.HasSuffix(p, suffix) {
			return errno
		}
		return nil
	}
}

// rosterRefusalCauses enumerates every refusal lockRosterFile,
// acquireMutationLock, writeLockedRoster and PrepareRosterAdminSync can
// produce for an existing roster; errors a real file system gives rarely
// are injected (InjectFileFault).
func rosterRefusalCauses() map[string]rosterRefusalCause {
	migrate, remove := rosterLockSuffixes[0], rosterLockSuffixes[1]
	return map[string]rosterRefusalCause{
		"migrate lock held": {want: ErrMutationLocked, setup: func(t *testing.T, p string) func(string, string) error {
			holdFlock(t, p+migrate)
			return nil
		}},
		"remove lock held": {want: ErrMutationLocked, setup: func(t *testing.T, p string) func(string, string) error {
			holdFlock(t, p+remove)
			return nil
		}},
		"lock file not openable": {want: ErrRosterLockFile, skipRoot: "root opens any lock file", setup: func(t *testing.T, p string) func(string, string) error {
			if err := os.WriteFile(p+migrate, nil, 0o000); err != nil {
				t.Fatal(err)
			}
			return nil
		}},
		"lock file cannot be created": {want: ErrRosterLockFile, skipRoot: "root writes any directory", setup: func(t *testing.T, p string) func(string, string) error {
			dir := filepath.Dir(p)
			if err := os.Chmod(dir, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(dir, 0o700) }) //nolint:errcheck
			return nil
		}},
		"lock file is a symlink": {want: ErrRosterLockFile, setup: func(t *testing.T, p string) func(string, string) error {
			if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), p+migrate); err != nil {
				t.Fatal(err)
			}
			return nil
		}},
		"lock file is a directory": {want: ErrRosterLockFile, setup: func(t *testing.T, p string) func(string, string) error {
			if err := os.Mkdir(p+migrate, 0o700); err != nil {
				t.Fatal(err)
			}
			return nil
		}},
		"lock file is a FIFO": {want: ErrRosterLockFile, setup: func(t *testing.T, p string) func(string, string) error {
			if err := syscall.Mkfifo(p+remove, 0o600); err != nil {
				t.Fatal(err)
			}
			return nil
		}},
		"lock file has another name": {want: ErrRosterLockFile, setup: func(t *testing.T, p string) func(string, string) error {
			if err := os.WriteFile(p+migrate, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(p+migrate, p+".other-name"); err != nil {
				t.Fatal(err)
			}
			return nil
		}},
		"lock file open EROFS (injected)":  {want: ErrRosterLockFile, setup: func(*testing.T, string) func(string, string) error { return faultOn("open", migrate, syscall.EROFS) }},
		"lock file open EIO (injected)":    {want: ErrRosterLockFile, setup: func(*testing.T, string) func(string, string) error { return faultOn("open", remove, syscall.EIO) }},
		"lock file open ENOSPC (injected)": {want: ErrRosterLockFile, setup: func(*testing.T, string) func(string, string) error { return faultOn("open", migrate, syscall.ENOSPC) }},
		"flock EIO on an existing lock file (injected)": {want: ErrRosterLockFile, setup: func(t *testing.T, p string) func(string, string) error {
			if err := os.WriteFile(p+remove, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return faultOn("flock", remove, syscall.EIO)
		}},
		"flock EIO on a lock file not created yet (injected)": {want: ErrRosterLockFile,
			noProbe: "the probe creates no lock file, so it cannot flock one that does not exist yet; the apply refuses",
			setup:   func(*testing.T, string) func(string, string) error { return faultOn("flock", remove, syscall.EIO) }},
		"roster not writable": {want: ErrRosterNotWritable, skipRoot: "root writes a 0400 roster", setup: func(t *testing.T, p string) func(string, string) error {
			if err := os.Chmod(p, 0o400); err != nil {
				t.Fatal(err)
			}
			return nil
		}},
		"roster open EROFS (injected)": {want: ErrRosterNotWritable, setup: func(*testing.T, string) func(string, string) error {
			return faultOn("open", "ipa-identity.yaml", syscall.EROFS)
		}},
		"roster open EIO (injected)": {want: ErrRosterNotWritable, setup: func(*testing.T, string) func(string, string) error {
			return faultOn("open", "ipa-identity.yaml", syscall.EIO)
		}},
		// No sentinel classifies this one: callers must refuse on errors
		// they do not recognise, too.
		"roster path cannot be resolved (injected)": {setup: func(*testing.T, string) func(string, string) error {
			return faultOn("resolve", "ipa-identity.yaml", syscall.EIO)
		}},
		"roster path re-resolves while locking": {want: ErrMutationLocked, noProbe: "the probe holds no lock, so there is no window to re-resolve in", setup: func(t *testing.T, p string) func(string, string) error {
			afterRosterLockHook = func() {
				other := filepath.Join(filepath.Dir(p), "other.yaml")
				data, _ := os.ReadFile(p)
				if err := os.WriteFile(other, data, 0o600); err != nil {
					t.Error(err)
				}
				if err := os.Rename(p, p+".moved"); err != nil {
					t.Error(err)
				}
				if err := os.Symlink(other, p); err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(func() { afterRosterLockHook = nil })
			return nil
		}},
	}
}

// Every refusal is reported the same way by the vault save's Prepare, the
// plan's probe and a writer, as a refusal — never as a hand-edit case the
// save may go past — and names the roster (PR #148 round 6, P2-1). The
// hand-edit cases are the complementary set.
func TestRosterRefusalsAgreeAcrossPrepareProbeAndWriter(t *testing.T) {
	shortLockContentionWait(t)
	for name, cause := range rosterRefusalCauses() {
		t.Run(name, func(t *testing.T) {
			if cause.skipRoot != "" && os.Geteuid() == 0 {
				t.Skip(cause.skipRoot)
			}
			for _, who := range []string{"prepare", "probe", "writer"} {
				t.Run(who, func(t *testing.T) {
					if who == "probe" && cause.noProbe != "" {
						t.Skip(cause.noProbe)
					}
					body := strings.Replace(rosterAdminFixture, "%s", `"Old-pass_1"`, 1)
					dir, err := filepath.EvalSymlinks(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(dir, "ipa-identity.yaml")
					if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
					if fault := cause.setup(t, path); fault != nil {
						t.Cleanup(InjectFileFault(fault))
					}
					switch who {
					case "prepare":
						_, err = PrepareRosterAdminSync(path, "Old-pass_1", "New-pass_2")
					case "probe":
						err = ProbeRosterWrite(path)
					case "writer":
						err = AppendRosterUser(path, "erin")
					}
					if err == nil || cause.want != nil && !errors.Is(err, cause.want) || errors.Is(err, ErrRosterNeedsHandEdit) {
						t.Fatalf("error = %v; want %v and not a hand-edit case", err, cause.want)
					}
					if !strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "Old-pass_1") || strings.Contains(err.Error(), "New-pass_2") {
						t.Fatalf("error %q does not name the roster, or leaks a password", err)
					}
					if data, rerr := os.ReadFile(path); rerr == nil && string(data) != body {
						t.Fatalf("roster changed:\n%s", data)
					}
				})
			}
		})
	}
	for name, body := range map[string]string{
		"encrypted file": "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n",
		"inline !vault":  strings.Replace(rosterAdminFixture, "%s", "!vault |\n      $ANSIBLE_VAULT;1.1;AES256\n      6162", 1),
		"alias":          "schema_version: 3\npw: &pw \"Old-pass_1\"\nfreeipa:\n  admin:\n    principal: admin\n    password: *pw\n",
		"flow mapping":   "schema_version: 3\nfreeipa:\n  admin: {principal: admin, password: \"Old-pass_1\"}\n",
		"invalid YAML":   "schema_version: 3\nfreeipa: [unclosed\n",
		"folded scalar":  "schema_version: 3\nfreeipa:\n  admin:\n    principal: admin\n    password: >-\n      Old-pass_1\n",
		// A graph that refers to itself is a roster pilot cannot follow, the
		// same hand-edit report as any other layout it cannot (round 11).
		"cyclic merge key": "schema_version: 3\nfreeipa: &f\n  <<: *f\n",
		"cyclic alias":     "schema_version: 3\nfreeipa: &f\n  admin: *f\n",
	} {
		t.Run("hand edit: "+name, func(t *testing.T) {
			check := func(t *testing.T) {
				path := writeRoster(t, body)
				_, err := PrepareRosterAdminSync(path, "Old-pass_1", "New-pass_2")
				if !errors.Is(err, ErrRosterNeedsHandEdit) {
					t.Fatalf("error = %v; want ErrRosterNeedsHandEdit", err)
				}
			}
			// A stack overflow takes the whole test binary down.
			if strings.HasPrefix(name, "cyclic") {
				runIsolated(t, 20*time.Second, check)
				return
			}
			check(t)
		})
	}
}
