package spec

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// Two gaps in the migration's rollback archive, both seen in every
// realm-replacement evidence record up to 2026-10-13:
//   - `--check --diff` always failed at the archive link: check mode skips the
//     snapshot, so the link's source did not exist, and the preview ended in
//     the rescue.
//   - the archive was named from ansible_date_time, which the one-hour fact
//     cache kept, so every run within the hour reused the first run's name
//     and its tar overwrote that run's archive.

const (
	realmArchiveNameTask     = "Realm replacement — name this run's archive"
	realmArchiveDirsTask     = "Realm replacement — create local state and backup directories"
	realmArchiveStatTask     = "Realm replacement — look for an archive at this run's name"
	realmArchiveGateTask     = "Gate: this run's archive must not exist yet"
	realmArchiveSnapshotTask = "Realm replacement — snapshot old client trust before mutation"
	realmArchiveLinkTask     = "Realm replacement — expose archive through a stable root-only link"
)

// realmArchiveFixture creates stand-ins for the files the snapshot archives
// and returns the path rewrites and the state/backup variables.
func realmArchiveFixture(t *testing.T) (dir string, paths map[string]string, vars map[string]any) {
	t.Helper()
	dir = t.TempDir()
	src := filepath.Join(dir, "src")
	for _, d := range []string{filepath.Join(src, "ipa"), filepath.Join(src, "sssd")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	paths = map[string]string{
		"/etc/ipa":           filepath.Join(src, "ipa"),
		"/etc/krb5.conf":     filepath.Join(src, "krb5.conf"),
		"/etc/krb5.keytab":   filepath.Join(src, "krb5.keytab"),
		"/etc/sssd":          filepath.Join(src, "sssd"),
		"/etc/nsswitch.conf": filepath.Join(src, "nsswitch.conf"),
		"/etc/hosts":         filepath.Join(src, "hosts"),
	}
	for name, content := range map[string]string{
		filepath.Join(src, "ipa", "default.conf"): "[global]\nrealm = IPA.PILOT.INTERNAL\n",
		paths["/etc/krb5.conf"]:                   "[libdefaults]\n",
		paths["/etc/krb5.keytab"]:                 "keytab",
		paths["/etc/nsswitch.conf"]:               "passwd: files sss\n",
		paths["/etc/hosts"]:                       "127.0.0.1 localhost\n",
	} {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	vars = map[string]any{
		"freeipa_realm_replacement_state_dir":   filepath.Join(dir, "state"),
		"freeipa_realm_replacement_backup_dir":  filepath.Join(dir, "backups"),
		"freeipa_realm_replacement_backup_link": filepath.Join(dir, "state", "backup"),
	}
	return dir, paths, vars
}

// TestRegression_RealmReplacementCheckModePreviewsTheArchiveLink runs the
// archive tasks with --check --diff: the preview passes, reports the link it
// would create, and writes nothing.
func TestRegression_RealmReplacementCheckModePreviewsTheArchiveLink(t *testing.T) {
	dir, paths, vars := realmArchiveFixture(t)
	tasks := []string{realmArchiveNameTask, realmArchiveDirsTask, realmArchiveStatTask, realmArchiveGateTask, realmArchiveSnapshotTask, realmArchiveLinkTask}
	rc, changed, failures := runRealmTasksArgs(t, tasks, paths, vars, nil, []string{"--check", "--diff"})
	if rc != 0 {
		t.Fatalf("--check --diff: rc=%d failures=%v; want the preview to pass", rc, failures)
	}
	if !changed[realmArchiveLinkTask] {
		t.Errorf("the preview does not report the link it would create (changed=%v)", changed)
	}
	for _, p := range []string{filepath.Join(dir, "backups"), filepath.Join(dir, "state")} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("check mode created %s (err %v)", p, err)
		}
	}
}

// TestRegression_RealmReplacementNamesEachRunsArchive runs the archive tasks
// twice, more than a second apart: each run writes its own archive, links
// it, and leaves the earlier one as it was.
func TestRegression_RealmReplacementNamesEachRunsArchive(t *testing.T) {
	dir, paths, vars := realmArchiveFixture(t)
	tasks := []string{realmArchiveNameTask, realmArchiveDirsTask, realmArchiveStatTask, realmArchiveGateTask, realmArchiveSnapshotTask, realmArchiveLinkTask}
	name := regexp.MustCompile(`^localhost-\d{8}T\d{6}Z\.tar\.gz$`)
	backups, link := filepath.Join(dir, "backups"), filepath.Join(dir, "state", "backup")
	var first string
	var firstContent []byte
	for run := 1; run <= 2; run++ {
		if run == 2 {
			time.Sleep(1100 * time.Millisecond)
		}
		rc, _, failures := runRealmTasks(t, tasks, paths, vars)
		if rc != 0 {
			t.Fatalf("run %d: rc=%d failures=%v", run, rc, failures)
		}
		entries, err := os.ReadDir(backups)
		if err != nil {
			t.Fatal(err)
		}
		var archives []string
		for _, e := range entries {
			if !name.MatchString(e.Name()) {
				t.Errorf("run %d: archive %q, want <host>-<UTC timestamp>Z.tar.gz", run, e.Name())
			}
			archives = append(archives, filepath.Join(backups, e.Name()))
		}
		slices.Sort(archives)
		if len(archives) != run {
			t.Fatalf("run %d: archives %v, want %d", run, archives, run)
		}
		target, err := os.Readlink(link)
		if err != nil {
			t.Fatal(err)
		}
		if newest := archives[len(archives)-1]; target != newest {
			t.Errorf("run %d: the link points at %s, want this run's archive %s", run, target, newest)
		}
		if run == 1 {
			first = archives[0]
			if firstContent, err = os.ReadFile(first); err != nil {
				t.Fatal(err)
			}
		} else if got, err := os.ReadFile(first); err != nil || string(got) != string(firstContent) {
			t.Errorf("run 2 changed the first run's archive %s (err %v)", first, err)
		}
	}
}

// TestRegression_RealmReplacementNeverOverwritesAnArchive: when this run's
// name is already taken, the gate refuses before the snapshot and the
// earlier archive keeps its content.
func TestRegression_RealmReplacementNeverOverwritesAnArchive(t *testing.T) {
	dir, paths, vars := realmArchiveFixture(t)
	archive := filepath.Join(dir, "backups", "localhost-earlier.tar.gz")
	if err := os.MkdirAll(filepath.Dir(archive), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, []byte("earlier run"), 0o600); err != nil {
		t.Fatal(err)
	}
	vars["freeipa_realm_replacement_backup_archive"] = archive
	rc, _, failures := runRealmTasks(t, []string{realmArchiveDirsTask, realmArchiveStatTask, realmArchiveGateTask, realmArchiveSnapshotTask}, paths, vars)
	if rc == 0 || len(failures) != 1 || !strings.HasPrefix(failures[0], realmArchiveGateTask+": ") || !strings.Contains(failures[0], "already exists") {
		t.Fatalf("rc=%d failures=%v; want only the archive gate to refuse", rc, failures)
	}
	if got, err := os.ReadFile(archive); err != nil || string(got) != "earlier run" {
		t.Errorf("the earlier archive was changed: %q (err %v)", got, err)
	}
}

// TestRegression_RealmReplacementOldRealmGateRunsInCheckMode: the gate that
// requires the client to still be in the declared old realm is read-only and
// refuses a --check preview of a client in another realm too. Check mode used
// to skip it.
func TestRegression_RealmReplacementOldRealmGateRunsInCheckMode(t *testing.T) {
	tasks := []string{"Gate: reject a second migration without explicit recovery review", "Gate: client must still be enrolled in the declared old realm"}
	for _, tc := range []struct {
		realm  string
		refuse bool
	}{
		{"IPA.PILOT.INTERNAL", false},
		{"OTHER.EXAMPLE.TEST", true},
	} {
		t.Run(tc.realm, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			conf := filepath.Join(dir, "default.conf")
			if err := os.WriteFile(conf, []byte("[global]\nrealm = "+tc.realm+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			vars := map[string]any{
				"freeipa_realm_replacement_old_realm":  "IPA.PILOT.INTERNAL",
				"freeipa_realm_replacement_state_file": filepath.Join(dir, "state.env"),
			}
			rc, _, failures := runRealmTasksArgs(t, tasks, map[string]string{"/etc/ipa/default.conf": conf}, vars, nil, []string{"--check", "--diff"})
			if tc.refuse && (rc == 0 || len(failures) != 1 || !strings.HasPrefix(failures[0], tasks[1]+": ")) {
				t.Errorf("--check on a client in %s: rc=%d failures=%v; want the old-realm gate to refuse", tc.realm, rc, failures)
			}
			if !tc.refuse && rc != 0 {
				t.Errorf("--check on a client in the old realm: rc=%d failures=%v", rc, failures)
			}
		})
	}
}
