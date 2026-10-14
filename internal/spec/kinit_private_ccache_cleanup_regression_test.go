package spec

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// PR #72 review: tasks/freeipa-private-ccache-open.yml removed every
// day-old pilot-krb5cc-*.ccache in the shared temp dir, whoever owned it.
// gateway-scope-apply.yml runs with `become: false`; once a killed root run
// had left a cache in sticky /tmp, the unlink failed with EPERM and every
// gateway-scope run failed before kinit, on every retry. Only the executing
// user's own caches may be removed.

// privateCcacheOpened is what the test play records between the open and
// the close task files.
type privateCcacheOpened struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	UID  int    `json:"uid"`
	Name string `json:"krb5ccname"`
}

// runPrivateCcacheOpenClose runs the shared open and close task files on
// localhost with TMPDIR set to dir, so the cache and the stale-cache scan
// both live there, and returns what the open task produced.
func runPrivateCcacheOpenClose(t *testing.T, dir string) privateCcacheOpened {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	tasksDir, err := filepath.Abs("../../playbooks/apply/tasks")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	record := filepath.Join(work, "opened.json")
	play := []map[string]any{{
		"name":         "open and close a private Kerberos cache",
		"hosts":        "localhost",
		"connection":   "local",
		"gather_facts": false,
		"environment":  map[string]any{"TMPDIR": dir},
		"tasks": []map[string]any{
			{"ansible.builtin.include_tasks": map[string]any{"file": filepath.Join(tasksDir, "freeipa-private-ccache-open.yml")}},
			{"ansible.builtin.copy": map[string]any{
				"dest":    record,
				"content": "{{ {'path': pilot_krb5ccname_file.path, 'mode': pilot_krb5ccname_file.mode, 'uid': pilot_krb5ccname_file.uid, 'krb5ccname': pilot_krb5ccname} | to_json }}",
			}},
			{"ansible.builtin.include_tasks": map[string]any{"file": filepath.Join(tasksDir, "freeipa-private-ccache-close.yml")}},
		},
	}}
	raw, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	pb := filepath.Join(work, "play.yml")
	if err := os.WriteFile(pb, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", pb)
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ansible-playbook: %v\n%s", err, out)
	}
	var opened privateCcacheOpened
	if err := json.Unmarshal([]byte(readFile(t, record)), &opened); err != nil {
		t.Fatal(err)
	}
	return opened
}

// stickyTempDir returns a world-writable sticky directory, like /tmp.
func stickyTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o1777); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeAgedFile creates path, owned by the test user, with an mtime age ago.
func writeAgedFile(t *testing.T, path string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

// sudoRun runs argv under passwordless sudo, or directly when the test
// already runs as root.
func sudoRun(t *testing.T, argv ...string) {
	t.Helper()
	if os.Geteuid() != 0 {
		argv = append([]string{"sudo", "-n"}, argv...)
	}
	if out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(argv, " "), err, out)
	}
}

// rootStickyDir returns a world-writable sticky directory owned by root,
// like /tmp. The owner of a sticky directory may unlink any file in it, so
// a directory the test user owns would hide the failure this guards
// against. It skips the test without root or passwordless sudo.
func rootStickyDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
			t.Skipf("needs root or passwordless sudo for a root-owned sticky directory: %v", err)
		}
	}
	dir := filepath.Join(t.TempDir(), "tmp")
	sudoRun(t, "install", "-d", "-m", "1777", "-o", "root", "-g", "root", dir)
	// Runs before t.TempDir's own cleanup, which cannot remove files other
	// users own from a root-owned sticky directory.
	t.Cleanup(func() {
		argv := []string{"rm", "-rf", dir}
		if os.Geteuid() != 0 {
			argv = append([]string{"sudo", "-n"}, argv...)
		}
		if out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput(); err != nil {
			t.Errorf("removing %s: %v\n%s", dir, err, out)
		}
	})
	return dir
}

// writeForeignAgedFile creates path with an mtime age ago, owned by root
// when the test runs as another user, by nobody when it runs as root.
func writeForeignAgedFile(t *testing.T, path string, age time.Duration) {
	t.Helper()
	owner := "root"
	if os.Geteuid() == 0 {
		owner = "65534"
	}
	sudoRun(t, "install", "-m", "0600", "-o", owner, "/dev/null", path)
	sudoRun(t, "touch", "-d", "@"+strconv.FormatInt(time.Now().Add(-age).Unix(), 10), path)
}

// The cache is private while it exists and gone after close; a stale cache
// of the same user is removed, a younger one and other files are kept.
func TestRegression_PrivateCcacheOpenCleansOnlyItsOwnStaleCaches(t *testing.T) {
	dir := stickyTempDir(t)
	stale := filepath.Join(dir, "pilot-krb5cc-killedrun.ccache")
	young := filepath.Join(dir, "pilot-krb5cc-running.ccache")
	other := filepath.Join(dir, "other-tool.ccache")
	writeAgedFile(t, stale, 48*time.Hour)
	writeAgedFile(t, young, time.Hour)
	writeAgedFile(t, other, 48*time.Hour)

	opened := runPrivateCcacheOpenClose(t, dir)

	if filepath.Dir(opened.Path) != dir || !strings.HasPrefix(filepath.Base(opened.Path), "pilot-krb5cc-") {
		t.Errorf("cache created at %s, want a pilot-krb5cc-* file in %s", opened.Path, dir)
	}
	if opened.Mode != "0600" || opened.UID != os.Geteuid() {
		t.Errorf("cache mode %s uid %d, want 0600 owned by uid %d", opened.Mode, opened.UID, os.Geteuid())
	}
	if opened.Name != "FILE:"+opened.Path {
		t.Errorf("pilot_krb5ccname = %q, want FILE:%s", opened.Name, opened.Path)
	}
	if exists(opened.Path) {
		t.Errorf("close left the cache %s behind", opened.Path)
	}
	if exists(stale) {
		t.Errorf("the day-old cache of the same user %s was not removed", stale)
	}
	if !exists(young) {
		t.Errorf("a cache younger than a day %s was removed; it may belong to a running play", young)
	}
	if !exists(other) {
		t.Errorf("%s does not match pilot-krb5cc-* but was removed", other)
	}
}

// A day-old cache another user left in the shared sticky directory is not
// this run's: it is left alone, and the run still succeeds. Run as a
// regular user against a root-owned file, the old task failed here with
// "Unlinking failed: [Errno 1] Operation not permitted".
func TestRegression_PrivateCcacheOpenLeavesOtherUsersCaches(t *testing.T) {
	dir := rootStickyDir(t)
	foreign := filepath.Join(dir, "pilot-krb5cc-rootrun.ccache")
	writeForeignAgedFile(t, foreign, 48*time.Hour)

	opened := runPrivateCcacheOpenClose(t, dir)

	if !exists(foreign) {
		t.Errorf("the run removed %s, which another user owns", foreign)
	}
	if exists(opened.Path) {
		t.Errorf("close left the cache %s behind", opened.Path)
	}
}
