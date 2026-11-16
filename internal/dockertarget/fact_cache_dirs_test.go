package dockertarget

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/factcache"
	"github.com/kjelly/pilot/internal/factcache/factcachetest"
)

// These tests run Up and Down with the fact-cache cleanup NewManager has
// outside the tests (TestMain replaces it for every other test), against
// two real directories: the cache ansible.cfg resolves (the fake
// ansible-config prints captured output pointing at it) and the one
// `pilot deploy` reads, <stateDir>/ansible/fact-cache. The oracle is what is
// left in the directories, not what was called. They mirror the tests of
// internal/vmtarget: the two backends are parallel implementations.

// useProductionDropFacts makes the managers built after this call get the
// production fact cache cleanup, bound to their stateDir.
func useProductionDropFacts(t *testing.T) {
	t.Helper()
	saved := defaultDropFacts
	defaultDropFacts = productionDropFacts
	t.Cleanup(func() { defaultDropFacts = saved })
}

// runSnapshotShim is loggingShim, except that `docker run` records what
// both cache directories hold at that moment into
// $PILOT_FACT_AT_RUN/{ambient,deploy}: the point where Up starts the
// container.
const runSnapshotShim = `echo "$1" >> "$PILOT_DOCKER_LOG"
case "$1" in
  inspect) exit 1 ;;
  run)     ls -A "$PILOT_FACT_AMBIENT" > "$PILOT_FACT_AT_RUN/ambient" ; ls -A "$PILOT_FACT_DEPLOY" > "$PILOT_FACT_AT_RUN/deploy" ; echo "cid-facts" ;;
  *)       exit 0 ;;
esac`

// Cache entries as Ansible names them (ansible-core 2.19 schema prefix,
// and the unprefixed pre-2.19 form) for the hosts of the target below.
var (
	targetEntries = []string{"s1_vb-ntp", "vb-ntp", "s1_core", "core", "s1_ntp", "ntp"}
	// Names a pattern that is too loose would also remove: other hosts, a
	// host whose name extends or ends in a target's, files Ansible does
	// not read as cache entries.
	neighbourEntries = []string{"s1_vb-ntp-cand", "s1_xcore", "s1_ntp2", ".s1_vb-ntp", "s1_vb-ntp.bak", "s1_other"}
)

func sortedNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func seedCache(t *testing.T, dir string, names ...string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func wantNames(names ...string) string {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

// TestUpAndDown_DropFactsFromEveryCacheDeployReads: a target recreated
// under a name used within the cache timeout must not be served the facts
// of the one it replaces, whichever cache a later `pilot deploy` reads. Up
// removes them from both caches before the container is started, Down
// removes them again, and other hosts' entries stay.
func TestUpAndDown_DropFactsFromEveryCacheDeployReads(t *testing.T) {
	useProductionDropFacts(t)
	ambient := t.TempDir()
	factcachetest.InstallOnPath(t, "jsonfile", ambient, "")
	m, stateDir := newTestManager(t, runSnapshotShim)
	deploy := factcache.RuntimeDir(stateDir)
	atRun := t.TempDir()
	t.Setenv("PILOT_DOCKER_LOG", filepath.Join(t.TempDir(), "docker.log"))
	t.Setenv("PILOT_FACT_AMBIENT", ambient)
	t.Setenv("PILOT_FACT_DEPLOY", deploy)
	t.Setenv("PILOT_FACT_AT_RUN", atRun)
	dirs := map[string]string{"ambient": ambient, "deploy": deploy}
	for _, dir := range dirs {
		seedCache(t, dir, append(append([]string(nil), targetEntries...), neighbourEntries...)...)
	}

	if _, err := m.Up(context.Background(), Options{Name: "vb-ntp", Image: "u", Hosts: []string{"core", "ntp"}}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	for name, dir := range dirs {
		// What `docker run` saw: the target's entries were already gone
		// (and the snapshot is of the real directory, not of an empty one).
		data, err := os.ReadFile(filepath.Join(atRun, name))
		if err != nil {
			t.Fatalf("the docker run shim recorded nothing for the %s cache: %v", name, err)
		}
		if got := strings.Fields(string(data)); wantNames(got...) != wantNames(neighbourEntries...) {
			t.Errorf("%s cache at docker run = %v, want only the neighbours %v: Up started the container before dropping its facts", name, got, neighbourEntries)
		}
		if got := strings.Join(sortedNames(t, dir), ","); got != wantNames(neighbourEntries...) {
			t.Errorf("%s cache after Up = %s, want %s", name, got, wantNames(neighbourEntries...))
		}
	}

	// A deploy after Up caches the new target's facts again; Down must
	// clear them from both caches.
	for _, dir := range dirs {
		seedCache(t, dir, targetEntries...)
	}
	if err := m.Down(context.Background(), "vb-ntp"); err != nil {
		t.Fatalf("Down: %v", err)
	}
	for name, dir := range dirs {
		if got := strings.Join(sortedNames(t, dir), ","); got != wantNames(neighbourEntries...) {
			t.Errorf("%s cache after Down = %s, want %s", name, got, wantNames(neighbourEntries...))
		}
	}
}

// TestUpAndDown_MissingCachesAreLeftAlone: no cache directory is created
// for a target that never had facts, and Down of a target whose caches are
// already empty succeeds.
func TestUpAndDown_MissingCachesAreLeftAlone(t *testing.T) {
	useProductionDropFacts(t)
	ambient := filepath.Join(t.TempDir(), "never-created")
	factcachetest.InstallOnPath(t, "jsonfile", ambient, "")
	m, stateDir := newTestManager(t, loggingShim)
	t.Setenv("PILOT_DOCKER_LOG", filepath.Join(t.TempDir(), "docker.log"))

	if _, err := m.Up(context.Background(), Options{Name: "vb-new", Image: "u"}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := m.Down(context.Background(), "vb-new"); err != nil {
		t.Fatalf("Down: %v", err)
	}
	for _, dir := range []string{ambient, filepath.Join(stateDir, "ansible")} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s was created (stat error %v)", dir, err)
		}
	}
}

// breakDeployCache replaces the deploy cache directory with a regular file,
// so that reading it fails (ENOTDIR) for whoever runs the test.
func breakDeployCache(t *testing.T, stateDir string) {
	t.Helper()
	deploy := factcache.RuntimeDir(stateDir)
	if err := os.RemoveAll(deploy); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(deploy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deploy, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestUp_RefusesWhenTheDeployCacheCannotBeCleaned: failing to clean the
// cache `pilot deploy` reads stops Up before it starts anything or writes
// state, exactly as for the cache ansible.cfg resolves.
func TestUp_RefusesWhenTheDeployCacheCannotBeCleaned(t *testing.T) {
	useProductionDropFacts(t)
	ambient := t.TempDir()
	factcachetest.InstallOnPath(t, "jsonfile", ambient, "")
	seedCache(t, ambient, "s1_vb-x", "s1_other")
	m, stateDir := newTestManager(t, loggingShim)
	breakDeployCache(t, stateDir)
	dockerLog := filepath.Join(t.TempDir(), "docker.log")
	t.Setenv("PILOT_DOCKER_LOG", dockerLog)

	_, err := m.Up(context.Background(), Options{Name: "vb-x", Image: "u"})
	if err == nil || !strings.Contains(err.Error(), "drop cached Ansible facts") || !strings.Contains(err.Error(), factcache.RuntimeDir(stateDir)) {
		t.Fatalf("Up error = %v, want the deploy cache failure naming %s", err, factcache.RuntimeDir(stateDir))
	}
	if data, _ := os.ReadFile(dockerLog); strings.Contains(string(data), "run") {
		t.Fatalf("docker run was called although the deploy cache could not be cleaned:\n%s", data)
	}
	if all, _ := m.List(context.Background()); len(all) != 0 {
		t.Fatalf("Up left state behind: %+v", all)
	}
	// The other cache was still cleaned: one failure does not skip the rest.
	if got := strings.Join(sortedNames(t, ambient), ","); got != "s1_other" {
		t.Fatalf("ambient cache = %s, want s1_other", got)
	}
}

// TestDown_ToleratesAnUncleanableDeployCache: Down is best effort, so a
// deploy cache that cannot be cleaned does not stop the teardown (the next
// Up refuses instead).
func TestDown_ToleratesAnUncleanableDeployCache(t *testing.T) {
	useProductionDropFacts(t)
	ambient := t.TempDir()
	factcachetest.InstallOnPath(t, "jsonfile", ambient, "")
	m, stateDir := newTestManager(t, loggingShim)
	t.Setenv("PILOT_DOCKER_LOG", filepath.Join(t.TempDir(), "docker.log"))
	if _, err := m.Up(context.Background(), Options{Name: "vb-down", Image: "u"}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	seedCache(t, ambient, "s1_vb-down", "s1_other")
	breakDeployCache(t, stateDir)

	if err := m.Down(context.Background(), "vb-down"); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if all, _ := m.List(context.Background()); len(all) != 0 {
		t.Fatalf("state after Down: %+v", all)
	}
	if got := strings.Join(sortedNames(t, ambient), ","); got != "s1_other" {
		t.Fatalf("ambient cache = %s, want s1_other", got)
	}
}
