package vmtarget

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
// left in the directories, not what was called.

// useProductionDropFacts makes the managers built after this call get the
// production fact cache cleanup, bound to their stateDir.
func useProductionDropFacts(t *testing.T) {
	t.Helper()
	saved := defaultDropFacts
	defaultDropFacts = productionDropFacts
	t.Cleanup(func() { defaultDropFacts = saved })
}

// defineSnapshotVirsh is happyVirsh, except that `virsh define` records
// what both cache directories hold at that moment into
// $PILOT_FACT_AT_DEFINE/{ambient,deploy}: the point of no return of Up.
const defineSnapshotVirsh = `  define)             ls -A "$PILOT_FACT_AMBIENT" > "$PILOT_FACT_AT_DEFINE/ambient" ; ls -A "$PILOT_FACT_DEPLOY" > "$PILOT_FACT_AT_DEFINE/deploy" ; exit 0 ;;
` + happyVirsh

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

// TestUpAndDown_DropFactsFromEveryCacheDeployReads: a VM recreated under a
// name used within the cache timeout must not be served the facts of the
// one it replaces, whichever cache a later `pilot deploy` reads. Up removes
// them from both caches before anything is created, Down removes them again,
// and other hosts' entries stay.
func TestUpAndDown_DropFactsFromEveryCacheDeployReads(t *testing.T) {
	useProductionDropFacts(t)
	ambient := t.TempDir()
	factcachetest.InstallOnPath(t, "jsonfile", ambient, "")
	m, base := newTestManager(t, defineSnapshotVirsh)
	deploy := factcache.RuntimeDir(m.stateDir)
	atDefine := t.TempDir()
	t.Setenv("PILOT_FACT_AMBIENT", ambient)
	t.Setenv("PILOT_FACT_DEPLOY", deploy)
	t.Setenv("PILOT_FACT_AT_DEFINE", atDefine)
	dirs := map[string]string{"ambient": ambient, "deploy": deploy}
	for _, dir := range dirs {
		seedCache(t, dir, append(append([]string(nil), targetEntries...), neighbourEntries...)...)
	}

	if _, err := m.Up(context.Background(), Options{Name: "vb-ntp", BaseImage: base, Hosts: []string{"core", "ntp"}}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	for name, dir := range dirs {
		// What `virsh define` saw: the target's entries were already gone
		// (and the snapshot is of the real directory, not of an empty one).
		data, err := os.ReadFile(filepath.Join(atDefine, name))
		if err != nil {
			t.Fatalf("the virsh define shim recorded nothing for the %s cache: %v", name, err)
		}
		if got := strings.Fields(string(data)); wantNames(got...) != wantNames(neighbourEntries...) {
			t.Errorf("%s cache at virsh define = %v, want only the neighbours %v: Up created the VM before dropping its facts", name, got, neighbourEntries)
		}
		if got := strings.Join(sortedNames(t, dir), ","); got != wantNames(neighbourEntries...) {
			t.Errorf("%s cache after Up = %s, want %s", name, got, wantNames(neighbourEntries...))
		}
	}

	// A deploy after Up caches the new VM's facts again; Down must clear
	// them from both caches.
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
	m, base := newTestManager(t, happyVirsh)

	if _, err := m.Up(context.Background(), Options{Name: "vb-new", BaseImage: base}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := m.Down(context.Background(), "vb-new"); err != nil {
		t.Fatalf("Down: %v", err)
	}
	for _, dir := range []string{ambient, filepath.Join(m.stateDir, "ansible")} {
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
// cache `pilot deploy` reads stops Up before it reserves the name or creates
// anything, exactly as for the cache ansible.cfg resolves.
func TestUp_RefusesWhenTheDeployCacheCannotBeCleaned(t *testing.T) {
	useProductionDropFacts(t)
	ambient := t.TempDir()
	factcachetest.InstallOnPath(t, "jsonfile", ambient, "")
	seedCache(t, ambient, "s1_vb-x", "s1_other")
	m, base := newTestManager(t, happyVirsh)
	breakDeployCache(t, m.stateDir)
	virshLog := filepath.Join(t.TempDir(), "virsh.log")
	t.Setenv("PILOT_VIRSH_LOG", virshLog)

	_, err := m.Up(context.Background(), Options{Name: "vb-x", BaseImage: base})
	if err == nil || !strings.Contains(err.Error(), "drop cached Ansible facts") || !strings.Contains(err.Error(), factcache.RuntimeDir(m.stateDir)) {
		t.Fatalf("Up error = %v, want the deploy cache failure naming %s", err, factcache.RuntimeDir(m.stateDir))
	}
	if all, _ := m.List(context.Background()); len(all) != 0 {
		t.Fatalf("Up left a state record behind: %+v", all)
	}
	if data, _ := os.ReadFile(virshLog); strings.Contains(string(data), "define ") {
		t.Fatalf("Up defined a domain although the deploy cache could not be cleaned:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(m.vmDir, "vb-x")); !os.IsNotExist(err) {
		t.Fatalf("Up created the target dir: %v", err)
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
	m, base := newTestManager(t, happyVirsh)
	if _, err := m.Up(context.Background(), Options{Name: "vb-down", BaseImage: base}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	seedCache(t, ambient, "s1_vb-down", "s1_other")
	breakDeployCache(t, m.stateDir)

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
