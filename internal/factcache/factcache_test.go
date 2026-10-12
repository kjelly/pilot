package factcache

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The fixtures under testdata are real `ansible-config dump --format json`
// and `ansible-config dump -t cache --format json` output (ansible-core
// 2.19.2) with the repo ansible.cfg, trimmed to a few base settings and
// with local paths replaced: /repo/ansible.cfg for the config file and
// @CACHE_DIR@ for the jsonfile cache directory.

// fakeAnsibleConfig points ansibleConfigBin at a script that prints the
// base fixture (with CACHE_PLUGIN set to plugin) or, for `-t cache`, the
// cache fixture with cacheDir and prefix substituted.
func fakeAnsibleConfig(t *testing.T, plugin, cacheDir, prefix string) {
	t.Helper()
	dir := t.TempDir()
	base := readFixture(t, "dump-jsonfile.json")
	base = strings.Replace(base, `"value": "jsonfile"`, `"value": "`+plugin+`"`, 1)
	cache := strings.ReplaceAll(readFixture(t, "dump-cache-jsonfile.json"), "@CACHE_DIR@", cacheDir)
	if prefix != "" {
		cache = strings.Replace(cache, `"origin": "default",
                "value": null`, `"origin": "env: ANSIBLE_CACHE_PLUGIN_PREFIX",
                "value": "`+prefix+`"`, 1)
	}
	writeFile(t, filepath.Join(dir, "base.json"), base)
	writeFile(t, filepath.Join(dir, "cache.json"), cache)
	script := "#!/bin/sh\n" +
		"echo \"$*\" >> " + filepath.Join(dir, "calls") + "\n" +
		"case \"$*\" in\n" +
		"  *'-t cache'*) cat " + filepath.Join(dir, "cache.json") + " ;;\n" +
		"  *) cat " + filepath.Join(dir, "base.json") + " ;;\n" +
		"esac\n"
	bin := filepath.Join(dir, "ansible-config")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := ansibleConfigBin
	ansibleConfigBin = bin
	t.Cleanup(func() { ansibleConfigBin = old })
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func listDir(t *testing.T, dir string) []string {
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

func TestResolve_JSONFileUsesPluginOptions(t *testing.T) {
	cacheDir := t.TempDir()
	fakeAnsibleConfig(t, "jsonfile", cacheDir, "")
	store, err := Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The base dump says CACHE_PLUGIN_PREFIX=ansible_facts (its default),
	// but the jsonfile plugin's own _prefix is unset: real cache files are
	// named s1_<host>, not ansible_factss1_<host>.
	if store.Plugin != "jsonfile" || store.Dir != cacheDir || store.Prefix != "" {
		t.Fatalf("Resolve = %+v, want plugin jsonfile, dir %s, no prefix", store, cacheDir)
	}
}

func TestResolve_ConfiguredPrefix(t *testing.T) {
	cacheDir := t.TempDir()
	fakeAnsibleConfig(t, "ansible.builtin.jsonfile", cacheDir, "pfx_")
	store, err := Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if store.Dir != cacheDir || store.Prefix != "pfx_" {
		t.Fatalf("Resolve = %+v, want dir %s and prefix pfx_", store, cacheDir)
	}
}

func TestResolve_NonFilePluginsHaveNoDir(t *testing.T) {
	for _, plugin := range []string{"memory", "community.general.redis"} {
		t.Run(plugin, func(t *testing.T) {
			fakeAnsibleConfig(t, plugin, t.TempDir(), "")
			store, err := Resolve(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if store.Plugin != plugin || store.Dir != "" {
				t.Fatalf("Resolve = %+v, want plugin %s and no directory", store, plugin)
			}
		})
	}
}

func TestResolve_AnsibleConfigFailureIsAnError(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "ansible-config")
	writeFile(t, bin, "#!/bin/sh\necho 'ERROR: boom' >&2\nexit 1\n")
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	old := ansibleConfigBin
	ansibleConfigBin = bin
	t.Cleanup(func() { ansibleConfigBin = old })
	if _, err := Resolve(context.Background()); err == nil || !strings.Contains(err.Error(), "ERROR: boom") {
		t.Fatalf("Resolve error = %v, want the ansible-config failure", err)
	}
	if err := Drop(context.Background(), []string{"vb-1"}); err == nil {
		t.Fatal("Drop must fail when the cache location cannot be resolved")
	}
}

func TestPurge_RemovesOnlyTheNamedHosts(t *testing.T) {
	dir := t.TempDir()
	files := []string{
		"s1_vb-ntp",      // ansible-core 2.19 schema prefix: remove
		"s1_core",        // alias: remove
		"s2_ntp",         // a later schema id: remove
		"vb-ntp",         // pre-2.19 name: remove
		"s1_vb-ntp-cand", // a different host whose name extends vb-ntp: keep
		"s1_xcore",       // a different host ending in core: keep
		"s1_other",       // unrelated: keep
		".s1_vb-ntp",     // not a cache file Ansible reads: keep
		"s1_vb-ntp.bak",  // keep
	}
	for _, f := range files {
		writeFile(t, filepath.Join(dir, f), "{}")
	}
	removed, err := Store{Plugin: "jsonfile", Dir: dir}.Purge([]string{"vb-ntp", "core", "ntp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 4 {
		t.Errorf("removed %v, want 4 files", removed)
	}
	want := []string{".s1_vb-ntp", "s1_other", "s1_vb-ntp-cand", "s1_vb-ntp.bak", "s1_xcore"}
	if got := listDir(t, dir); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("left %v, want %v", got, want)
	}
}

func TestPurge_HonoursPrefix(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"pfx_s1_vb-1", "pfx_vb-1", "s1_vb-1"} {
		writeFile(t, filepath.Join(dir, f), "{}")
	}
	if _, err := (Store{Plugin: "jsonfile", Dir: dir, Prefix: "pfx_"}).Purge([]string{"vb-1"}); err != nil {
		t.Fatal(err)
	}
	// s1_vb-1 has no prefix, so Ansible with this prefix never reads it.
	if got := listDir(t, dir); strings.Join(got, ",") != "s1_vb-1" {
		t.Fatalf("left %v, want only s1_vb-1", got)
	}
}

func TestPurge_MissingDirAndNoHostsAreNoOps(t *testing.T) {
	if removed, err := (Store{Dir: filepath.Join(t.TempDir(), "absent")}).Purge([]string{"vb-1"}); err != nil || removed != nil {
		t.Fatalf("missing dir: removed=%v err=%v", removed, err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "s1_vb-1"), "{}")
	if _, err := (Store{Dir: dir}).Purge(nil); err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, dir); len(got) != 1 {
		t.Fatalf("Purge(nil) removed files: left %v", got)
	}
}

func TestDrop_RemovesCachedFactsThroughAnsibleConfig(t *testing.T) {
	cacheDir := t.TempDir()
	writeFile(t, filepath.Join(cacheDir, "s1_vb-1"), "{}")
	writeFile(t, filepath.Join(cacheDir, "s1_vb-2"), "{}")
	fakeAnsibleConfig(t, "jsonfile", cacheDir, "")
	if err := Drop(context.Background(), []string{"vb-1"}); err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, cacheDir); strings.Join(got, ",") != "s1_vb-2" {
		t.Fatalf("left %v, want only s1_vb-2", got)
	}
}

func TestDrop_MemoryPluginAndMissingAnsibleAreNoOps(t *testing.T) {
	fakeAnsibleConfig(t, "memory", t.TempDir(), "")
	if err := Drop(context.Background(), []string{"vb-1"}); err != nil {
		t.Fatal(err)
	}
	// A bare name that is not on PATH, like ansible-config on a host
	// without Ansible.
	ansibleConfigBin = "pilot-test-no-such-ansible-config"
	if _, err := exec.LookPath(ansibleConfigBin); !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("test setup: %s resolves on PATH (%v)", ansibleConfigBin, err)
	}
	if err := Drop(context.Background(), []string{"vb-1"}); err != nil {
		t.Fatalf("Drop without ansible-config: %v", err)
	}
}

// TestDrop_RealAnsible runs real Ansible: an ad-hoc setup fills a jsonfile
// cache named by Ansible itself, and Drop must remove exactly the named
// host's entry through the same ansible.cfg (ANSIBLE_CONFIG).
func TestDrop_RealAnsible(t *testing.T) {
	for _, bin := range []string{"ansible", "ansible-config"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	cfg := filepath.Join(dir, "ansible.cfg")
	writeFile(t, cfg, "[defaults]\ngathering = smart\nfact_caching = jsonfile\nfact_caching_connection = "+cacheDir+"\nfact_caching_timeout = 3600\ninterpreter_python = auto_silent\n")
	inv := filepath.Join(dir, "inventory.ini")
	writeFile(t, inv, "vb-a ansible_connection=local\nvb-b ansible_connection=local\n")
	t.Setenv("ANSIBLE_CONFIG", cfg)
	t.Setenv("ANSIBLE_LOCAL_TEMP", filepath.Join(dir, "tmp"))
	t.Setenv("ANSIBLE_HOME", filepath.Join(dir, "home"))

	setup := exec.Command("ansible", "all", "-i", inv, "-m", "ansible.builtin.setup", "-a", "gather_subset=min")
	if out, err := setup.CombinedOutput(); err != nil {
		t.Fatalf("ansible setup: %v\n%s", err, out)
	}
	before := listDir(t, cacheDir)
	if len(before) != 2 {
		t.Fatalf("ansible cached %v, want one file per host", before)
	}

	if err := Drop(context.Background(), []string{"vb-a"}); err != nil {
		t.Fatal(err)
	}
	after := listDir(t, cacheDir)
	if len(after) != 1 || !strings.HasSuffix(after[0], "vb-b") {
		t.Fatalf("after Drop(vb-a): %v (before %v), want only vb-b's entry", after, before)
	}
}
