package factcache

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// noSuchAnsibleConfig is a bare name that is not on PATH, like
// ansible-config on a host without Ansible.
func noSuchAnsibleConfig(t *testing.T) {
	t.Helper()
	old := ansibleConfigBin
	ansibleConfigBin = "pilot-test-no-such-ansible-config"
	t.Cleanup(func() { ansibleConfigBin = old })
	if _, err := exec.LookPath(ansibleConfigBin); err == nil {
		t.Fatalf("test setup: %s resolves on PATH", ansibleConfigBin)
	}
}

// failingAnsibleConfig makes ansible-config exit 1.
func failingAnsibleConfig(t *testing.T) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "ansible-config")
	writeFile(t, bin, "#!/bin/sh\necho 'ERROR: boom' >&2\nexit 1\n")
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	old := ansibleConfigBin
	ansibleConfigBin = bin
	t.Cleanup(func() { ansibleConfigBin = old })
}

// seed writes one empty cache file per name into dir, creating it.
func seed(t *testing.T, dir string, names ...string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		writeFile(t, filepath.Join(dir, n), "{}")
	}
}

func left(t *testing.T, dir string) string {
	t.Helper()
	return strings.Join(listDir(t, dir), ",")
}

func TestRuntimeDir(t *testing.T) {
	t.Run("a data dir under the data dir", func(t *testing.T) {
		d := t.TempDir()
		if got, want := RuntimeDir(d), filepath.Join(d, "ansible", "fact-cache"); got != want {
			t.Fatalf("RuntimeDir(%s) = %s, want %s", d, got, want)
		}
	})
	t.Run("is cleaned, not joined twice", func(t *testing.T) {
		if got, want := RuntimeDir("/srv/pilot/./sub/../data/"), "/srv/pilot/data/ansible/fact-cache"; got != want {
			t.Fatalf("RuntimeDir = %s, want %s", got, want)
		}
		if got := RuntimeDir("/srv/pilot"); strings.Count(got, "ansible") != 1 || strings.Count(got, "fact-cache") != 1 {
			t.Fatalf("RuntimeDir = %s joins a segment twice", got)
		}
	})
	t.Run("a relative data dir is made absolute once", func(t *testing.T) {
		cwd := t.TempDir()
		t.Chdir(cwd)
		wd, err := os.Getwd() // the working directory as the OS spells it
		if err != nil {
			t.Fatal(err)
		}
		got := RuntimeDir("data")
		if want := filepath.Join(wd, "data", "ansible", "fact-cache"); got != want {
			t.Fatalf("RuntimeDir(data) = %s, want %s", got, want)
		}
		if !filepath.IsAbs(got) {
			t.Fatalf("RuntimeDir(data) = %s is not absolute", got)
		}
	})
}

func TestRuntimeEnvPinsJSONFileAtRuntimeDir(t *testing.T) {
	d := t.TempDir()
	want := []string{"ANSIBLE_CACHE_PLUGIN=jsonfile", "ANSIBLE_CACHE_PLUGIN_CONNECTION=" + RuntimeDir(d)}
	got := RuntimeEnv(d)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("RuntimeEnv = %v, want %v", got, want)
	}
}

// The hosts of every DropAll test below. s1_web is a 2.19 schema entry and
// web a pre-2.19 one, both of host web; the neighbours must stay.
var (
	dropHosts  = []string{"web"}
	webEntries = []string{"s1_web", "web"}
	neighbours = []string{"s1_web2", "s1_xweb", ".s1_web", "s1_web.bak", "s1_db"}
	allSeeded  = append(append([]string(nil), webEntries...), neighbours...)
)

// survivors is what listDir returns (sorted) once web's entries are gone.
const survivors = ".s1_web,s1_db,s1_web.bak,s1_web2,s1_xweb"

func TestDropAll_CleansTheAmbientAndTheDeployCache(t *testing.T) {
	ambient, data := t.TempDir(), t.TempDir()
	seed(t, ambient, allSeeded...)
	seed(t, RuntimeDir(data), allSeeded...)
	fakeAnsibleConfig(t, "jsonfile", ambient, "")

	if err := DropAll(context.Background(), data, dropHosts); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{"ambient": ambient, "deploy": RuntimeDir(data)} {
		if got := left(t, dir); got != survivors {
			t.Errorf("%s cache left %s, want %s", name, got, survivors)
		}
	}
}

func TestDropAll_WithoutAnsibleConfigStillCleansTheDeployCache(t *testing.T) {
	data := t.TempDir()
	seed(t, RuntimeDir(data), allSeeded...)
	noSuchAnsibleConfig(t)

	if err := DropAll(context.Background(), data, dropHosts); err != nil {
		t.Fatalf("DropAll without ansible-config: %v", err)
	}
	if got := left(t, RuntimeDir(data)); got != survivors {
		t.Fatalf("deploy cache left %s, want %s", got, survivors)
	}
}

// The deploy cache is found from the data dir alone, not from where this
// process runs or what ansible.cfg says: the ambient cache is a different
// directory and the working directory is unrelated.
func TestDropAll_DeployCacheDoesNotDependOnTheWorkingDirectory(t *testing.T) {
	ambient, data := t.TempDir(), t.TempDir()
	seed(t, ambient, "s1_web")
	seed(t, RuntimeDir(data), "s1_web", "s1_db")
	fakeAnsibleConfig(t, "jsonfile", ambient, "")
	t.Chdir(t.TempDir())

	if err := DropAll(context.Background(), data, dropHosts); err != nil {
		t.Fatal(err)
	}
	if got := left(t, RuntimeDir(data)); got != "s1_db" {
		t.Fatalf("deploy cache left %s, want s1_db", got)
	}
}

func TestDropAll_MissingDirectoriesAreLeftAlone(t *testing.T) {
	data := filepath.Join(t.TempDir(), "never-created")
	fakeAnsibleConfig(t, "jsonfile", filepath.Join(t.TempDir(), "no-ambient-cache"), "")

	if err := DropAll(context.Background(), data, dropHosts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(data); !os.IsNotExist(err) {
		t.Fatalf("DropAll created the data directory: %v", err)
	}
	// Idempotent: a second call is the same no-op.
	if err := DropAll(context.Background(), data, dropHosts); err != nil {
		t.Fatalf("second DropAll: %v", err)
	}
}

func TestDropAll_NoHostsRemovesNothing(t *testing.T) {
	ambient, data := t.TempDir(), t.TempDir()
	seed(t, ambient, "s1_web")
	seed(t, RuntimeDir(data), "s1_web")
	fakeAnsibleConfig(t, "jsonfile", ambient, "")
	if err := DropAll(context.Background(), data, nil); err != nil {
		t.Fatal(err)
	}
	if left(t, ambient) != "s1_web" || left(t, RuntimeDir(data)) != "s1_web" {
		t.Fatalf("DropAll(no hosts) removed files: ambient %s, deploy %s", left(t, ambient), left(t, RuntimeDir(data)))
	}
}

func TestDropAll_RequiresTheDataDirectory(t *testing.T) {
	fakeAnsibleConfig(t, "memory", t.TempDir(), "")
	if err := DropAll(context.Background(), "", dropHosts); err == nil || !strings.Contains(err.Error(), "data directory is required") {
		t.Fatalf("DropAll(\"\") error = %v, want the missing data directory", err)
	}
}

// One failing cache must not skip the other, and both failures are reported.
func TestDropAll_AFailureInOneCacheDoesNotSkipTheOther(t *testing.T) {
	t.Run("deploy cache unreadable", func(t *testing.T) {
		ambient, data := t.TempDir(), t.TempDir()
		seed(t, ambient, "s1_web", "s1_db")
		fakeAnsibleConfig(t, "jsonfile", ambient, "")
		// A regular file where the directory should be: ReadDir fails with
		// ENOTDIR whoever runs the test (chmod would not stop root).
		seed(t, filepath.Join(data, "ansible"), "fact-cache")

		err := DropAll(context.Background(), data, dropHosts)
		if err == nil || !strings.Contains(err.Error(), "deploy fact cache") || !strings.Contains(err.Error(), RuntimeDir(data)) {
			t.Fatalf("DropAll error = %v, want the deploy cache failure naming %s", err, RuntimeDir(data))
		}
		if got := left(t, ambient); got != "s1_db" {
			t.Fatalf("ambient cache left %s, want s1_db: the deploy failure skipped it", got)
		}
	})
	t.Run("ambient resolution fails", func(t *testing.T) {
		data := t.TempDir()
		seed(t, RuntimeDir(data), "s1_web", "s1_db")
		failingAnsibleConfig(t)

		err := DropAll(context.Background(), data, dropHosts)
		if err == nil || !strings.Contains(err.Error(), "ERROR: boom") {
			t.Fatalf("DropAll error = %v, want the ansible-config failure", err)
		}
		if got := left(t, RuntimeDir(data)); got != "s1_db" {
			t.Fatalf("deploy cache left %s, want s1_db: the ambient failure skipped it", got)
		}
	})
}

// The deploy runtime only pins the plugin and its directory, so Ansible
// names its files with the prefix the ambient jsonfile cache has. When the
// ambient plugin is not jsonfile no prefix is known and none is assumed.
func TestDropAll_DeployCachePrefixFollowsTheAmbientJSONFileCache(t *testing.T) {
	for _, tc := range []struct {
		name, plugin, prefix, want string
	}{
		{"jsonfile with a prefix", "ansible.builtin.jsonfile", "pfx_", "s1_web,web"},
		{"jsonfile without one", "jsonfile", "", "pfx_s1_web,pfx_web"},
		{"memory", "memory", "", "pfx_s1_web,pfx_web"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := t.TempDir()
			seed(t, RuntimeDir(data), "pfx_s1_web", "pfx_web", "s1_web", "web")
			fakeAnsibleConfig(t, tc.plugin, t.TempDir(), tc.prefix)
			if err := DropAll(context.Background(), data, dropHosts); err != nil {
				t.Fatal(err)
			}
			if got := left(t, RuntimeDir(data)); got != tc.want {
				t.Fatalf("deploy cache left %s, want %s", got, tc.want)
			}
		})
	}
}

// An operator who points ansible.cfg at the deploy directory has one cache,
// cleaned once.
func TestDropAll_AmbientCacheThatIsTheDeployCacheIsCleanedOnce(t *testing.T) {
	data := t.TempDir()
	seed(t, RuntimeDir(data), allSeeded...)
	fakeAnsibleConfig(t, "jsonfile", RuntimeDir(data), "")
	if err := DropAll(context.Background(), data, dropHosts); err != nil {
		t.Fatal(err)
	}
	if got := left(t, RuntimeDir(data)); got != survivors {
		t.Fatalf("cache left %s, want %s", got, survivors)
	}
}

func TestDropper_BindsTheDataDirectory(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	seed(t, RuntimeDir(a), "s1_web")
	seed(t, RuntimeDir(b), "s1_web")
	noSuchAnsibleConfig(t)
	if err := Dropper(a)(context.Background(), dropHosts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(RuntimeDir(a), "s1_web")); !os.IsNotExist(err) {
		t.Errorf("the bound data directory was not cleaned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(RuntimeDir(b), "s1_web")); err != nil {
		t.Errorf("another data directory was cleaned: %v", err)
	}
}

// requireAnsible reports whether real Ansible is installed. Without it the
// test skips, except where PILOT_REQUIRE_CONTAINER_TESTS=1 says the run is
// meant to have it (the convention of the other real-Ansible regressions):
// there a missing tool fails.
func requireAnsible(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"ansible", "ansible-config"} {
		if _, err := exec.LookPath(bin); err != nil {
			if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
				t.Fatalf("required %s not installed: %v", bin, err)
			}
			t.Skipf("%s not installed", bin)
		}
	}
}

// ansibleSetup runs a real ad-hoc `setup` on the local connection for hosts
// so that Ansible itself writes (and names) their fact-cache entries. extra
// is appended to the environment, after ansible's own isolation settings.
func ansibleSetup(t *testing.T, dir string, hosts []string, extra ...string) {
	t.Helper()
	var inv strings.Builder
	for _, h := range hosts {
		inv.WriteString(h + " ansible_connection=local\n")
	}
	invFile := filepath.Join(dir, "inventory.ini")
	writeFile(t, invFile, inv.String())
	cmd := exec.Command("ansible", "all", "-i", invFile, "-m", "ansible.builtin.setup", "-a", "gather_subset=min")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "tmp"),
		"ANSIBLE_HOME="+filepath.Join(dir, "home"),
		"ANSIBLE_PYTHON_INTERPRETER=auto_silent",
	)
	cmd.Env = append(cmd.Env, extra...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ansible setup: %v\n%s", err, out)
	}
}

// TestDropAll_RealAnsibleDeployRuntime is the oracle for the deploy cache:
// real Ansible, started with exactly RuntimeEnv, writes and names the files,
// and DropAll must remove the dropped host's entry from there and from the
// cache ansible.cfg resolves, leaving the other host's in both. The three
// subtests differ in what the ambient configuration looks like, because the
// deploy cache must be cleaned in all of them.
func TestDropAll_RealAnsibleDeployRuntime(t *testing.T) {
	requireAnsible(t)

	newCfg := func(t *testing.T, ambient string) {
		t.Helper()
		cfg := filepath.Join(t.TempDir(), "ansible.cfg")
		writeFile(t, cfg, "[defaults]\nfact_caching = jsonfile\nfact_caching_connection = "+ambient+"\nfact_caching_timeout = 3600\n")
		t.Setenv("ANSIBLE_CONFIG", cfg)
	}
	hosts := []string{"vb-a", "vb-b"}
	entries := func(t *testing.T, dir string) []string {
		t.Helper()
		got := listDir(t, dir)
		if len(got) != 2 {
			t.Fatalf("ansible cached %v in %s, want one file per host", got, dir)
		}
		return got
	}
	assertOnlyB := func(t *testing.T, dir string, before []string) {
		t.Helper()
		after := listDir(t, dir)
		if len(after) != 1 || !strings.HasSuffix(after[0], "vb-b") {
			t.Fatalf("%s after DropAll(vb-a): %v (before %v), want only vb-b's entry", dir, after, before)
		}
	}

	t.Run("ansible.cfg has its own cache", func(t *testing.T) {
		dir, data, ambient := t.TempDir(), t.TempDir(), filepath.Join(t.TempDir(), "ambient")
		newCfg(t, ambient)
		ansibleSetup(t, dir, hosts)                      // ambient: what ansible.cfg resolves
		ansibleSetup(t, dir, hosts, RuntimeEnv(data)...) // deploy: what prepareDeployAnsibleRuntime pins
		beforeAmbient, beforeDeploy := entries(t, ambient), entries(t, RuntimeDir(data))

		if err := DropAll(context.Background(), data, []string{"vb-a"}); err != nil {
			t.Fatal(err)
		}
		assertOnlyB(t, ambient, beforeAmbient)
		assertOnlyB(t, RuntimeDir(data), beforeDeploy)
	})

	t.Run("no ansible.cfg and a working directory without one", func(t *testing.T) {
		// Nothing configures a cache for this process: ansible-config
		// reports the memory plugin, so there is no ambient cache at all.
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("ANSIBLE_CONFIG", "")
		if err := os.Unsetenv("ANSIBLE_CONFIG"); err != nil {
			t.Fatal(err)
		}
		work := t.TempDir()
		t.Chdir(work)
		if store, err := Resolve(context.Background()); err != nil || store.Dir != "" || !isMemory(store.Plugin) {
			t.Fatalf("test setup: the ambient configuration is %+v (err %v), want no file cache", store, err)
		}
		data := t.TempDir()
		ansibleSetup(t, work, hosts, RuntimeEnv(data)...)
		before := entries(t, RuntimeDir(data))

		if err := DropAll(context.Background(), data, []string{"vb-a"}); err != nil {
			t.Fatal(err)
		}
		assertOnlyB(t, RuntimeDir(data), before)
	})

	t.Run("ansible-config is not installed", func(t *testing.T) {
		data := t.TempDir()
		ansibleSetup(t, t.TempDir(), hosts, RuntimeEnv(data)...)
		before := entries(t, RuntimeDir(data))
		noSuchAnsibleConfig(t)

		if err := DropAll(context.Background(), data, []string{"vb-a"}); err != nil {
			t.Fatal(err)
		}
		assertOnlyB(t, RuntimeDir(data), before)
	})
}
