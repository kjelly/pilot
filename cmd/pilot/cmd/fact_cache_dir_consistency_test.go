package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/dockertarget"
	"github.com/kjelly/pilot/internal/factcache"
	"github.com/kjelly/pilot/internal/factcache/factcachetest"
	"github.com/kjelly/pilot/internal/statefile"
	"github.com/kjelly/pilot/internal/vmtarget"
)

// The Ansible fact cache `pilot deploy` (and reconcile, the MCP server,
// gateway-scope, host-decommission) reads is decided in
// prepareDeployAnsibleRuntime. The lifecycle commands that recreate a host
// (vm-target, docker-target) have to clean that same directory, not only the
// one ansible.cfg resolves. These tests tie the two together: the directory
// the deploy runtime pins is factcache.RuntimeDir of the data dir, the data
// dir the lifecycle commands use is the one deploy uses, and a real
// `vm-target down` / `docker-target down` empties it (kjelly/pilot#336).

// lastEnv returns the value Ansible sees for key: the last KEY=value entry,
// as exec resolves duplicates.
func lastEnv(env []string, key string) (string, bool) {
	value, found := "", false
	for _, entry := range env {
		if v, ok := strings.CutPrefix(entry, key+"="); ok {
			value, found = v, true
		}
	}
	return value, found
}

func sortedEntries(t *testing.T, dir string) string {
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
	return strings.Join(names, ",")
}

func seedFactCache(t *testing.T, dir string, names ...string) {
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

// TestDeployFactCacheIsTheDirectoryTheLifecycleCommandsDrop: one data dir,
// one fact-cache directory, whatever the operator exports.
func TestDeployFactCacheIsTheDirectoryTheLifecycleCommandsDrop(t *testing.T) {
	home := isolateDataDirInputs(t)
	data := filepath.Join(home, "pilot-data")
	t.Setenv("PILOT_DATA_DIR", data)
	// An operator-exported cache location does not move deploy's cache:
	// the runtime's value comes last.
	t.Setenv("ANSIBLE_CACHE_PLUGIN", "memory")
	t.Setenv("ANSIBLE_CACHE_PLUGIN_CONNECTION", filepath.Join(home, "operator-cache"))
	ambient := filepath.Join(home, "ambient-cache")
	factcachetest.InstallOnPath(t, "jsonfile", ambient, "")

	// Every command resolves the same data dir.
	deployDir := resolvePilotDataDir()
	for name, got := range map[string]string{
		"vm-target":     resolveStateDir(vmTargetStateFiles...),
		"docker-target": resolveStateDir(dockerTargetStateFiles...),
	} {
		if got != deployDir {
			t.Fatalf("%s keeps its state in %s but deploy uses %s: they would drop and read different fact caches", name, got, deployDir)
		}
	}

	runtime, err := prepareDeployAnsibleRuntime(deployDir)
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), runtime.Env...)
	plugin, _ := lastEnv(env, "ANSIBLE_CACHE_PLUGIN")
	connection, found := lastEnv(env, "ANSIBLE_CACHE_PLUGIN_CONNECTION")
	if !found || plugin != "jsonfile" {
		t.Fatalf("deploy runtime pins plugin %q, connection %q (found %v), want jsonfile and a directory", plugin, connection, found)
	}
	// The consistency: deploy's cache directory is factcache's definition of
	// it for the data dir the lifecycle commands are bound to.
	stateDir := resolveStateDir(vmTargetStateFiles...)
	if want := factcache.RuntimeDir(stateDir); connection != want {
		t.Fatalf("deploy reads the fact cache in %s, but a lifecycle command bound to %s drops %s", connection, stateDir, want)
	}

	// And the cleanup the Managers are bound to purges exactly that
	// directory, from a working directory that has nothing to do with it.
	seedFactCache(t, connection, "s1_s1web", "s1_s1web2", "s1_other")
	seedFactCache(t, ambient, "s1_s1web", "s1_other")
	t.Chdir(t.TempDir())
	if err := factcache.Dropper(stateDir)(context.Background(), []string{"s1web"}); err != nil {
		t.Fatal(err)
	}
	if got := sortedEntries(t, connection); got != "s1_other,s1_s1web2" {
		t.Fatalf("deploy cache holds %s after the drop, want s1_other,s1_s1web2", got)
	}
	if got := sortedEntries(t, ambient); got != "s1_other" {
		t.Fatalf("ambient cache holds %s after the drop, want s1_other", got)
	}
}

// runLifecycleCommand runs one pilot command and returns what it wrote to
// stderr (slog warnings), restoring the flag variables it sets.
func runLifecycleCommand(t *testing.T, args ...string) string {
	t.Helper()
	stderr := captureStderr(t)
	savedVT, savedDT := vtName, dtName
	t.Cleanup(func() { vtName, dtName = savedVT, savedDT })
	rootCmd.SetArgs(args)
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("pilot %s: %v", strings.Join(args, " "), err)
	}
	return stderr()
}

func writeExitZeroShim(t *testing.T, name, envKey string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envKey, p)
}

// lifecycleFactCaches seeds the cache ansible.cfg resolves and the one
// deploy reads, for a target s1web (also known as host web), with
// neighbours that must survive, and returns the two directories.
func lifecycleFactCaches(t *testing.T, data string) (ambient, deploy string) {
	t.Helper()
	ambient = filepath.Join(filepath.Dir(data), "ambient-cache")
	deploy = factcache.RuntimeDir(data)
	factcachetest.InstallOnPath(t, "jsonfile", ambient, "")
	for _, dir := range []string{ambient, deploy} {
		seedFactCache(t, dir, "s1_s1web", "s1_web", "web", "s1_s1web2", "s1_xweb", "s1_other")
	}
	return ambient, deploy
}

const lifecycleSurvivors = "s1_other,s1_s1web2,s1_xweb"

// TestVMTargetDownCleansTheFactCacheDeployReads drives the real command, as
// the issue's reproduction does: before the fix `vm-target down` left the
// target's s1_<host> entry in <data-dir>/ansible/fact-cache.
func TestVMTargetDownCleansTheFactCacheDeployReads(t *testing.T) {
	home := isolateDataDirInputs(t)
	data := filepath.Join(home, "pilot-data")
	t.Setenv("PILOT_DATA_DIR", data)
	t.Setenv("PILOT_SSH_CONTROL_BASE", t.TempDir())
	writeExitZeroShim(t, "virsh", "PILOT_VIRSH_BIN")
	store, err := statefile.New[vmtarget.Target](data, "vm-targets.json", 1, "vmtarget")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save([]vmtarget.Target{{Name: "s1web", Hosts: []string{"web"}, Status: vmtarget.StatusRunning}}); err != nil {
		t.Fatal(err)
	}
	ambient, deploy := lifecycleFactCaches(t, data)

	stderr := runLifecycleCommand(t, "vm-target", "down", "--name", "s1web")

	if strings.Contains(stderr, "failed to drop cached Ansible facts") {
		t.Fatalf("down could not clean the fact cache: %s", stderr)
	}
	for name, dir := range map[string]string{"deploy": deploy, "ambient": ambient} {
		if got := sortedEntries(t, dir); got != lifecycleSurvivors {
			t.Errorf("%s fact cache holds %s after `vm-target down`, want %s", name, got, lifecycleSurvivors)
		}
	}
}

// TestDockerTargetDownCleansTheFactCacheDeployReads is the same for the
// docker backend (AGENTS.md §5.1: the two backends are parallel).
func TestDockerTargetDownCleansTheFactCacheDeployReads(t *testing.T) {
	home := isolateDataDirInputs(t)
	data := filepath.Join(home, "pilot-data")
	t.Setenv("PILOT_DATA_DIR", data)
	writeExitZeroShim(t, "docker", "PILOT_DOCKER_BIN")
	store, err := statefile.New[dockertarget.Target](data, "docker-targets.json", 1, "dockertarget")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save([]dockertarget.Target{{Name: "s1web", Hosts: []string{"web"}, Status: dockertarget.StatusRunning}}); err != nil {
		t.Fatal(err)
	}
	ambient, deploy := lifecycleFactCaches(t, data)

	stderr := runLifecycleCommand(t, "docker-target", "down", "--name", "s1web")

	if strings.Contains(stderr, "failed to drop cached Ansible facts") {
		t.Fatalf("down could not clean the fact cache: %s", stderr)
	}
	for name, dir := range map[string]string{"deploy": deploy, "ambient": ambient} {
		if got := sortedEntries(t, dir); got != lifecycleSurvivors {
			t.Errorf("%s fact cache holds %s after `docker-target down`, want %s", name, got, lifecycleSurvivors)
		}
	}
}
