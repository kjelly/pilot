package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	// testIsolationRoot is the per-run directory isolatePilotUserDirs
	// points pilot's data dir and config file lookups at.
	testIsolationRoot string
	// hostXDGConfigHome is XDG_CONFIG_HOME before isolatePilotUserDirs
	// changed it, for tools that must keep the operator's own config.
	hostXDGConfigHome, hadHostXDGConfigHome = os.LookupEnv("XDG_CONFIG_HOME")
)

// isolatePilotUserDirs points every pilot data-dir and config-file lookup in
// this test binary, and in the pilot processes its tests start, at a fresh
// temporary directory. Without it, a test that forgets its own
// PILOT_DATA_DIR writes into the operator's ~/.local/share/pilot (history.db
// checkpoints, the Ansible runtime and log), and every loadConfig() reads
// the operator's ~/.config/pilot/config.yaml.
//
// It sets environment variables rather than the dataDir package variable:
// tests reset dataDir to "" in their cleanups, which would undo it. A test
// that needs its own directory still uses t.Setenv or dataDir, and t.Setenv
// restores this value afterwards.
func isolatePilotUserDirs() (cleanup func(), err error) {
	root, err := os.MkdirTemp("", "pilot-cmd-test-")
	if err != nil {
		return nil, err
	}
	for name, dir := range map[string]string{
		"PILOT_DATA_DIR":  filepath.Join(root, "data"),
		"XDG_CONFIG_HOME": filepath.Join(root, "config"),
	} {
		if err := os.Setenv(name, dir); err != nil {
			_ = os.RemoveAll(root)
			return nil, fmt.Errorf("set %s: %w", name, err)
		}
	}
	testIsolationRoot = root
	return func() { _ = os.RemoveAll(root) }, nil
}

// hostToolEnv is the test process environment with the operator's
// XDG_CONFIG_HOME restored, for host tools such as `go build` whose own
// settings (`go env -w`) live under the user config dir.
func hostToolEnv() []string {
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "XDG_CONFIG_HOME=") {
			env = append(env, kv)
		}
	}
	if hadHostXDGConfigHome {
		env = append(env, "XDG_CONFIG_HOME="+hostXDGConfigHome)
	}
	return env
}

// TestPackageTestsUseIsolatedPilotDirs guards isolatePilotUserDirs: with no
// per-test override, the data dir and the config file both resolve inside
// the per-run directory, never under the operator's home.
func TestPackageTestsUseIsolatedPilotDirs(t *testing.T) {
	savedDataDir, savedCfgFile := dataDir, cfgFile
	dataDir, cfgFile = "", ""
	t.Cleanup(func() { dataDir, cfgFile = savedDataDir, savedCfgFile })

	if testIsolationRoot == "" {
		t.Fatal("TestMain did not call isolatePilotUserDirs")
	}
	inRoot := func(p string) bool {
		return strings.HasPrefix(p, testIsolationRoot+string(os.PathSeparator))
	}
	if got := resolvePilotDataDir(); !inRoot(got) {
		t.Errorf("resolvePilotDataDir() = %q, want a path under %q", got, testIsolationRoot)
	}
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("os.UserConfigDir: %v", err)
	}
	if !inRoot(cfgDir) {
		t.Errorf("os.UserConfigDir() = %q (loadConfig reads pilot/config.yaml there), want a path under %q", cfgDir, testIsolationRoot)
	}
}
