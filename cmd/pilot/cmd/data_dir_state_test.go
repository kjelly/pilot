package cmd

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/statefile"
	"github.com/kjelly/pilot/internal/vmtarget"
)

// isolateDataDirInputs clears every input of the data dir precedence for
// one test: --data-dir, $PILOT_DATA_DIR, the config file and $HOME.
func isolateDataDirInputs(t *testing.T) (home string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("PILOT_DATA_DIR", "")
	savedDataDir, savedCfgFile := dataDir, cfgFile
	dataDir, cfgFile = "", ""
	t.Cleanup(func() { dataDir, cfgFile = savedDataDir, savedCfgFile })
	resetLegacyStateWarnings()
	t.Cleanup(resetLegacyStateWarnings)
	return home
}

func resetLegacyStateWarnings() {
	legacyStateMu.Lock()
	defer legacyStateMu.Unlock()
	legacyStateWarned = map[string]bool{}
}

func writeConfigDataDir(t *testing.T, home, dir string) {
	t.Helper()
	p := filepath.Join(home, ".config", "pilot", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("data_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDataDirPrecedenceIsTheSameForEveryCommand: evidence, vm-target,
// docker-target, access grants and services all resolve the data dir as
// --data-dir, then $PILOT_DATA_DIR, then the config file's data_dir, then
// ~/.local/share/pilot.
func TestDataDirPrecedenceIsTheSameForEveryCommand(t *testing.T) {
	cases := []struct {
		name              string
		flag, env, config string
		wantUnderHome     string
	}{
		{name: "default", wantUnderHome: ".local/share/pilot"},
		{name: "config data_dir", config: "/srv/pilot-config"},
		{name: "PILOT_DATA_DIR over config", env: "/srv/pilot-env", config: "/srv/pilot-config"},
		{name: "--data-dir over everything", flag: "/srv/pilot-flag", env: "/srv/pilot-env", config: "/srv/pilot-config"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := isolateDataDirInputs(t)
			if tc.config != "" {
				writeConfigDataDir(t, home, tc.config)
			}
			if tc.env != "" {
				t.Setenv("PILOT_DATA_DIR", tc.env)
			}
			dataDir = tc.flag
			want := tc.flag
			switch {
			case want != "":
			case tc.env != "":
				want = tc.env
			case tc.config != "":
				want = tc.config
			default:
				want = filepath.Join(home, tc.wantUnderHome)
			}
			for name, got := range map[string]string{
				"resolvePilotDataDir":  resolvePilotDataDir(),
				"resolveStateDir":      resolveStateDir(),
				"loadConfig().DataDir": loadConfig().DataDir,
			} {
				if got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
		})
	}
}

// saveVMTargetState writes a vm-targets.json holding one target, through
// the same statefile store the vmtarget package uses (state version 1).
func saveVMTargetState(t *testing.T, dir, name string) {
	t.Helper()
	store, err := statefile.New[vmtarget.Target](dir, "vm-targets.json", 1, "vmtarget")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save([]vmtarget.Target{{Name: name, Status: vmtarget.StatusRunning}}); err != nil {
		t.Fatal(err)
	}
}

func runVMTargetListJSON(t *testing.T) string {
	t.Helper()
	var out bytes.Buffer
	rootCmd.SetArgs([]string{"vm-target", "list", "--json"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(io.Discard)
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("pilot vm-target list: %v", err)
	}
	return out.String()
}

// captureStderr swaps os.Stderr for a file, because the root command's
// PersistentPreRun points slog at os.Stderr on every Execute. It returns
// what was written so far.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	savedStderr, savedLogger := os.Stderr, slog.Default()
	os.Stderr = f
	t.Cleanup(func() {
		os.Stderr = savedStderr
		slog.SetDefault(savedLogger)
		_ = f.Close()
	})
	return func() string {
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

// TestVMTargetListReadsStateFromPilotDataDir drives the real command:
// with $PILOT_DATA_DIR set, vm-target reads its state there. Before the
// data dir was unified it read ~/.local/share/pilot regardless.
func TestVMTargetListReadsStateFromPilotDataDir(t *testing.T) {
	home := isolateDataDirInputs(t)
	envDir := filepath.Join(home, "isolated")
	t.Setenv("PILOT_DATA_DIR", envDir)
	saveVMTargetState(t, envDir, "dd-in-env-dir")
	saveVMTargetState(t, filepath.Join(home, ".local", "share", "pilot"), "dd-in-default-dir")
	stderr := captureStderr(t)

	out := runVMTargetListJSON(t)
	if !strings.Contains(out, `"dd-in-env-dir"`) || strings.Contains(out, "dd-in-default-dir") {
		t.Fatalf("vm-target list = %s, want only the target from $PILOT_DATA_DIR", out)
	}
	if strings.Contains(stderr(), "found_in=") {
		t.Fatalf("unexpected notice while the data dir has its own state: %s", stderr())
	}
}

// TestVMTargetListNoticesStateLeftInTheOldDataDir: the state is only where
// an older pilot kept it, so the command warns once, naming the file, where
// it is and the data dir in use, and changes nothing. It reports only its
// own state file, not another command's.
func TestVMTargetListNoticesStateLeftInTheOldDataDir(t *testing.T) {
	home := isolateDataDirInputs(t)
	oldDir := filepath.Join(home, ".local", "share", "pilot")
	envDir := filepath.Join(home, "isolated")
	t.Setenv("PILOT_DATA_DIR", envDir)
	saveVMTargetState(t, oldDir, "dd-in-default-dir")
	if err := os.WriteFile(filepath.Join(oldDir, "services.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr := captureStderr(t)

	if out := runVMTargetListJSON(t); strings.Contains(out, "dd-in-default-dir") {
		t.Fatalf("vm-target list = %s, want no target from the old data dir", out)
	}
	for _, want := range []string{"level=WARN", "file=vm-targets.json", "found_in=" + oldDir, "data_dir=" + envDir} {
		if !strings.Contains(stderr(), want) {
			t.Fatalf("notice %q missing from: %s", want, stderr())
		}
	}
	_ = runVMTargetListJSON(t)
	if n := strings.Count(stderr(), "file=vm-targets.json"); n != 1 {
		t.Fatalf("notice printed %d times, want once per process", n)
	}
	if strings.Contains(stderr(), "file=services.json") {
		t.Fatalf("vm-target reported another command's state file: %s", stderr())
	}
	if _, err := os.Stat(filepath.Join(oldDir, "vm-targets.json")); err != nil {
		t.Fatalf("old state was touched: %v", err)
	}
	if _, err := os.Stat(filepath.Join(envDir, "vm-targets.json")); !os.IsNotExist(err) {
		t.Fatalf("state was copied into the new data dir (stat err %v)", err)
	}
}

// TestLegacyStateNotices covers which files are reported, for each legacy
// resolver: vm-target/docker-target/access grants used ~/.local/share/pilot;
// services used the config file's data_dir.
func TestLegacyStateNotices(t *testing.T) {
	root := t.TempDir()
	def, cfgDir, cur := filepath.Join(root, "default"), filepath.Join(root, "config"), filepath.Join(root, "current")
	touch := func(dir, f string) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	touch(def, "vm-targets.json")
	touch(def, "breakglass-activations.json")
	touch(def, "services.json") // services never used the default when data_dir was set
	touch(cfgDir, "services.json")
	touch(cur, "breakglass-activations.json")
	locs := []legacyStateLocation{
		{dir: def, files: []string{"vm-targets.json", "docker-targets.json", "breakglass-activations.json", "auth-policy-hosts.json"}},
		{dir: cfgDir, files: []string{"services.json"}},
	}
	all := []string{"vm-targets.json", "docker-targets.json", "breakglass-activations.json", "auth-policy-hosts.json", "services.json"}
	got := legacyStateNotices(cur, all, locs)
	want := []legacyStateNotice{{file: "vm-targets.json", from: def}, {file: "services.json", from: cfgDir}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("notices = %+v, want %+v", got, want)
	}
	if got := legacyStateNotices(cur, servicesStateFiles, locs); len(got) != 1 || got[0] != want[1] {
		t.Fatalf("notices for services only = %+v, want %+v", got, want[1:])
	}
	if got := legacyStateNotices(def, all, locs[:1]); len(got) != 0 {
		t.Fatalf("notices for the dir itself = %+v, want none", got)
	}
	dataDir = "/explicit"
	t.Cleanup(func() { dataDir = "" })
	if locs := legacyStateLocations(); locs != nil {
		t.Fatalf("legacyStateLocations with --data-dir = %+v, want nil (the flag always won)", locs)
	}
}

// TestExecPilotForwardsTheDataDir: a child pilot (vm-target/docker-target
// verify) gets this process's data dir, so --data-dir reaches it.
func TestExecPilotForwardsTheDataDir(t *testing.T) {
	isolateDataDirInputs(t)
	dataDir = "/srv/pilot-flag"
	var got []string
	saved := newCmd
	newCmd = func(ctx context.Context, bin string, args ...string) *exec.Cmd {
		got = args
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { newCmd = saved })
	if err := execPilot(io.Discard, "verify", "spec.md", "-i", "inv.yml"); err != nil {
		t.Fatalf("execPilot: %v", err)
	}
	want := []string{"verify", "--data-dir=/srv/pilot-flag", "spec.md", "-i", "inv.yml"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("child args = %q, want %q", got, want)
	}
}

// TestDataDirIsResolvedInOnePlace keeps the precedence in loadConfig: no
// other non-test file in this package reads $PILOT_DATA_DIR, builds the
// ~/.local/share/pilot default, or loads the config file for its data dir.
func TestDataDirIsResolvedInOnePlace(t *testing.T) {
	rules := []struct {
		re      *regexp.Regexp
		allowed map[string]bool
	}{
		{regexp.MustCompile(`Getenv\("PILOT_DATA_DIR"\)`), map[string]bool{"root.go": true}},
		{regexp.MustCompile(`"\.local",\s*"share"`), map[string]bool{}},
		{regexp.MustCompile(`config\.Default\(\)\.DataDir`), map[string]bool{"data_dir_state.go": true}},
		{regexp.MustCompile(`config\.Load\(`), map[string]bool{"root.go": true, "data_dir_state.go": true}},
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			if r.re.Match(src) && !r.allowed[f] {
				t.Errorf("%s matches %s: resolve the data dir with resolvePilotDataDir or resolveStateDir", f, r.re)
			}
		}
	}
}

// TestApplyRootFlags: vm-target run and verify turn off cobra's flag
// parsing, so they take the root --data-dir and --config themselves and do
// not pass them on to ansible-playbook or pilot verify.
func TestApplyRootFlags(t *testing.T) {
	isolateDataDirInputs(t)
	rest := applyRootFlags([]string{"--name", "vm1", "--data-dir", "/srv/d", "spec.md", "-e", "a=b", "--config=/etc/pilot.yaml"})
	if dataDir != "/srv/d" || cfgFile != "/etc/pilot.yaml" {
		t.Fatalf("dataDir=%q cfgFile=%q, want /srv/d and /etc/pilot.yaml", dataDir, cfgFile)
	}
	if want := "--name vm1 spec.md -e a=b"; strings.Join(rest, " ") != want {
		t.Fatalf("remaining args = %q, want %q", rest, want)
	}
}

// TestVMTargetVerifyHonoursDataDirFlag drives the real command: vm-target
// verify turns off cobra's flag parsing, so before applyRootFlags a
// --data-dir given to it was ignored and the target was looked up in the
// default data dir.
func TestVMTargetVerifyHonoursDataDirFlag(t *testing.T) {
	home := isolateDataDirInputs(t)
	dir := filepath.Join(home, "flag-dir")
	saveVMTargetState(t, dir, "dd-flag-target")
	savedName := vtName
	vtName = ""
	t.Cleanup(func() { vtName = savedName })
	rootCmd.SetArgs([]string{"vm-target", "verify", "--data-dir", dir, "--name", "dd-flag-target", filepath.Join(home, "spec.md")})
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })
	err := rootCmd.Execute()
	if err != nil && strings.Contains(err.Error(), `no target named "dd-flag-target"`) {
		t.Fatalf("vm-target verify looked outside --data-dir: %v", err)
	}
}
