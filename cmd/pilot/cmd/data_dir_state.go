package cmd

import (
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/kjelly/pilot/internal/config"
)

// The local state files each command family keeps in the data dir.
var (
	vmTargetStateFiles     = []string{"vm-targets.json"}
	dockerTargetStateFiles = []string{"docker-targets.json"}
	accessStateFiles       = []string{"breakglass-activations.json", "auth-policy-hosts.json"}
	servicesStateFiles     = []string{"services.json"}
)

// resolveStateDir is resolvePilotDataDir for commands that keep local state
// (vm-target, docker-target, access grants, services); files are the state
// files the caller uses. Before 2026-09-25 those commands ignored
// $PILOT_DATA_DIR, and some also ignored the config file's data_dir, so a
// file may still sit in the directory they used then. resolveStateDir
// reports each such file once per process; it never moves or deletes
// anything.
func resolveStateDir(files ...string) string {
	dir := resolvePilotDataDir()
	warnLegacyState(dir, files)
	return dir
}

// legacyStateLocation is where one pre-2026-09-25 resolver kept state.
type legacyStateLocation struct {
	dir   string
	files []string
}

// legacyStateNotice is a state file found only at a legacy location.
type legacyStateNotice struct {
	file string
	from string
}

// legacyStateLocations returns where the state commands kept their files
// before every command used resolvePilotDataDir. --data-dir always won, so
// with the flag set nothing moved.
func legacyStateLocations() []legacyStateLocation {
	if dataDir != "" {
		return nil
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		cfg = config.Default()
	}
	return []legacyStateLocation{
		// vm-target, docker-target and access grants used --data-dir or
		// ~/.local/share/pilot, ignoring PILOT_DATA_DIR and data_dir.
		{dir: config.Default().DataDir, files: []string{
			"vm-targets.json", "docker-targets.json",
			"breakglass-activations.json", "auth-policy-hosts.json",
		}},
		// services honoured data_dir but ignored PILOT_DATA_DIR.
		{dir: cfg.DataDir, files: []string{"services.json"}},
	}
}

// legacyStateNotices lists which of files are missing from current, the
// data dir now in use, but present where an older pilot kept them.
func legacyStateNotices(current string, files []string, locs []legacyStateLocation) []legacyStateNotice {
	var out []legacyStateNotice
	for _, loc := range locs {
		if loc.dir == "" || samePath(loc.dir, current) {
			continue
		}
		for _, f := range loc.files {
			if !slices.Contains(files, f) {
				continue
			}
			if fileExists(filepath.Join(loc.dir, f)) && !fileExists(filepath.Join(current, f)) {
				out = append(out, legacyStateNotice{file: f, from: loc.dir})
			}
		}
	}
	return out
}

var (
	legacyStateMu     sync.Mutex
	legacyStateWarned = map[string]bool{}
)

func warnLegacyState(current string, files []string) {
	legacyStateMu.Lock()
	defer legacyStateMu.Unlock()
	var pending []string
	for _, f := range files {
		if !legacyStateWarned[f] {
			legacyStateWarned[f] = true
			pending = append(pending, f)
		}
	}
	if len(pending) == 0 {
		return
	}
	for _, n := range legacyStateNotices(current, pending, legacyStateLocations()) {
		slog.Warn("local state is in the data dir an older pilot used for it; move the file into data_dir, or pass --data-dir with found_in, to keep managing it",
			"file", n.file, "found_in", n.from, "data_dir", current)
	}
}

func samePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return absA == absB
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// applyRootFlags honours the root --data-dir and --config for the commands
// that turn off cobra's flag parsing (vm-target run and verify), and
// removes them from args so they are not passed on to ansible-playbook or
// pilot verify.
func applyRootFlags(args []string) []string {
	var v string
	if args, v = extractValueFlag(args, "--data-dir"); v != "" {
		dataDir = v
	}
	if args, v = extractValueFlag(args, "--config"); v != "" {
		cfgFile = v
	}
	return args
}
