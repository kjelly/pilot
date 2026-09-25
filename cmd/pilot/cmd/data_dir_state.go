package cmd

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/kjelly/pilot/internal/config"
)

// resolveStateDir is resolvePilotDataDir for commands that keep local state
// (vm-target, docker-target, access grants, services). Before 2026-09-25
// those commands ignored $PILOT_DATA_DIR, and some also ignored the config
// file's data_dir, so their state may still sit in the directory they used
// then. resolveStateDir reports that once per process; it never moves or
// deletes anything.
func resolveStateDir() string {
	dir := resolvePilotDataDir()
	warnLegacyStateOnce(dir)
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

// legacyStateNotices lists the files in locs that are missing from current,
// the data dir now in use, but present where an older pilot kept them.
func legacyStateNotices(current string, locs []legacyStateLocation) []legacyStateNotice {
	var out []legacyStateNotice
	for _, loc := range locs {
		if loc.dir == "" || samePath(loc.dir, current) {
			continue
		}
		for _, f := range loc.files {
			if fileExists(filepath.Join(loc.dir, f)) && !fileExists(filepath.Join(current, f)) {
				out = append(out, legacyStateNotice{file: f, from: loc.dir})
			}
		}
	}
	return out
}

var legacyStateWarned atomic.Bool

func warnLegacyStateOnce(current string) {
	if !legacyStateWarned.CompareAndSwap(false, true) {
		return
	}
	for _, n := range legacyStateNotices(current, legacyStateLocations()) {
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
