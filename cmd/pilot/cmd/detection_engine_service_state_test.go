package cmd

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"go.yaml.in/yaml/v3"
)

// loadDetectionEnginePlay returns the real install block, its real rescue and the real
// Step 0* tasks that precede the block (read-only probe + its fail-closed assert, and
// the read-only snapshot of the files the rescue restores), with the
// unprivileged owner/group dropped from copy/file tasks.
func loadDetectionEnginePlay(t *testing.T) (probes, block, rescue []any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRootForTest(t), "playbooks", "apply", "detection-engine-apply.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	for _, play := range plays {
		tasks, _ := play["tasks"].([]any)
		for _, task := range tasks {
			m, ok := task.(map[string]any)
			if !ok {
				continue
			}
			if m["name"] == "Detection Engine install + systemd service" {
				block, _ = m["block"].([]any)
				rescue, _ = m["rescue"].([]any)
			}
			if name, _ := m["name"].(string); strings.HasPrefix(name, "Step 0") {
				probes = append(probes, m)
			}
		}
	}
	for _, list := range [][]any{block, rescue} {
		for _, task := range list {
			m, _ := task.(map[string]any)
			// the config restore passes the originals' uid/gid on purpose (tests chgrp to a
			// group the unprivileged test user belongs to); every other task has root/pilot-detect
			if name, _ := m["name"].(string); strings.HasPrefix(name, "ROLLBACK — restore the unit, config") {
				continue
			}
			stripDetectionEngineTestOwnership(m)
			for _, module := range []string{"ansible.builtin.copy", "ansible.builtin.file"} {
				if args, ok := m[module].(map[string]any); ok {
					delete(args, "owner")
					delete(args, "group")
				}
			}
		}
	}
	if len(block) == 0 || len(rescue) == 0 {
		t.Fatal("the install block or its rescue is gone from detection-engine-apply.yml")
	}
	if len(probes) != 6 {
		t.Fatalf("found %d Step 0* tasks outside the install block, want 6 (the authority reset, systemctl show probe, its assert, and the stat/slurp/unit-existed snapshot of the files the rescue restores): "+
			"the snapshots must be taken and validated before the block, whose rescue stops the service", len(probes))
	}
	return
}

// detectionEngineRollbackFilesVar returns the playbook's own detection_engine_rollback_files
// (templated against the harness vars at run time).
func detectionEngineRollbackFilesVar(t *testing.T) any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRootForTest(t), "playbooks", "apply", "detection-engine-apply.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	for _, play := range plays {
		if vars, ok := play["vars"].(map[string]any); ok && vars["detection_engine_rollback_files"] != nil {
			return vars["detection_engine_rollback_files"]
		}
	}
	t.Fatal("detection_engine_rollback_files is gone from the playbook vars")
	return nil
}

// loadDetectionEngineBlock returns the real install block and its real rescue.
func loadDetectionEngineBlock(t *testing.T) (block, rescue []any) {
	t.Helper()
	_, block, rescue = loadDetectionEnginePlay(t)
	return
}

// loadDetectionEngineProbes returns the real Step 0* tasks (probe, assert, file snapshots).
func loadDetectionEngineProbes(t *testing.T) []any {
	t.Helper()
	probes, _, _ := loadDetectionEnginePlay(t)
	return probes
}

// A stand-in for systemctl with the bits of real semantics that matter here: state lives
// in $FAKE_SD/{loaded,active,enabled}; start/stop/enable/disable of an unknown unit fail;
// `show` reports a unit that does not exist as inactive with an empty UnitFileState and
// exit 0 (as the real one does; checked against systemd on Ubuntu 24.04/26.04).
//
// The active/enabled files may hold the state name (default "active"/"enabled"):
// "activating", "reloading", "enabled-runtime". A plain `disable` leaves a runtime
// (enabled-runtime) link alone, exactly like real systemd (checked against a systemd user
// manager: `enable --runtime` then `disable` still shows UnitFileState=enabled-runtime).
//
// Fault injection by marker files: show_fail_once (the next `show` exits 1 and the marker
// goes away), show_fail_always, show_raw (`show` prints that file's content, exit 0),
// show_raw_rc (exit code of the show_raw output, default 0), enable_fail, restart_fail.
// With FAKE_HEALTH_CFG/FAKE_HEALTH_MARK set, start/restart leave the unit "activating" (a
// crash loop) unless that config file contains the marker, like a real unit whose
// ExecStart needs a good config.
const fakeSystemctl = `#!/bin/bash
sd=$FAKE_SD; cmd=; skip=0
for a in "$@"; do
  if [ $skip = 1 ]; then skip=0; continue; fi
  case "$a" in -p|--property) skip=1;; -*) ;; *) [ -z "$cmd" ] && cmd=$a;; esac
done
echo "$*" >> $sd/calls.log
kind() { local v; v=$(cat "$sd/$1"); echo "${v:-$2}"; }
case "$cmd" in
 show) [ -e $sd/show_fail_always ] && { echo "Failed to connect to bus" >&2; exit 1; }
       [ -e $sd/show_fail_once ] && { rm -f $sd/show_fail_once; echo "Failed to connect to bus" >&2; exit 1; }
       [ -e $sd/show_raw ] && { cat $sd/show_raw; exit $(cat $sd/show_raw_rc 2>/dev/null || echo 0); }
       if [ -e $sd/loaded ]; then echo LoadState=loaded
         [ -e $sd/active ] && echo ActiveState=$(kind active active) || echo ActiveState=inactive
         [ -e $sd/enabled ] && echo UnitFileState=$(kind enabled enabled) || echo UnitFileState=disabled
       else echo LoadState=not-found; echo ActiveState=inactive; echo UnitFileState=; fi ;;
 is-enabled) [ -e $sd/enabled ] && { kind enabled enabled; exit 0; }; echo disabled; exit 1 ;;
 start|restart) [ -e $sd/loaded ] || exit 5; [ -e $sd/restart_fail ] && exit 1
       # a unit whose ExecStart needs the config: with a config that lacks the marker the
       # start "succeeds" and the unit crash-loops (Restart=on-failure -> activating)
       if [ -n "$FAKE_HEALTH_CFG" ] && ! grep -q "$FAKE_HEALTH_MARK" "$FAKE_HEALTH_CFG" 2>/dev/null; then echo activating > $sd/active
       else echo active > $sd/active; fi ;;
 stop) [ -e $sd/loaded ] || exit 5; rm -f $sd/active ;;
 enable) [ -e $sd/loaded ] || exit 1; [ -e $sd/enable_fail ] && exit 1; echo enabled > $sd/enabled ;;
 disable) [ -e $sd/loaded ] || exit 1; [ "$(kind enabled enabled)" = enabled ] && rm -f $sd/enabled ;;
 daemon-reload) ;;
 *) exit 1 ;;
esac
`

type fakeUnit struct {
	loaded, active, enabled bool
	activeKind, enabledKind string // "" = plain active/enabled
}

func (u fakeUnit) String() string {
	return fmt.Sprintf("{loaded:%v active:%v(%s) enabled:%v(%s)}", u.loaded, u.active, u.activeKind, u.enabled, u.enabledKind)
}

// harness runs a play made of the given probes + one block/rescue against a fake systemctl
// and reports the unit as the run left it.
type harness struct {
	probes    []any
	steps     []any
	inject    []any
	rescue    []any
	args      []string
	unit      fakeUnit
	flags     []string // marker files for the fake systemctl
	binary    string   // "old", "new" or "" (first install)
	started   bool     // the run itself created/started the unit before failing (Steps 11-14)
	noSystemd bool     // PATH without any systemctl

	files       map[string]string // files that exist before the run: unit, config, profile, provider (provider.env is 0600)
	artifact    string            // content of the artifact Step 6 installs (default deNewBin)
	healthMark  string            // the unit crash-loops unless config.yaml contains this
	vars        map[string]any    // extra playbook vars
	noBlockOnly bool              // run only probes (no block/rescue)
	fileModes   map[string]os.FileMode
	fileGIDs    map[string]int    // chgrp the seeded file to this gid
	symlinks    map[string]bool   // seed this file as a symlink to a real file with the content
	linkKinds   map[string]string // with symlinks: "dangling" (the target does not exist) or "dir" (the target is a directory holding marker.txt)
}

type harnessResult struct {
	log, calls  string
	err         error
	unit        fakeUnit
	bin, db     string
	backupFiles []string
	files       map[string]string // unit, config, profile, provider after the run ("" and absent: see exists)
	exists      map[string]bool
	providerMod os.FileMode
	stats       map[string]fileStat // Lstat of unit, config, profile, provider after the run
}

type fileStat struct {
	mode     os.FileMode
	uid, gid int
	link     string // symlink target, "" for a regular file
}

const (
	deOldBin = "#!/bin/sh\n# old build\nif [ \"$1 $2\" = \"db check\" ]; then echo ok; exit 0; fi\n[ \"$1 $2\" = \"db backup\" ] && cp \"$4\" \"$6\"\n"
	deNewBin = "#!/bin/sh\n# new build\n"
)

func (h harness) run(t *testing.T) harnessResult {
	t.Helper()
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not installed")
	}
	dir := t.TempDir()
	sd, fakebin, backups := filepath.Join(dir, "sd"), filepath.Join(dir, "fakebin"), filepath.Join(dir, "backups")
	for _, d := range []string{sd, fakebin, backups} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, content string, mode os.FileMode) {
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(fakebin, "systemctl"), fakeSystemctl, 0o755)
	for name, on := range map[string]bool{"loaded": h.unit.loaded, "active": h.unit.active, "enabled": h.unit.enabled} {
		if on {
			write(filepath.Join(sd, name), map[string]string{"active": h.unit.activeKind, "enabled": h.unit.enabledKind}[name], 0o600)
		}
	}
	for _, f := range h.flags {
		name, content, _ := strings.Cut(f, "=")
		write(filepath.Join(sd, name), content, 0o600)
	}
	etc := filepath.Join(dir, "etc")
	if err := os.MkdirAll(etc, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := detectionEnginePaths(dir)
	for name, content := range h.files {
		mode := os.FileMode(0o644)
		if name == "provider" {
			mode = 0o600
		}
		if m, ok := h.fileModes[name]; ok {
			mode = m
		}
		target := paths[name]
		if h.symlinks[name] {
			target = filepath.Join(dir, "real-"+name)
		}
		switch h.linkKinds[name] {
		case "dangling":
			// the link is made below; nothing exists at its target
		case "dir":
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(target, "marker.txt"), content, 0o644)
		default:
			write(target, content, mode)
			if err := os.Chmod(target, mode); err != nil {
				t.Fatal(err)
			}
		}
		if gid, ok := h.fileGIDs[name]; ok && h.linkKinds[name] == "" {
			if err := os.Chown(target, -1, gid); err != nil {
				t.Fatal(err)
			}
		}
		if h.symlinks[name] {
			if err := os.Symlink(target, paths[name]); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(filepath.Join(dir, "new-profile.yaml"), "NEW-PROFILE\n", 0o644)
	bin, artifact, db := filepath.Join(dir, "bin"), filepath.Join(dir, "artifact"), filepath.Join(dir, "state.db")
	if h.binary != "" {
		write(bin, map[string]string{"old": deOldBin, "new": deNewBin}[h.binary], 0o755)
		write(db, "state", 0o600)
	}
	newBin := h.artifact
	if newBin == "" {
		newBin = deNewBin
	}
	write(artifact, newBin, 0o755)
	inject := h.inject
	if h.started { // what Steps 11-14 do to the service before a later step fails
		inject = append([]any{map[string]any{"name": "emulate Steps 11-14", "ansible.builtin.shell": "touch " + sd + "/loaded " + sd + "/enabled " + sd + "/active"}}, inject...)
	}
	sum := sha256.Sum256([]byte(newBin))
	tasks := append([]any{}, h.probes...)
	if !h.noBlockOnly {
		tasks = append(tasks, map[string]any{"block": append(append([]any{}, h.steps...), inject...), "rescue": h.rescue,
			"tags": []string{"observability", "detection-engine"}})
	}
	vars := map[string]any{"detection_engine_db_path": db, "detection_engine_bin_dest": bin,
		"detection_engine_backup_dir": backups, "detection_engine_artifact_abs_path": artifact,
		"detection_engine_artifact_sha256": hex.EncodeToString(sum[:]),
		"detection_engine_user":            "pilot-detect", "detection_engine_data_dir": "/var/lib/pilot/detection-engine", "detection_engine_status_path": filepath.Join(dir, "status.json"),
		"detection_engine_textfile_path": filepath.Join(dir, "x.prom"), "detection_metrics_source_alias": "m", "detection_alertmanager_alias": "a",
		"detection_model_provider_enabled": false, "detection_model_provider_protocol": "openai-responses", "detection_model_provider_base_url": "",
		"detection_model_provider_model": "", "detection_model_provider_auth": "none", "detection_model_provider_fallback_enabled": false,
		"detection_model_provider_fallback_protocol": "openai-responses", "detection_model_provider_fallback_base_url": "",
		"detection_model_provider_fallback_model": "", "detection_model_provider_fallback_auth": "none", "detection_log_source_enabled": false,
		"detection_log_source_base_url": "", "detection_log_source_query": "", "detection_log_source_current_window": "5m", "detection_log_source_baseline_window": "1h"}
	for k, v := range detectionEngineSnapshotVars(t, dir) {
		vars[k] = v
	}
	for k, v := range h.vars {
		vars[k] = v
	}
	play := []any{map[string]any{"hosts": "localhost", "connection": "local", "gather_facts": false, "vars": vars, "tasks": tasks}}
	out, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	pb := filepath.Join(dir, "p.yml")
	write(pb, string(out), 0o600)
	path := fakebin + ":" + os.Getenv("PATH")
	if h.noSystemd {
		// A PATH that has every tool of /usr/bin (ansible's shell wrapper and modules need
		// them) except systemctl.
		path = filepath.Join(dir, "nosystemd")
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir("/usr/bin")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "systemctl") {
				continue
			}
			if err := os.Symlink(filepath.Join("/usr/bin", e.Name()), filepath.Join(path, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	cmd := exec.Command(ansible, append([]string{"-i", "localhost,", pb}, h.args...)...)
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "FAKE_SD="+sd, "PATH="+path)
	if h.healthMark != "" {
		cmd.Env = append(cmd.Env, "FAKE_HEALTH_CFG="+paths["config"], "FAKE_HEALTH_MARK="+h.healthMark)
	}
	log, runErr := cmd.CombinedOutput()
	read := func(path string) string { b, _ := os.ReadFile(path); return string(b) }
	exists := func(n string) bool { _, e := os.Stat(filepath.Join(sd, n)); return e == nil }
	res := harnessResult{log: string(log), calls: read(filepath.Join(sd, "calls.log")), err: runErr, bin: read(bin), db: read(db)}
	res.unit = fakeUnit{loaded: exists("loaded"), active: exists("active"), enabled: exists("enabled"),
		activeKind: strings.TrimSpace(read(filepath.Join(sd, "active"))), enabledKind: strings.TrimSpace(read(filepath.Join(sd, "enabled")))}
	res.files, res.exists = map[string]string{}, map[string]bool{}
	for name, path := range paths {
		if b, err := os.ReadFile(path); err == nil {
			res.files[name], res.exists[name] = string(b), true
		}
	}
	res.stats = map[string]fileStat{}
	for name, path := range paths {
		if fi, err := os.Lstat(path); err == nil {
			st := fileStat{mode: fi.Mode().Perm()}
			if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
				st.uid, st.gid = int(sys.Uid), int(sys.Gid)
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				st.link, _ = os.Readlink(path)
			}
			res.stats[name] = st
		}
	}
	if fi, err := os.Stat(paths["provider"]); err == nil {
		res.providerMod = fi.Mode().Perm()
	}
	// the fake writes the plain state name when it starts/enables the unit; "" means plain
	if res.unit.activeKind == "active" {
		res.unit.activeKind = ""
	}
	if res.unit.enabledKind == "enabled" {
		res.unit.enabledKind = ""
	}
	entries, _ := os.ReadDir(backups)
	for _, e := range entries {
		res.backupFiles = append(res.backupFiles, e.Name())
	}
	return res
}

// detectionEnginePaths are the files Steps 8-12 rewrite, under a test dir.
func detectionEnginePaths(dir string) map[string]string {
	etc := filepath.Join(dir, "etc")
	return map[string]string{"etc": etc, "unit": filepath.Join(dir, "pilot-detection-engine.service"), "config": filepath.Join(etc, "config.yaml"),
		"profile": filepath.Join(etc, "feature-profile.yaml"), "provider": filepath.Join(etc, "provider.env")}
}

// detectionEngineSnapshotVars are the vars the Step 0* snapshot tasks (and Steps 8-12) read;
// the list of files to snapshot is the playbook's own.
func detectionEngineSnapshotVars(t *testing.T, dir string) map[string]any {
	t.Helper()
	paths := detectionEnginePaths(dir)
	if err := os.MkdirAll(paths["etc"], 0o700); err != nil {
		t.Fatal(err)
	}
	return map[string]any{"detection_engine_config_dir": paths["etc"], "detection_engine_config_path": paths["config"],
		"detection_engine_feature_profile_dest": paths["profile"], "detection_engine_feature_profile_src": filepath.Join(dir, "new-profile.yaml"),
		"detection_engine_unit_path": paths["unit"], "detection_engine_rollback_files": detectionEngineRollbackFilesVar(t)}
}

func detectionEnginePick(t *testing.T, block []any, prefixes ...string) []any {
	t.Helper()
	var out []any
	for _, task := range block {
		name, _ := task.(map[string]any)["name"].(string)
		for _, p := range prefixes {
			if strings.HasPrefix(name, p) {
				out = append(out, task)
				break
			}
		}
	}
	if len(out) < len(prefixes) {
		t.Fatalf("picked %d tasks for %v", len(out), prefixes)
	}
	return out
}

func detectionEngineRescueSteps(t *testing.T) (probes, steps, rescue []any) {
	t.Helper()
	probes, block, rescue := loadDetectionEnginePlay(t)
	for _, task := range block {
		name, _ := task.(map[string]any)["name"].(string)
		for _, p := range []string{"Step 3", "Step 4", "Step 5", "Step 6:"} {
			if strings.HasPrefix(name, p) {
				steps = append(steps, task)
			}
		}
	}
	if len(steps) != 17 {
		t.Fatalf("picked %d steps, want 17 (Steps 3-6)", len(steps))
	}
	return
}

func injectedFailure(tags []string) []any {
	task := map[string]any{"name": "inject failure", "ansible.builtin.fail": map[string]any{"msg": "boom"}}
	if tags != nil {
		task["tags"] = tags
	}
	return []any{task}
}

// The rescue stops and disables the unit so it can restore the binary/state.db safely; it
// must then put the service back exactly as it was before the run, whatever tags selected
// the failing step. Run with the real Step 0 probe, real Steps 3-6 and the real rescue.
func TestDetectionEngineRescuePutsServiceBack(t *testing.T) {
	probes, steps, rescue := detectionEngineRescueSteps(t)
	c1 := []string{"detection-engine-C1"}
	plain := fakeUnit{loaded: true, active: true, enabled: true}
	for _, tt := range []struct {
		name     string
		before   fakeUnit
		binary   string // "old" (stale), "new" (up to date), "" (first install)
		args     []string
		inject   []any
		flags    []string
		started  bool
		want     fakeUnit
		wantBin  string
		wantWarn []string // phrases the final failure message must contain
	}{
		{"reviewer: skip C1, failure in Step 8 (untagged)", plain, "old",
			[]string{"--tags", "detection-engine", "--skip-tags", "detection-engine-C1"}, injectedFailure(nil), nil, false, plain, "old", nil},
		{"only C4 selected, failure in C4", plain, "old",
			[]string{"--tags", "detection-engine-C4"}, injectedFailure([]string{"detection-engine-C4"}), nil, false, plain, "old", nil},
		{"up-to-date binary, failure in Step 8", plain, "new", nil, injectedFailure(nil), nil, false, plain, "new", nil},
		{"up-to-date binary, run restarted the unit, failure after", plain, "new", nil, injectedFailure(nil), nil, true, plain, "new", nil},
		{"stale binary, full run, failure after Step 6: binary restored and service back up", plain, "old", nil, injectedFailure(c1), nil, false, plain, "old", nil},
		{"stale binary, --tags tagged, failure after Step 6", plain, "old", []string{"--tags", "tagged"}, injectedFailure(c1), nil, false, plain, "old", nil},
		{"stale binary, --tags detection-engine-C1, failure after Step 6", plain, "old", []string{"--tags", "detection-engine-C1"}, injectedFailure(c1), nil, false, plain, "old", nil},
		{"was stopped (enabled): the rescue does not start it", fakeUnit{loaded: true, enabled: true}, "old", nil, injectedFailure(c1), nil, false, fakeUnit{loaded: true, enabled: true}, "old", nil},
		{"was running but disabled: the rescue does not enable it", fakeUnit{loaded: true, active: true}, "old", nil, injectedFailure(c1), nil, false, fakeUnit{loaded: true, active: true}, "old", nil},
		{"first install, failure before the unit exists", fakeUnit{}, "", nil, injectedFailure(nil), nil, false, fakeUnit{}, "new", nil},
		{"first install, run created+started the unit: stopped and disabled for inspection", fakeUnit{}, "", nil, injectedFailure(nil), nil, true, fakeUnit{loaded: true}, "new", nil},
		// activating (starting, or waiting out Restart=on-failure) and reloading are a unit
		// that is meant to run: put back running.
		{"was activating (auto-restart): restarted", fakeUnit{loaded: true, active: true, enabled: true, activeKind: "activating"}, "old", nil, injectedFailure(c1), nil, false, plain, "old", nil},
		{"was reloading: restarted", fakeUnit{loaded: true, active: true, enabled: true, activeKind: "reloading"}, "old", nil, injectedFailure(c1), nil, false, plain, "old", nil},
		// enabled-runtime (a /run link): `disable` leaves it alone, so there is nothing to put
		// back and it must NOT be turned into a persistent enable.
		{"was enabled-runtime and active: still enabled-runtime (not made persistent), still active", fakeUnit{loaded: true, active: true, enabled: true, enabledKind: "enabled-runtime"}, "old", nil, injectedFailure(c1), nil, false,
			fakeUnit{loaded: true, active: true, enabled: true, enabledKind: "enabled-runtime"}, "old", nil},
		// a restore that fails must not hide behind failed_when: false: the other restore
		// still runs and the final message says what was left undone.
		{"re-enable fails: restart still runs, failure is reported", plain, "old", nil, injectedFailure(c1), []string{"enable_fail"}, false,
			fakeUnit{loaded: true, active: true}, "old", []string{"re-enabling the service FAILED"}},
		{"restart fails: re-enable still done, failure is reported", plain, "old", nil, injectedFailure(c1), []string{"restart_fail"}, false,
			fakeUnit{loaded: true, enabled: true}, "old", []string{"restarting the service FAILED"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := harness{probes: probes, steps: steps, inject: tt.inject, rescue: rescue, args: tt.args, unit: tt.before,
				flags: tt.flags, binary: tt.binary, started: tt.started}.run(t)
			if res.err == nil {
				t.Fatalf("the run must still fail (the rescue's last task re-raises the failure)\n%s", res.log)
			}
			if res.unit != tt.want {
				t.Errorf("service after the failed run = %v, want %v\n%s", res.unit, tt.want, res.log)
			}
			if want := map[string]string{"old": deOldBin, "new": deNewBin}[tt.wantBin]; res.bin != want {
				t.Errorf("binary = %q, want %q", res.bin, want)
			}
			for _, w := range tt.wantWarn {
				if !strings.Contains(res.log, w) {
					t.Errorf("failure message lacks %q\n%s", w, res.log)
				}
			}
		})
	}
}

// Step 0 must give the rescue a VALID snapshot or stop the play before anything is changed:
// the rescue's first task stops AND disables the unit, so a query failure that was swallowed
// (the old failed_when: false) left a healthy service inactive/disabled whenever a later task
// failed (reviewer repro: one-shot `systemctl show` failure, upgrade, failure in Step 8).
// Whatever goes wrong with the query, the unit must end exactly as it was, nothing may have
// been mutated (no stop/disable/start/enable call, no backup, no binary replaced), and the
// run must fail with the Step 0 message.
func TestDetectionEngineServiceStateQueryFailsClosed(t *testing.T) {
	probes, steps, rescue := detectionEngineRescueSteps(t)
	plain := fakeUnit{loaded: true, active: true, enabled: true}
	for _, tt := range []struct {
		name      string
		flags     []string
		noSystemd bool
		args      []string
		inject    []any
	}{
		{"one-shot show failure, upgrade, later task fails (reviewer repro)", []string{"show_fail_once"}, false, nil, injectedFailure(nil)},
		{"one-shot show failure, nothing else fails", []string{"show_fail_once"}, false, nil, nil},
		{"one-shot show failure under --skip-tags C1", []string{"show_fail_once"}, false,
			[]string{"--tags", "detection-engine", "--skip-tags", "detection-engine-C1"}, injectedFailure(nil)},
		{"one-shot show failure, only another component's tag", []string{"show_fail_once"}, false,
			[]string{"--tags", "detection-engine-C4"}, injectedFailure([]string{"detection-engine-C4"})},
		{"show keeps failing", []string{"show_fail_always"}, false, nil, injectedFailure(nil)},
		{"show exits 0 with empty output", []string{"show_raw="}, false, nil, injectedFailure(nil)},
		// valid-looking output must not be believed when the command itself failed
		{"show exits 1 but printed valid-looking properties", []string{"show_raw=ActiveState=active\nUnitFileState=enabled\n", "show_raw_rc=1"}, false, nil, injectedFailure(nil)},
		{"show exits 0 with garbage", []string{"show_raw=Failed to get properties: Access denied\n"}, false, nil, injectedFailure(nil)},
		{"show exits 0 without UnitFileState", []string{"show_raw=ActiveState=active\n"}, false, nil, injectedFailure(nil)},
		{"show exits 0 with an empty ActiveState", []string{"show_raw=ActiveState=\nUnitFileState=enabled\n"}, false, nil, injectedFailure(nil)},
		{"systemctl is not installed", nil, true, nil, injectedFailure(nil)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := harness{probes: probes, steps: steps, inject: tt.inject, rescue: rescue, args: tt.args, unit: plain,
				flags: tt.flags, binary: "old", noSystemd: tt.noSystemd}.run(t)
			if res.err == nil {
				t.Fatalf("the run must fail closed when the original state cannot be read\n%s", res.log)
			}
			if !strings.Contains(res.log, "cannot read the original state of pilot-detection-engine.service") {
				t.Errorf("the failure is not the Step 0 refusal\n%s", res.log)
			}
			if res.unit != plain {
				t.Errorf("service = %v, want it left as it was (%v)\n%s", res.unit, plain, res.log)
			}
			for _, mutating := range []string{"stop", "disable", "enable", "start", "restart"} {
				if regexp.MustCompile(`(?m)^(--\S+ )*` + mutating + ` `).MatchString(res.calls) {
					t.Errorf("systemctl %s was called although nothing was known about the original state:\n%s", mutating, res.calls)
				}
			}
			if res.bin != deOldBin || res.db != "state" || len(res.backupFiles) != 0 {
				t.Errorf("something was changed before the refusal: binary=%q db=%q backups=%v", res.bin, res.db, res.backupFiles)
			}
			if strings.Contains(res.log, "TASK [Step 3") || strings.Contains(res.log, "ROLLBACK") {
				t.Errorf("a block task or the rescue ran although the play had to stop at Step 0\n%s", res.log)
			}
		})
	}
}

// Even with no snapshot at all (here: the probe tasks are left out of the play, as with a
// selection that skips them or a future refactor that moves them into the block) the rescue
// must not stop+disable a unit it cannot put back.
func TestDetectionEngineRescueDoesNotStopWithoutSnapshot(t *testing.T) {
	_, steps, rescue := detectionEngineRescueSteps(t)
	plain := fakeUnit{loaded: true, active: true, enabled: true}
	res := harness{steps: steps, inject: injectedFailure(nil), rescue: rescue, unit: plain, binary: "old"}.run(t)
	if res.err == nil {
		t.Fatalf("the run must fail\n%s", res.log)
	}
	if res.unit != plain {
		t.Errorf("service = %v, want it left as it was (%v)\n%s", res.unit, plain, res.log)
	}
	for _, mutating := range []string{"stop", "disable"} {
		if regexp.MustCompile(`(?m)^` + mutating + ` `).MatchString(res.calls) {
			t.Errorf("systemctl %s was called without a snapshot:\n%s", mutating, res.calls)
		}
	}
}

// Steps 8/9/9b/9c/11 rewrite what the unit runs from before Step 10's `config validate` and
// the health checks can reject it. The rescue must put those files back BEFORE restarting,
// or it restarts a healthy service into a configuration this run wrote (the reviewer's
// repro: ExecStart needs the old config, Step 10 rejects the new one, the restarted unit
// crash-loops while a state-based check says active). The fake unit crash-loops
// ("activating") unless config.yaml still has the old content, so "ends active" below means
// healthy on the old config, not just a state name.
func TestDetectionEngineRescueDoesNotRestartIntoNewConfig(t *testing.T) {
	_, steps, rescue := detectionEngineRescueSteps(t)
	probes, block, _ := loadDetectionEnginePlay(t)
	rejectBin := "#!/bin/sh\n# new build whose validator rejects the new config\n[ \"$1 $2\" = \"config validate\" ] && { echo 'invalid config' >&2; exit 1; }\nexit 0\n"
	steps = append(append([]any{}, steps...), detectionEnginePick(t, block, "Step 8:", "Step 9:", "Step 9b:", "Step 9c:", "Step 10:")...)
	withUnit := append(append([]any{}, steps...), detectionEnginePick(t, block, "Step 11:", "Step 12:")...)
	const oldCfg, oldProfile, oldProvider, oldUnit = "OLD-GOOD-CONFIG\n", "OLD-PROFILE\n", "OLD=1\n", "OLD-UNIT\n"
	all := map[string]string{"config": oldCfg, "profile": oldProfile, "provider": oldProvider, "unit": oldUnit}
	plain := fakeUnit{loaded: true, active: true, enabled: true}
	bearer := map[string]any{"detection_model_provider_enabled": true, "detection_model_provider_base_url": "http://x", "detection_model_provider_model": "m",
		"detection_model_provider_auth": "bearer", "detection_model_provider_api_key": "k"}
	breakConfig := append([]any{map[string]any{"name": "make the config path unwritable", "ansible.builtin.shell": "rm -f {{ detection_engine_config_path }} && mkdir {{ detection_engine_config_path }}"}}, injectedFailure(nil)...)

	for _, tt := range []struct {
		name       string
		before     fakeUnit
		files      map[string]string
		binary     string
		artifact   string
		steps      []any
		inject     []any
		vars       map[string]any
		wantUnit   fakeUnit
		wantFiles  map[string]string // present with this content afterwards
		wantAbsent []string
		wantLog    string
		wantReload int // minimum daemon-reload calls
	}{
		{"Step 10 rejects the new config: old files back, restart is healthy", plain, all, "old", rejectBin, steps, nil, nil, plain, all, nil, "", 0},
		{"failure after Step 11 rewrote the unit: unit back and systemd reloaded", plain, all, "old", "", withUnit, injectedFailure(nil), nil, plain, all, nil, "", 2},
		{"provider.env did not exist and the run created it: removed", plain, map[string]string{"config": oldCfg, "profile": oldProfile, "unit": oldUnit}, "old", rejectBin, steps, nil, bearer, plain,
			map[string]string{"config": oldCfg, "profile": oldProfile, "unit": oldUnit}, []string{"provider"}, "", 0},
		{"first install: nothing to put back, the new files stay for inspection and the service is not touched", fakeUnit{}, nil, "", rejectBin, steps, nil, nil, fakeUnit{}, nil, nil, "", 0},
		{"the old config cannot be put back: not restarted/enabled, said loudly", plain, all, "old", "", steps, breakConfig, nil, fakeUnit{loaded: true}, nil, nil,
			"putting the previous unit/config.yaml/feature profile/provider.env back FAILED", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := harness{probes: probes, steps: tt.steps, inject: tt.inject, rescue: rescue, unit: tt.before, files: tt.files, binary: tt.binary,
				artifact: tt.artifact, healthMark: "OLD-GOOD-CONFIG", vars: tt.vars}.run(t)
			if res.err == nil {
				t.Fatalf("the run must still fail\n%s", res.log)
			}
			if res.unit != tt.wantUnit {
				t.Errorf("service = %v, want %v (an activating unit is a crash loop on a config this run wrote)\n%s", res.unit, tt.wantUnit, res.log)
			}
			for name, want := range tt.wantFiles {
				if got := res.files[name]; got != want {
					t.Errorf("%s = %q after the failed run, want the original %q", name, got, want)
				}
			}
			for _, name := range tt.wantAbsent {
				if res.exists[name] {
					t.Errorf("%s exists after the failed run, want it removed (it did not exist before)", name)
				}
			}
			if _, ok := tt.wantFiles["provider"]; ok && res.providerMod != 0o600 {
				t.Errorf("provider.env mode = %v, want 0600", res.providerMod)
			}
			if tt.name == "first install: nothing to put back, the new files stay for inspection and the service is not touched" && !res.exists["config"] {
				t.Errorf("config.yaml written by the failed first install was removed; it is left for inspection")
			}
			if tt.wantLog != "" {
				if !strings.Contains(res.log, tt.wantLog) {
					t.Errorf("failure message lacks %q\n%s", tt.wantLog, res.log)
				}
				for _, mutating := range []string{"restart", "start", "enable"} {
					if regexp.MustCompile(`(?m)^` + mutating + ` `).MatchString(res.calls) {
						t.Errorf("systemctl %s was called although the old files could not be put back:\n%s", mutating, res.calls)
					}
				}
			}
			if n := strings.Count(res.calls, "daemon-reload"); n < tt.wantReload {
				t.Errorf("daemon-reload called %d times, want >= %d (the rescue must reload after restoring the unit)\n%s", n, tt.wantReload, res.calls)
			}
			if t.Failed() {
				t.Logf("%s", res.log)
			}
		})
	}
}

// Step 0* (the probe, its assert and the file snapshot) run on every apply, so they must
// be read-only: nothing changed (a second apply must report changed=0), nothing skipped or
// failed under --check (the probe is a `command`, which check mode skips unless
// check_mode: false; slurp/stat are read-only), and every task must actually have run.
func TestDetectionEngineStepZeroIsReadOnlyAndCheckModeSafe(t *testing.T) {
	probes := loadDetectionEngineProbes(t)
	recap := regexp.MustCompile(`ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)\s+skipped=(\d+)`)
	all := map[string]string{"config": "C\n", "profile": "P\n", "provider": "E=1\n", "unit": "U\n"}
	for _, tt := range []struct {
		name        string
		args        []string
		files       map[string]string
		ok, skipped string
	}{
		{"apply, all files exist", nil, all, "5", "0"},
		{"--check, all files exist", []string{"--check"}, all, "5", "0"},
		{"apply, first install (no files; slurp has nothing to read)", nil, nil, "4", "1"},
		{"--check, first install", []string{"--check"}, nil, "4", "1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := harness{probes: probes, noBlockOnly: true, args: tt.args, files: tt.files, unit: fakeUnit{loaded: true, active: true, enabled: true}}.run(t)
			if res.err != nil {
				t.Fatalf("Step 0* must not fail%s\n%s", map[bool]string{true: " under --check"}[len(tt.args) > 0], res.log)
			}
			m := recap.FindStringSubmatch(res.log)
			if m == nil {
				t.Fatalf("no recap\n%s", res.log)
			}
			if got := [5]string{m[1], m[2], m[3], m[4], m[5]}; got != [5]string{tt.ok, "0", "0", "0", tt.skipped} {
				t.Errorf("recap ok/changed/unreachable/failed/skipped = %v, want [%s 0 0 0 %s] (a changed probe breaks the second-apply changed=0 check; a skipped one breaks --check)\n%s", got, tt.ok, tt.skipped, res.log)
			}
			for _, mutating := range []string{"stop", "disable", "enable", "start", "restart"} {
				if regexp.MustCompile(`(?m)^` + mutating + ` `).MatchString(res.calls) {
					t.Errorf("Step 0* called systemctl %s", mutating)
				}
			}
		})
	}
}

// The unit-existed guard on the restore matters: with no unit file there is no running
// service to protect, and a failed first install leaves what it wrote for inspection. This
// also holds when config.yaml/provider.env are already there (a unit file removed by hand,
// a half-applied earlier run): they must stay exactly as this run wrote them, not be rolled
// back to the older contents, and the service must not be touched.
func TestDetectionEngineRescueLeavesWhatItWroteWithoutAUnitFile(t *testing.T) {
	_, steps, rescue := detectionEngineRescueSteps(t)
	probes, block, _ := loadDetectionEnginePlay(t)
	steps = append(append([]any{}, steps...), detectionEnginePick(t, block, "Step 8:", "Step 9:", "Step 9b:", "Step 9c:", "Step 10:", "Step 11:", "Step 12:")...)
	const oldCfg, oldProvider = "OLD-GOOD-CONFIG\n", "OLD=1\n"
	res := harness{probes: probes, steps: steps, inject: injectedFailure(nil), rescue: rescue, unit: fakeUnit{}, binary: "old", healthMark: "OLD-GOOD-CONFIG",
		files: map[string]string{"config": oldCfg, "provider": oldProvider},
		vars: map[string]any{"detection_model_provider_enabled": true, "detection_model_provider_base_url": "http://x", "detection_model_provider_model": "m",
			"detection_model_provider_auth": "bearer", "detection_model_provider_api_key": "k"}}.run(t)
	if res.err == nil {
		t.Fatalf("the run must fail\n%s", res.log)
	}
	if res.unit != (fakeUnit{}) {
		t.Errorf("service = %v, want it untouched\n%s", res.unit, res.log)
	}
	if !res.exists["config"] || res.files["config"] == oldCfg || !strings.Contains(res.files["config"], "metricsSourceBaseUrl") {
		t.Errorf("config.yaml = %q: it must stay as the failed run wrote it, not be rolled back to %q", res.files["config"], oldCfg)
	}
	if !strings.Contains(res.files["provider"], "DETECTION_MODEL_API_KEY=k") {
		t.Errorf("provider.env = %q: it must stay as the failed run wrote it, not be rolled back to %q", res.files["provider"], oldProvider)
	}
	if !res.exists["unit"] || !strings.Contains(res.files["unit"], "[Service]") {
		t.Errorf("the unit file Step 11 wrote must stay for inspection, got %q", res.files["unit"])
	}
	for _, mutating := range []string{"restart", "start", "enable"} {
		if regexp.MustCompile(`(?m)^` + mutating + ` `).MatchString(res.calls) {
			t.Errorf("systemctl %s was called on a unit that did not exist before:\n%s", mutating, res.calls)
		}
	}
}

// What the rescue puts back must be the file as it was, not as the playbook would create it:
// an operator's 0640 provider.env owned by another group, a 0600 config.yaml, a symlinked
// config.yaml (the run's copy replaces the link with a regular file; it must come back as
// the same link, with the target's content untouched). The test user need not be root: it
// uses a group it belongs to (or gid 1 as root).
func TestDetectionEngineRescueRestoresModeOwnerAndSymlinks(t *testing.T) {
	_, steps, rescue := detectionEngineRescueSteps(t)
	probes, block, _ := loadDetectionEnginePlay(t)
	steps = append(append([]any{}, steps...), detectionEnginePick(t, block, "Step 8:", "Step 9:", "Step 9b:", "Step 9c:", "Step 10:")...)
	rejectBin := "#!/bin/sh\n[ \"$1 $2\" = \"config validate\" ] && { echo 'invalid config' >&2; exit 1; }\nexit 0\n"
	plain := fakeUnit{loaded: true, active: true, enabled: true}
	gid := -1
	if os.Geteuid() == 0 {
		gid = 1
	} else if groups, err := os.Getgroups(); err == nil {
		for _, g := range groups {
			if g != os.Getgid() {
				gid = g
				break
			}
		}
	}
	if gid < 0 {
		t.Skip("no secondary group to chgrp to")
	}
	files := map[string]string{"config": "OLD-GOOD-CONFIG\n", "profile": "OLD-PROFILE\n", "provider": "OLD=1\n", "unit": "OLD-UNIT\n"}
	t.Run("mode and group are the originals, not the playbook's", func(t *testing.T) {
		res := harness{probes: probes, steps: steps, rescue: rescue, unit: plain, binary: "old", artifact: rejectBin, healthMark: "OLD-GOOD-CONFIG", files: files,
			fileModes: map[string]os.FileMode{"provider": 0o640, "config": 0o600, "profile": 0o664}, fileGIDs: map[string]int{"provider": gid, "profile": gid}}.run(t)
		if res.err == nil {
			t.Fatalf("the run must fail\n%s", res.log)
		}
		for name, want := range map[string]fileStat{"provider": {0o640, os.Getuid(), gid, ""}, "config": {0o600, os.Getuid(), os.Getgid(), ""}, "profile": {0o664, os.Getuid(), gid, ""}} {
			if got := res.stats[name]; got != want {
				t.Errorf("%s after the rescue = %+v, want %+v\n%s", name, got, want, res.log)
			}
			if res.files[name] != files[name] {
				t.Errorf("%s content = %q, want %q", name, res.files[name], files[name])
			}
		}
		if res.unit != plain {
			t.Errorf("service = %v, want %v\n%s", res.unit, plain, res.log)
		}
	})
	t.Run("a symlinked config.yaml comes back as the same symlink", func(t *testing.T) {
		res := harness{probes: probes, steps: steps, rescue: rescue, unit: plain, binary: "old", artifact: rejectBin, healthMark: "OLD-GOOD-CONFIG", files: files,
			symlinks: map[string]bool{"config": true}}.run(t)
		if res.err == nil {
			t.Fatalf("the run must fail\n%s", res.log)
		}
		link := res.stats["config"].link
		if link == "" || !strings.HasSuffix(link, "real-config") {
			t.Fatalf("config.yaml is not a symlink to its original target after the rescue: %+v\n%s", res.stats["config"], res.log)
		}
		if got, _ := os.ReadFile(link); string(got) != files["config"] {
			t.Errorf("the symlink target's content = %q, want it untouched (%q)", got, files["config"])
		}
		if res.files["config"] != files["config"] || res.unit != plain {
			t.Errorf("config via the link = %q, service = %v: want the old config and a healthy active service\n%s", res.files["config"], res.unit, res.log)
		}
	})
}

// Step 0c reads provider.env (a secret) into a fact and the rescue writes it back; neither
// the content, its base64, nor the sha1 that `stat` would add may appear in the output, even
// at -vvv with --diff (the slurp and the restore are no_log; the stat does not checksum).
func TestDetectionEngineSnapshotDoesNotLeakProviderEnv(t *testing.T) {
	_, steps, rescue := detectionEngineRescueSteps(t)
	probes, block, _ := loadDetectionEnginePlay(t)
	steps = append(append([]any{}, steps...), detectionEnginePick(t, block, "Step 8:", "Step 9:", "Step 9b:", "Step 9c:", "Step 10:")...)
	rejectBin := "#!/bin/sh\n[ \"$1 $2\" = \"config validate\" ] && { echo 'invalid config' >&2; exit 1; }\nexit 0\n"
	const secret = "sk-live-7Qp2ZxLeakCanary9d41"
	content := "DETECTION_MODEL_API_KEY=" + secret + "\n"
	sha := sha1.Sum([]byte(content))
	needles := map[string]string{
		"the secret": secret, "the file's base64": base64.StdEncoding.EncodeToString([]byte(content)),
		"the secret's base64": base64.StdEncoding.EncodeToString([]byte(secret)), "the file's sha1": hex.EncodeToString(sha[:]),
	}
	plain := fakeUnit{loaded: true, active: true, enabled: true}
	// Under --check the rejecting validator is a skipped command, so nothing fails and the
	// rescue does not run: that variant covers the snapshot tasks alone.
	for _, tt := range []struct {
		args    []string
		rescued bool
	}{{[]string{"-vvv", "--diff"}, true}, {[]string{"-vvv", "--diff", "--check"}, false}} {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			res := harness{probes: probes, steps: steps, rescue: rescue, unit: plain, binary: "old", artifact: rejectBin, healthMark: "OLD-GOOD-CONFIG", args: tt.args,
				files: map[string]string{"config": "OLD-GOOD-CONFIG\n", "provider": content, "unit": "OLD-UNIT\n"}}.run(t)
			if (res.err != nil) != tt.rescued {
				t.Fatalf("run failed = %v, want %v\n%s", res.err != nil, tt.rescued, res.log)
			}
			// the tasks that handle the secret really ran, or the absence below proves nothing
			tasks := []string{"Step 0b", "Step 0c"}
			if tt.rescued {
				tasks = append(tasks, "ROLLBACK — restore the unit, config")
			}
			for _, task := range tasks {
				if !strings.Contains(res.log, "TASK ["+task) {
					t.Fatalf("task %q did not run\n%s", task, res.log)
				}
			}
			for what, needle := range needles {
				if strings.Contains(res.log, needle) {
					t.Errorf("the output contains %s (%q)", what, needle)
				}
			}
			if tt.rescued && res.files["provider"] != content {
				t.Errorf("provider.env not restored: %q", res.files["provider"])
			}
		})
	}
}

// Step 0c slurps only regular files: `slurp` follows symlinks, so a config.yaml that is a
// dangling link, or a link to a directory, would fail the snapshot (a refusal before any
// change, for a layout the apply handled before) if the `when` did not skip links. With a
// failure injected after Step 11 the rescue must run, recreate the link with the same target
// and leave everything else as it was: the other files restored, the target untouched, the
// service back in its original state.
func TestDetectionEngineSnapshotAndRescueHandleUnreadableSymlinks(t *testing.T) {
	_, steps, rescue := detectionEngineRescueSteps(t)
	probes, block, _ := loadDetectionEnginePlay(t)
	steps = append(append([]any{}, steps...), detectionEnginePick(t, block, "Step 8:", "Step 9:", "Step 9b:", "Step 9c:", "Step 10:", "Step 11:", "Step 12:")...)
	files := map[string]string{"config": "OLD-GOOD-CONFIG\n", "profile": "OLD-PROFILE\n", "provider": "OLD=1\n", "unit": "OLD-UNIT\n"}
	plain := fakeUnit{loaded: true, active: true, enabled: true}
	for _, kind := range []string{"dangling", "dir"} {
		t.Run("config.yaml is a "+kind+" symlink", func(t *testing.T) {
			// no healthMark: the fake unit cannot "read" a config through a link like these
			res := harness{probes: probes, steps: steps, inject: injectedFailure(nil), rescue: rescue, unit: plain, binary: "old", files: files,
				symlinks: map[string]bool{"config": true}, linkKinds: map[string]string{"config": kind}}.run(t)
			if res.err == nil {
				t.Fatalf("the run must fail (the injected failure after Step 11)\n%s", res.log)
			}
			// Step 0c did not fail: nothing fatal happens before the block's first task
			if i := strings.Index(res.log, "TASK [Step 3:"); i < 0 || strings.Contains(res.log[:i], "fatal:") {
				t.Fatalf("the snapshot failed before the block ran (slurp following the link?)\n%s", res.log)
			}
			if !strings.Contains(res.log, `"msg": "boom"`) || !strings.Contains(res.log, "TASK [ROLLBACK — restore the files that were symlinks]") {
				t.Fatalf("the injected failure or the rescue did not run\n%s", res.log)
			}
			link := res.stats["config"].link
			if !strings.HasSuffix(link, "real-config") {
				t.Fatalf("config.yaml = %+v, want the same symlink to its original target\n%s", res.stats["config"], res.log)
			}
			switch kind {
			case "dangling":
				if _, err := os.Lstat(link); err == nil {
					t.Errorf("the target %s exists now: the rescue created what the link pointed at", link)
				}
			case "dir":
				// (Step 9's copy onto a link to a directory drops a temp-named file into it; that
				// is the playbook's own pre-existing behaviour, not the rescue's)
				if got, _ := os.ReadFile(filepath.Join(link, "marker.txt")); string(got) != files["config"] {
					t.Errorf("target directory marker = %q, want it untouched (%q)", got, files["config"])
				}
			}
			for _, name := range []string{"profile", "provider", "unit"} {
				if res.files[name] != files[name] {
					t.Errorf("%s = %q, want it restored to %q", name, res.files[name], files[name])
				}
			}
			if res.unit != plain {
				t.Errorf("service = %v, want its original state %v\n%s", res.unit, plain, res.log)
			}
		})
	}
}
