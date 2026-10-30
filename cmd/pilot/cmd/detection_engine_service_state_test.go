package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// loadDetectionEnginePlay returns the real install block, its real rescue and the real
// Step 0 tasks that precede the block (read-only probe + its fail-closed assert), with the
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
			if name, _ := m["name"].(string); strings.HasPrefix(name, "Step 0:") {
				probes = append(probes, m)
			}
		}
	}
	for _, list := range [][]any{block, rescue} {
		for _, task := range list {
			m, _ := task.(map[string]any)
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
	if len(probes) != 2 {
		t.Fatalf("found %d Step 0 tasks outside the install block, want 2 (the systemctl show probe and its assert): "+
			"the snapshot must be taken and validated before the block, whose rescue stops the service", len(probes))
	}
	return
}

// loadDetectionEngineBlock returns the real install block and its real rescue.
func loadDetectionEngineBlock(t *testing.T) (block, rescue []any) {
	t.Helper()
	_, block, rescue = loadDetectionEnginePlay(t)
	return
}

// loadDetectionEngineProbes returns the real Step 0 tasks (probe, then assert).
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
// enable_fail, restart_fail.
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
       [ -e $sd/show_raw ] && { cat $sd/show_raw; exit 0; }
       if [ -e $sd/loaded ]; then echo LoadState=loaded
         [ -e $sd/active ] && echo ActiveState=$(kind active active) || echo ActiveState=inactive
         [ -e $sd/enabled ] && echo UnitFileState=$(kind enabled enabled) || echo UnitFileState=disabled
       else echo LoadState=not-found; echo ActiveState=inactive; echo UnitFileState=; fi ;;
 is-enabled) [ -e $sd/enabled ] && { kind enabled enabled; exit 0; }; echo disabled; exit 1 ;;
 start|restart) [ -e $sd/loaded ] || exit 5; [ -e $sd/restart_fail ] && exit 1; echo active > $sd/active ;;
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
}

type harnessResult struct {
	log, calls  string
	err         error
	unit        fakeUnit
	bin, db     string
	backupFiles []string
}

const (
	deOldBin = "#!/bin/sh\n# old build\n[ \"$1 $2\" = \"db backup\" ] && cp \"$4\" \"$6\"\n"
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
	bin, artifact, db := filepath.Join(dir, "bin"), filepath.Join(dir, "artifact"), filepath.Join(dir, "state.db")
	if h.binary != "" {
		write(bin, map[string]string{"old": deOldBin, "new": deNewBin}[h.binary], 0o755)
		write(db, "state", 0o600)
	}
	write(artifact, deNewBin, 0o755)
	inject := h.inject
	if h.started { // what Steps 11-14 do to the service before a later step fails
		inject = append([]any{map[string]any{"name": "emulate Steps 11-14", "ansible.builtin.shell": "touch " + sd + "/loaded " + sd + "/enabled " + sd + "/active"}}, inject...)
	}
	sum := sha256.Sum256([]byte(deNewBin))
	tasks := append([]any{}, h.probes...)
	tasks = append(tasks, map[string]any{"block": append(append([]any{}, h.steps...), inject...), "rescue": h.rescue,
		"tags": []string{"observability", "detection-engine"}})
	play := []any{map[string]any{"hosts": "localhost", "connection": "local", "gather_facts": false,
		"vars": map[string]any{"detection_engine_db_path": db, "detection_engine_bin_dest": bin,
			"detection_engine_backup_dir": backups, "detection_engine_artifact_abs_path": artifact,
			"detection_engine_artifact_sha256": hex.EncodeToString(sum[:])},
		"tasks": tasks}}
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
	log, runErr := cmd.CombinedOutput()
	read := func(path string) string { b, _ := os.ReadFile(path); return string(b) }
	exists := func(n string) bool { _, e := os.Stat(filepath.Join(sd, n)); return e == nil }
	res := harnessResult{log: string(log), calls: read(filepath.Join(sd, "calls.log")), err: runErr, bin: read(bin), db: read(db)}
	res.unit = fakeUnit{loaded: exists("loaded"), active: exists("active"), enabled: exists("enabled"),
		activeKind: strings.TrimSpace(read(filepath.Join(sd, "active"))), enabledKind: strings.TrimSpace(read(filepath.Join(sd, "enabled")))}
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

func detectionEngineRescueSteps(t *testing.T) (probes, steps, rescue []any) {
	t.Helper()
	probes, block, rescue := loadDetectionEnginePlay(t)
	for _, task := range block {
		name, _ := task.(map[string]any)["name"].(string)
		for _, p := range []string{"Step 3:", "Step 3b:", "Step 3c:", "Step 3d:", "Step 4:", "Step 5:", "Step 6:"} {
			if strings.HasPrefix(name, p) {
				steps = append(steps, task)
			}
		}
	}
	if len(steps) != 7 {
		t.Fatalf("picked %d steps, want 7 (Steps 3-6)", len(steps))
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
