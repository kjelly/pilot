package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// loadDetectionEngineBlock returns the real install block and its real rescue, with the
// unprivileged owner/group dropped from copy/file tasks.
func loadDetectionEngineBlock(t *testing.T) (block, rescue []any) {
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
			if m, ok := task.(map[string]any); ok && m["name"] == "Detection Engine install + systemd service" {
				block, _ = m["block"].([]any)
				rescue, _ = m["rescue"].([]any)
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
	return
}

func loadDetectionEngineProbe(t *testing.T) any {
	t.Helper()
	block, _ := loadDetectionEngineBlock(t)
	for _, task := range block {
		if m, ok := task.(map[string]any); ok && strings.HasPrefix(m["name"].(string), "Step 0:") {
			return m
		}
	}
	t.Fatal("Step 0 (the original service state probe) is gone from the install block")
	return nil
}

// A stand-in for systemctl with the bits of real semantics that matter here: state lives
// in $FAKE_SD/{loaded,active,enabled}; start/stop/enable/disable of an unknown unit fail;
// `show` reports a unit that does not exist as inactive with an empty UnitFileState and
// exit 0 (as the real one does; checked against systemd on Ubuntu 24.04/26.04).
const fakeSystemctl = `#!/bin/bash
sd=$FAKE_SD; cmd=; skip=0
for a in "$@"; do
  if [ $skip = 1 ]; then skip=0; continue; fi
  case "$a" in -p|--property) skip=1;; -*) ;; *) [ -z "$cmd" ] && cmd=$a;; esac
done
echo "$*" >> $sd/calls.log
case "$cmd" in
 show) if [ -e $sd/loaded ]; then echo LoadState=loaded
         [ -e $sd/active ] && echo ActiveState=active || echo ActiveState=inactive
         [ -e $sd/enabled ] && echo UnitFileState=enabled || echo UnitFileState=disabled
       else echo LoadState=not-found; echo ActiveState=inactive; echo UnitFileState=; fi ;;
 is-enabled) [ -e $sd/enabled ] && { echo enabled; exit 0; }; echo disabled; exit 1 ;;
 start|restart) [ -e $sd/loaded ] || exit 5; touch $sd/active ;;
 stop) [ -e $sd/loaded ] || exit 5; rm -f $sd/active ;;
 enable) [ -e $sd/loaded ] || exit 1; touch $sd/enabled ;;
 disable) [ -e $sd/loaded ] || exit 1; rm -f $sd/enabled ;;
 daemon-reload) ;;
 *) exit 1 ;;
esac
`

// The rescue stops and disables the unit so it can restore the binary/state.db safely; it
// must then put the service back exactly as it was before the run, whatever tags selected
// the failing step. Run with the real Step 0 probe, real Steps 3-6 and the real rescue.
func TestDetectionEngineRescuePutsServiceBack(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not installed")
	}
	block, rescue := loadDetectionEngineBlock(t)
	var steps []any
	for _, task := range block {
		name, _ := task.(map[string]any)["name"].(string)
		for _, p := range []string{"Step 0:", "Step 3:", "Step 3b:", "Step 3c:", "Step 3d:", "Step 4:", "Step 5:", "Step 6:"} {
			if strings.HasPrefix(name, p) {
				steps = append(steps, task)
			}
		}
	}
	if len(steps) != 8 {
		t.Fatalf("picked %d steps, want 8 (Step 0 and Steps 3-6)", len(steps))
	}
	const oldBin = "#!/bin/sh\n# old build\n[ \"$1 $2\" = \"db backup\" ] && cp \"$4\" \"$6\"\n"
	const newBin = "#!/bin/sh\n# new build\n"
	c1 := []string{"detection-engine-C1"}
	fail := func(tags []string) []any {
		task := map[string]any{"name": "inject failure", "ansible.builtin.fail": map[string]any{"msg": "boom"}}
		if tags != nil {
			task["tags"] = tags
		}
		return []any{task}
	}

	type unit struct{ loaded, active, enabled bool }
	for _, tt := range []struct {
		name    string
		before  unit
		binary  string // "old" (stale), "new" (up to date), "" (first install)
		args    []string
		inject  []any
		started bool // the run itself created/started the unit before failing (Steps 11-14)
		want    unit
		wantBin string
	}{
		{"reviewer: skip C1, failure in Step 8 (untagged)", unit{true, true, true}, "old",
			[]string{"--tags", "detection-engine", "--skip-tags", "detection-engine-C1"}, fail(nil), false, unit{true, true, true}, "old"},
		{"only C4 selected, failure in C4", unit{true, true, true}, "old",
			[]string{"--tags", "detection-engine-C4"}, fail([]string{"detection-engine-C4"}), false, unit{true, true, true}, "old"},
		{"up-to-date binary, failure in Step 8", unit{true, true, true}, "new", nil, fail(nil), false, unit{true, true, true}, "new"},
		{"up-to-date binary, run restarted the unit, failure after", unit{true, true, true}, "new", nil, fail(nil), true, unit{true, true, true}, "new"},
		{"stale binary, full run, failure after Step 6: binary restored and service back up", unit{true, true, true}, "old", nil, fail(c1), false, unit{true, true, true}, "old"},
		{"stale binary, --tags tagged, failure after Step 6", unit{true, true, true}, "old", []string{"--tags", "tagged"}, fail(c1), false, unit{true, true, true}, "old"},
		{"stale binary, --tags detection-engine-C1, failure after Step 6", unit{true, true, true}, "old", []string{"--tags", "detection-engine-C1"}, fail(c1), false, unit{true, true, true}, "old"},
		{"was stopped (enabled): the rescue does not start it", unit{true, false, true}, "old", nil, fail(c1), false, unit{true, false, true}, "old"},
		{"was running but disabled: the rescue does not enable it", unit{true, true, false}, "old", nil, fail(c1), false, unit{true, true, false}, "old"},
		{"first install, failure before the unit exists", unit{}, "", nil, fail(nil), false, unit{}, "new"},
		{"first install, run created+started the unit: stopped and disabled for inspection", unit{}, "", nil, fail(nil), true, unit{true, false, false}, "new"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			sd := filepath.Join(dir, "sd")
			fakebin := filepath.Join(dir, "fakebin")
			for _, d := range []string{sd, fakebin, filepath.Join(dir, "backups")} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(fakebin, "systemctl"), []byte(fakeSystemctl), 0o755); err != nil {
				t.Fatal(err)
			}
			setUnit := func(u unit) {
				for name, on := range map[string]bool{"loaded": u.loaded, "active": u.active, "enabled": u.enabled} {
					p := filepath.Join(sd, name)
					if on {
						if err := os.WriteFile(p, nil, 0o600); err != nil {
							t.Fatal(err)
						}
					} else {
						os.Remove(p)
					}
				}
			}
			setUnit(tt.before)
			bin, artifact, db := filepath.Join(dir, "bin"), filepath.Join(dir, "artifact"), filepath.Join(dir, "state.db")
			if tt.binary != "" {
				if err := os.WriteFile(bin, []byte(map[string]string{"old": oldBin, "new": newBin}[tt.binary]), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(db, []byte("state"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(artifact, []byte(newBin), 0o755); err != nil {
				t.Fatal(err)
			}
			inject := tt.inject
			if tt.started { // what Steps 11-14 do to the service before a later step fails
				inject = append([]any{map[string]any{"name": "emulate Steps 11-14", "ansible.builtin.shell": "touch " + sd + "/loaded " + sd + "/enabled " + sd + "/active"}}, inject...)
			}
			sum := sha256.Sum256([]byte(newBin))
			play := []any{map[string]any{"hosts": "localhost", "connection": "local", "gather_facts": false,
				"vars": map[string]any{"detection_engine_db_path": db, "detection_engine_bin_dest": bin,
					"detection_engine_backup_dir": filepath.Join(dir, "backups"), "detection_engine_artifact_abs_path": artifact,
					"detection_engine_artifact_sha256": hex.EncodeToString(sum[:])},
				"tasks": []any{map[string]any{"block": append(append([]any{}, steps...), inject...), "rescue": rescue,
					"tags": []string{"observability", "detection-engine"}}}}}
			out, err := yaml.Marshal(play)
			if err != nil {
				t.Fatal(err)
			}
			pb := filepath.Join(dir, "p.yml")
			if err := os.WriteFile(pb, out, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(ansible, append([]string{"-i", "localhost,", pb}, tt.args...)...)
			cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "FAKE_SD="+sd, "PATH="+fakebin+":"+os.Getenv("PATH"))
			log, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("the run must still fail (the rescue's last task re-raises the failure)\n%s", log)
			}
			exists := func(n string) bool { _, e := os.Stat(filepath.Join(sd, n)); return e == nil }
			if got := (unit{exists("loaded"), exists("active"), exists("enabled")}); got != tt.want {
				t.Errorf("service after the failed run = %+v, want %+v\n%s", got, tt.want, log)
			}
			got, _ := os.ReadFile(bin)
			if want := map[string]string{"old": oldBin, "new": newBin}[tt.wantBin]; string(got) != want {
				t.Errorf("binary = %q, want %q", got, want)
			}
		})
	}
}
