package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// loadDetectionEngineSteps returns the real Steps 3-6 (block) and the two real restore
// rescue tasks, unprivileged (owner/group dropped). restart is the rescue's service
// restart task: it is only for static checks, never to be run (it would restart a real
// systemd unit).
func loadDetectionEngineSteps(t *testing.T) (steps, rescue, restart []any) {
	raw, err := os.ReadFile(filepath.Join(repoRootForTest(t), "playbooks", "apply", "detection-engine-apply.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	var block, resc []any
	for _, play := range plays {
		tasks, _ := play["tasks"].([]any)
		for _, task := range tasks {
			if m, ok := task.(map[string]any); ok && m["name"] == "Detection Engine install + systemd service" {
				block, _ = m["block"].([]any)
				resc, _ = m["rescue"].([]any)
			}
		}
	}
	pick := func(list []any, prefixes []string) []any {
		var out []any
		for _, task := range list {
			m, ok := task.(map[string]any)
			if !ok {
				continue
			}
			name, _ := m["name"].(string)
			for _, p := range prefixes {
				if strings.HasPrefix(name, p) {
					for _, module := range []string{"ansible.builtin.copy", "ansible.builtin.file"} {
						if args, ok := m[module].(map[string]any); ok {
							delete(args, "owner")
							delete(args, "group")
						}
					}
					out = append(out, m)
					break
				}
			}
		}
		return out
	}
	steps = pick(block, []string{"Step 3:", "Step 3b:", "Step 3c:", "Step 3d:", "Step 4:", "Step 5:", "Step 6:"})
	rescue = pick(resc, []string{"ROLLBACK — restore the previous binary", "ROLLBACK — restore the pre-upgrade database"})
	restart = pick(resc, []string{"ROLLBACK — re-enable the service", "ROLLBACK — restart the service"})
	if len(steps) != 7 || len(rescue) != 2 || len(restart) != 2 {
		t.Fatalf("steps=%d rescue=%d restart=%d: the install block or its rescue was renamed/restructured", len(steps), len(rescue), len(restart))
	}
	return
}

func taskTags(t *testing.T, task any) []string {
	t.Helper()
	m, _ := task.(map[string]any)
	raw, _ := m["tags"].([]any)
	var tags []string
	for _, tag := range raw {
		tags = append(tags, tag.(string))
	}
	sort.Strings(tags)
	return tags
}

// The backup (Steps 3-5) must be selected by exactly the tags that select Step 6, which
// replaces the binary; see the comment above Step 3 in detection-engine-apply.yml. This is
// the cheap YAML-only guard of that invariant (no ansible needed); the tests below prove
// the behaviour with real ansible-playbook.
func TestDetectionEngineBackupTagsEqualStep6Tags(t *testing.T) {
	steps, rescue, restart := loadDetectionEngineSteps(t)
	step6 := taskTags(t, steps[len(steps)-1])
	if len(step6) == 0 {
		t.Fatal("Step 6 has no tags")
	}
	for _, tag := range step6 {
		if tag == "always" {
			t.Fatal("Step 6 is always-tagged: it would replace the binary under --skip-tags and every selection; the backup invariant below would be meaningless")
		}
	}
	for _, step := range steps[:len(steps)-1] {
		name := step.(map[string]any)["name"]
		if got := taskTags(t, step); !reflect.DeepEqual(got, step6) {
			t.Errorf("%v has tags %v, want Step 6's %v (backup/upgrade detection must follow the binary replacement)", name, got, step6)
		}
	}
	// The restore tasks are always-tagged (the rescue must run whenever its block does) and
	// so must carry the guards in their own bodies instead of relying on the setters' tags.
	for _, task := range rescue {
		m := task.(map[string]any)
		if got := taskTags(t, task); !reflect.DeepEqual(got, []string{"always"}) {
			t.Errorf("%v has tags %v, want [always]: the rescue must run whenever its block does", m["name"], got)
		}
		when := strings.Join(whenStrings(m["when"]), " && ")
		if !strings.Contains(when, "detection_engine_is_upgrade is defined") {
			t.Errorf("%v: when %q must guard detection_engine_is_upgrade with `is defined`", m["name"], when)
		}
		if !strings.Contains(when, "detection_engine_binary_result is defined") {
			t.Errorf("%v: when %q must require `detection_engine_binary_result is defined` (this run reached Step 6), or a stale backup of an earlier upgrade can be restored", m["name"], when)
		}
	}
	// The service's original state is restored from Step 0's read-only probe, never from
	// facts Step 6's tag sets: those are undefined when the selection skips Step 6 and the
	// rescue still stops+disables the unit (reviewer repro: --tags detection-engine
	// --skip-tags detection-engine-C1 with a failure in Step 8).
	for _, task := range restart {
		m := task.(map[string]any)
		if got := taskTags(t, task); !reflect.DeepEqual(got, []string{"always"}) {
			t.Errorf("%v has tags %v, want [always]", m["name"], got)
		}
		when := strings.Join(whenStrings(m["when"]), " && ")
		if !strings.Contains(when, "detection_engine_service_before") {
			t.Errorf("%v: when %q must read Step 0's detection_engine_service_before", m["name"], when)
		}
		if strings.Contains(when, "detection_engine_is_upgrade") || strings.Contains(when, "detection_engine_binary_result") {
			t.Errorf("%v: when %q must not depend on facts only Step 6's tag sets", m["name"], when)
		}
	}
	// Step 0 (probe + assert) is always-tagged and sits BEFORE the block: a refusal there
	// must not run the rescue, whose first task stops and disables the unit.
	for _, probe := range loadDetectionEngineProbes(t) {
		if got := taskTags(t, probe); !reflect.DeepEqual(got, []string{"always"}) {
			t.Errorf("%v has tags %v, want [always]: it must run under every selection, before anything changes", probe.(map[string]any)["name"], got)
		}
	}
	block, resc := loadDetectionEngineBlock(t)
	for _, task := range block {
		if name, _ := task.(map[string]any)["name"].(string); strings.HasPrefix(name, "Step 0") {
			t.Errorf("%q is inside the install block: a failing probe would run the rescue, which stops and disables the service", name)
		}
	}
	// The re-enable and the restart must not run when the old unit/config files could not be
	// put back: restarting then runs a configuration this run wrote (crash loop that a state
	// check calls active). The restore tasks exist, are always-tagged, and sit between the
	// stop and the restart.
	names := map[string]int{}
	for i, task := range resc {
		m := task.(map[string]any)
		name, _ := m["name"].(string)
		names[name] = i
		if got := taskTags(t, task); !reflect.DeepEqual(got, []string{"always"}) {
			t.Errorf("rescue task %q has tags %v, want [always]", name, got)
		}
	}
	idx := func(prefix string) int {
		for name, i := range names {
			if strings.HasPrefix(name, prefix) {
				return i
			}
		}
		t.Fatalf("no rescue task %q", prefix)
		return -1
	}
	stopIdx, restoreIdx, reloadIdx, enableIdx, restartIdx := idx("ROLLBACK — stop"), idx("ROLLBACK — restore the unit, config"), idx("ROLLBACK — reload systemd"), idx("ROLLBACK — re-enable"), idx("ROLLBACK — restart")
	linksIdx := idx("ROLLBACK — restore the files that were symlinks")
	if !(stopIdx < restoreIdx && restoreIdx < linksIdx && linksIdx < reloadIdx && reloadIdx < enableIdx && enableIdx < restartIdx) {
		t.Errorf("rescue order must be stop < restore files < restore links < daemon-reload < re-enable < restart, got %d %d %d %d %d %d", stopIdx, restoreIdx, linksIdx, reloadIdx, enableIdx, restartIdx)
	}
	for _, i := range []int{enableIdx, restartIdx} {
		m := resc[i].(map[string]any)
		when := strings.Join(whenStrings(m["when"]), " && ")
		for _, reg := range []string{"detection_engine_rescue_restore_files is not failed", "detection_engine_rescue_restore_links is not failed", "detection_engine_rescue_remove_files is not failed", "detection_engine_rescue_reload is not failed"} {
			if !strings.Contains(when, reg) {
				t.Errorf("%v: when %q must require %q (never restart into a config this run wrote)", m["name"], when, reg)
			}
		}
	}
	for _, i := range []int{restoreIdx, linksIdx, reloadIdx, idx("ROLLBACK — remove the files")} {
		m := resc[i].(map[string]any)
		if m["ignore_errors"] != true {
			t.Errorf("%v must use ignore_errors with register (a failed restore has to reach the final message and stop the restart), not failed_when: false", m["name"])
		}
	}
	if resc[restoreIdx].(map[string]any)["no_log"] != true {
		t.Errorf("the restore task carries provider.env: it must be no_log")
	}
	// The snapshot reads provider.env (a secret): the slurp that holds it is no_log, and the
	// stat must not add a checksum of it (-vvv would print the sha1).
	for _, probe := range loadDetectionEngineProbes(t) {
		m := probe.(map[string]any)
		name, _ := m["name"].(string)
		switch {
		case strings.HasPrefix(name, "Step 0c:"):
			if m["no_log"] != true {
				t.Errorf("%s: the slurp holds provider.env, it must be no_log", name)
			}
		case strings.HasPrefix(name, "Step 0b:"):
			args, _ := m["ansible.builtin.stat"].(map[string]any)
			if args["get_checksum"] != false {
				t.Errorf("%s: stat must set get_checksum: false (nothing consumes it and -vvv prints the sha1 of provider.env)", name)
			}
			// the restore consumes exactly these
			for _, key := range []string{"mode", "uid", "gid", "lnk_target", "islnk"} {
				found := false
				for _, task := range resc {
					rm := task.(map[string]any)
					if n, _ := rm["name"].(string); strings.HasPrefix(n, "ROLLBACK — restore the") {
						if b, _ := yaml.Marshal(rm); strings.Contains(string(b), "stat."+key) {
							found = true
						}
					}
				}
				if !found {
					t.Errorf("no restore task uses the original's stat.%s: the rescue must put back the file as it was", key)
				}
			}
		}
	}
	// The rescue's mutating stop+disable must itself require the valid snapshot.
	stop, _ := resc[0].(map[string]any)
	if name, _ := stop["name"].(string); !strings.HasPrefix(name, "ROLLBACK — stop") {
		t.Fatalf("the rescue's first task is %q, want the stop task", name)
	}
	if when := strings.Join(whenStrings(stop["when"]), " && "); !strings.Contains(when, "detection_engine_service_before.rc == 0") {
		t.Errorf("the rescue's stop+disable has when %q: it must require Step 0's snapshot (detection_engine_service_before.rc == 0), or a failed query leaves a healthy service stopped and disabled with nothing to put it back", when)
	}
}

func whenStrings(v any) []string {
	switch w := v.(type) {
	case string:
		return []string{w}
	case []any:
		var out []string
		for _, e := range w {
			out = append(out, e.(string))
		}
		return out
	}
	return nil
}

func TestDetectionEngineRollbackFollowsStep6(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not installed")
	}
	steps, rescue, _ := loadDetectionEngineSteps(t)
	const oldBin = "#!/bin/sh\n# old build\n[ \"$1 $2\" = \"db backup\" ] && cp \"$4\" \"$6\"\n"
	const newBin = "#!/bin/sh\n# new build\n"

	for _, tt := range []struct {
		name string
		args []string
		// failTag: the tag of the injected failing task (post Step 6 when C1)
		failTag     string
		stale       bool // pre-seed stale backups from an "earlier upgrade"
		step6       bool
		backupFails bool // the old binary's `db backup` exits 1 (Step 4 fails before Step 6)
	}{
		{"no tags", nil, "detection-engine-C1", false, true, false},
		{"tagged", []string{"--tags", "tagged"}, "detection-engine-C1", false, true, false},
		{"C1", []string{"--tags", "detection-engine-C1"}, "detection-engine-C1", false, true, false},
		{"detection-engine", []string{"--tags", "detection-engine"}, "detection-engine-C1", false, true, false},
		{"observability", []string{"--tags", "observability"}, "detection-engine-C1", false, true, false},
		{"skip C1 but fail in C4 + stale backups", []string{"--tags", "detection-engine", "--skip-tags", "detection-engine-C1"}, "detection-engine-C4", true, false, false},
		{"other components only + failure in C4 + stale backups", []string{"--tags", "detection-engine-C4"}, "detection-engine-C4", true, false, false},
		{"stale backups, Step 6 selected, failure after", nil, "detection-engine-C1", true, true, false},
		{"Step 4 fails (upgrade, Step 6 never reached) with stale backups", nil, "detection-engine-C1", true, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			oldBin := oldBin
			if tt.backupFails {
				oldBin = "#!/bin/sh\n# old build, backup broken\n[ \"$1 $2\" = \"db backup\" ] && exit 1\n"
			}
			dir := t.TempDir()
			bin := filepath.Join(dir, "pilot-detection-engine")
			artifact := filepath.Join(dir, "artifact")
			db := filepath.Join(dir, "state.db")
			backups := filepath.Join(dir, "backups")
			write := func(path, content string, mode os.FileMode) {
				if err := os.WriteFile(path, []byte(content), mode); err != nil {
					t.Fatal(err)
				}
			}
			write(bin, oldBin, 0o755)
			write(artifact, newBin, 0o755)
			write(db, "state", 0o600)
			if err := os.Mkdir(backups, 0o700); err != nil {
				t.Fatal(err)
			}
			if tt.stale {
				write(filepath.Join(backups, "pre-upgrade.db"), "STALE-DB", 0o600)
				write(filepath.Join(backups, "pilot-detection-engine.prev"), "STALE-BIN", 0o755)
			}
			sum := sha256.Sum256([]byte(newBin))
			inject := []any{
				map[string]any{"name": "mutate db like a migration", "tags": []string{tt.failTag}, "ansible.builtin.copy": map[string]any{"dest": db, "content": "MIGRATED"}},
				map[string]any{"name": "inject failure", "tags": []string{tt.failTag}, "ansible.builtin.fail": map[string]any{"msg": "boom"}},
			}
			// rescue tasks are always-tagged in the real playbook; the play's own tags come from site.yml
			rescueTasks := rescue
			play := []any{map[string]any{
				"hosts": "localhost", "connection": "local", "gather_facts": false,
				"vars": map[string]any{
					"detection_engine_db_path":           db,
					"detection_engine_bin_dest":          bin,
					"detection_engine_backup_dir":        backups,
					"detection_engine_artifact_abs_path": artifact,
					"detection_engine_artifact_sha256":   hex.EncodeToString(sum[:]),
				},
				"tasks": []any{map[string]any{
					"block":  append(append([]any{}, steps...), inject...),
					"rescue": rescueTasks,
					"tags":   []string{"observability", "detection-engine"},
				}},
			}}
			out, err := yaml.Marshal(play)
			if err != nil {
				t.Fatal(err)
			}
			playbook := filepath.Join(dir, "play.yml")
			write(playbook, string(out), 0o600)
			cmd := exec.Command(ansible, append([]string{"-i", "localhost,", playbook}, tt.args...)...)
			cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
			log, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("ansible-playbook failed (the rescue should have swallowed boom; no final fail task in this harness): %v\n%s", err, log)
			}
			gotBin, _ := os.ReadFile(bin)
			gotDB, _ := os.ReadFile(db)
			if tt.step6 {
				if string(gotBin) != oldBin {
					t.Errorf("binary after rollback = %q, want the pre-upgrade binary", gotBin)
				}
				if string(gotDB) != "state" {
					t.Errorf("db after rollback = %q, want the pre-upgrade db (state)", gotDB)
				}
			} else {
				if string(gotBin) != oldBin {
					t.Errorf("binary = %q, want it untouched", gotBin)
				}
				wantDB := "MIGRATED"
				if tt.backupFails {
					wantDB = "state" // the migration task is after Step 6, never reached
				}
				if string(gotDB) != wantDB {
					t.Errorf("db = %q: rescue must not restore a STALE backup over current state (want %s left as is)", gotDB, wantDB)
				}
			}
			if t.Failed() {
				t.Logf("%s", log)
			}
		})
	}
}

// A stale binary upgraded by the first apply must leave nothing to change on the second
// one (pilot's second-apply idempotency check): Step 4's changed_when: true used to fail it
// whenever the backup ran without Step 6 replacing the binary.
func TestDetectionEngineSecondApplyChangedZero(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not installed")
	}
	steps, _, _ := loadDetectionEngineSteps(t)
	const oldBin = "#!/bin/sh\n# old build\n[ \"$1 $2\" = \"db backup\" ] && cp \"$4\" \"$6\"\n"
	const newBin = "#!/bin/sh\n# new build\n"
	changed := regexp.MustCompile(`changed=(\d+)\b`)
	backupStep := regexp.MustCompile(`TASK \[Step [3-6][:b-d]`) // Step 0* run on every apply
	for _, tt := range []struct {
		name        string
		args        []string
		step6       bool // the selection reaches Step 6
		wantChanged int  // changed tasks of the first apply: Steps 4, 5 and 6
	}{
		{"no tags", nil, true, 3},
		{"tagged", []string{"--tags", "tagged"}, true, 3},
		{"other component only (pilot deploy --limit), stale binary", []string{"--tags", "docker"}, false, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			bin, artifact, db, backups := filepath.Join(dir, "bin"), filepath.Join(dir, "artifact"), filepath.Join(dir, "state.db"), filepath.Join(dir, "backups")
			for p, c := range map[string]string{bin: oldBin, artifact: newBin, db: "state"} {
				if err := os.WriteFile(p, []byte(c), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(backups, 0o700); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(newBin))
			vars := map[string]any{"detection_engine_db_path": db, "detection_engine_bin_dest": bin, "detection_engine_backup_dir": backups,
				"detection_engine_artifact_abs_path": artifact, "detection_engine_artifact_sha256": hex.EncodeToString(sum[:])}
			for k, v := range detectionEngineSnapshotVars(t, dir) {
				vars[k] = v
			}
			// the real Step 0* (service probe, assert, file snapshot) run on every apply too, so
			// the second apply's changed=0 covers them; they need a systemctl to ask.
			fakebin, sd := filepath.Join(dir, "fakebin"), filepath.Join(dir, "sd")
			for _, d := range []string{fakebin, sd} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for p, c := range map[string]string{filepath.Join(fakebin, "systemctl"): fakeSystemctl, filepath.Join(sd, "loaded"): "", filepath.Join(sd, "active"): "", filepath.Join(sd, "enabled"): ""} {
				if err := os.WriteFile(p, []byte(c), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			play := []any{map[string]any{"hosts": "localhost", "connection": "local", "gather_facts": false, "vars": vars,
				"tasks": append(append([]any{}, loadDetectionEngineProbes(t)...), map[string]any{"block": steps, "tags": []string{"observability", "detection-engine"}})}}
			out, err := yaml.Marshal(play)
			if err != nil {
				t.Fatal(err)
			}
			pb := filepath.Join(dir, "p.yml")
			if err := os.WriteFile(pb, out, 0o600); err != nil {
				t.Fatal(err)
			}
			run := func() string {
				cmd := exec.Command(ansible, append([]string{"-i", "localhost,", pb}, tt.args...)...)
				cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "FAKE_SD="+sd, "PATH="+fakebin+":"+os.Getenv("PATH"))
				log, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%v\n%s", err, log)
				}
				return string(log)
			}
			first, second := run(), run()
			got, _ := os.ReadFile(bin)
			if !tt.step6 {
				if backupStep.MatchString(first) || backupStep.MatchString(second) {
					t.Errorf("a detection-engine task ran although the selection excludes it\n%s", first)
				}
				if string(got) != oldBin {
					t.Errorf("binary changed although Step 6 was not selected")
				}
				if _, err := os.Stat(filepath.Join(backups, "pre-upgrade.db")); err == nil {
					t.Errorf("a pre-upgrade backup was taken although Step 6 was not selected")
				}
				return
			}
			if string(got) != newBin {
				t.Errorf("first apply did not install the new binary")
			}
			if m := changed.FindStringSubmatch(first); m == nil || m[1] != fmt.Sprint(tt.wantChanged) {
				t.Errorf("first apply: want changed=%d\n%s", tt.wantChanged, first)
			}
			if m := changed.FindStringSubmatch(second); m == nil || m[1] != "0" {
				t.Errorf("second apply not changed=0\n%s", second)
			}
		})
	}
}
