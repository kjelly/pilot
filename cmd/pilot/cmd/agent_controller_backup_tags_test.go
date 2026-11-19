package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #195: agent-controller's Steps 3-5 (upgrade detection, state.db
// backup, previous-binary snapshot) were `always`-tagged while Step 6, the
// binary replacement, is agent-controller-C4. A run that did not select
// Step 6 still "backed up" an upgrade that never happened, and Step 4's
// changed_when: true failed the second-apply idempotency check. The rescue
// restored from fixed names in the backup directory whenever
// agent_controller_is_upgrade was true, so it could restore an older
// snapshot when this run's own backup had failed (Step 5 had
// failed_when: false). Same defects detection-engine had before #190/#203.
//
// These tests run the real tasks with a real ansible-playbook against a
// fake binary on localhost.

// agentControllerTasks returns the real Step 0e reset, the Steps 3-6 of the
// install block and the rescue without its final fail, unprivileged.
func agentControllerTasks(t *testing.T) (reset, steps, restore []any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRootForTest(t), "playbooks", "apply", "agent-controller-apply.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	var block, rescue []any
	for _, play := range plays {
		tasks, _ := play["tasks"].([]any)
		for _, task := range tasks {
			m, ok := task.(map[string]any)
			if !ok {
				continue
			}
			switch name, _ := m["name"].(string); {
			case strings.HasPrefix(name, "Step 0e:"):
				reset = append(reset, acUnprivileged(m))
			case name == "Agent Controller install + systemd service":
				block, _ = m["block"].([]any)
				rescue, _ = m["rescue"].([]any)
			}
		}
	}
	if len(reset) != 1 || block == nil || rescue == nil {
		t.Fatalf("agent-controller-apply.yml lost its Step 0e reset or install block/rescue (reset=%d)", len(reset))
	}
	seen := map[string]bool{}
	for _, task := range block {
		m, ok := task.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		for _, prefix := range []string{"Step 3", "Step 4", "Step 5", "Step 6:"} {
			if strings.HasPrefix(name, prefix) {
				seen[prefix] = true
				steps = append(steps, acUnprivileged(m))
				break
			}
		}
	}
	for _, prefix := range []string{"Step 3", "Step 4", "Step 5", "Step 6:"} {
		if !seen[prefix] {
			t.Fatalf("no task named %q* in the install block", prefix)
		}
	}
	// The whole real rescue except its final `fail`, so the play goes on to
	// record what the rescue did.
	sawRestore := false
	for _, task := range rescue {
		m, ok := task.(map[string]any)
		if !ok {
			continue
		}
		if _, isFail := m["ansible.builtin.fail"]; isFail {
			continue
		}
		if m["name"] == "ROLLBACK — restore only this invocation's validated material" {
			sawRestore = true
		}
		restore = append(restore, acUnprivileged(m))
	}
	if !sawRestore {
		t.Fatal("the rescue lost its \"restore only this invocation's validated material\" block")
	}
	return reset, steps, restore
}

// acUnprivileged drops what a non-root test cannot do (ownership, become),
// recursively through blocks.
func acUnprivileged(task map[string]any) map[string]any {
	delete(task, "become")
	delete(task, "become_user")
	for _, module := range []string{"ansible.builtin.copy", "ansible.builtin.file"} {
		if args, ok := task[module].(map[string]any); ok {
			delete(args, "owner")
			delete(args, "group")
		}
	}
	for _, key := range []string{"block", "rescue", "always"} {
		if list, ok := task[key].([]any); ok {
			for _, sub := range list {
				if m, ok := sub.(map[string]any); ok {
					acUnprivileged(m)
				}
			}
		}
	}
	return task
}

const (
	acOldBin = "#!/bin/sh\n# old build\nif [ \"$1 $2\" = \"db check\" ]; then echo ok; exit 0; fi\n[ \"$1 $2\" = \"db backup\" ] && cp \"$4\" \"$6\"\nexit 0\n"
	acNewBin = "#!/bin/sh\n# new build\nif [ \"$1 $2\" = \"db check\" ]; then echo ok; exit 0; fi\nexit 0\n"
	// An installed binary whose `db backup` fails (disk full, locked db, ...).
	acOldBinBackupFails = "#!/bin/sh\n# old build, backup fails\nif [ \"$1 $2\" = \"db check\" ]; then echo ok; exit 0; fi\n[ \"$1 $2\" = \"db backup\" ] && exit 1\nexit 0\n"
	// An installed binary whose snapshot fails the integrity check.
	acOldBinCheckBad = "#!/bin/sh\n# old build, snapshot corrupt\nif [ \"$1 $2\" = \"db check\" ]; then echo '*** in database main ***'; exit 1; fi\n[ \"$1 $2\" = \"db backup\" ] && cp \"$4\" \"$6\"\nexit 0\n"
)

// acFakeSystemctl stands in for systemctl under ansible.builtin.systemd: the
// unit's state is files in $FAKE_SD (loaded, active, enabled) and every call
// is appended to $FAKE_SD/calls.log. Taken from the #195 review's harness.
const acFakeSystemctl = `#!/bin/bash
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
 is-active) [ -e $sd/active ] && { echo active; exit 0; }; echo inactive; exit 3 ;;
 is-enabled) [ -e $sd/enabled ] && { echo enabled; exit 0; }; echo disabled; exit 1 ;;
 start|restart) [ -e $sd/loaded ] || exit 5; touch $sd/active ;;
 stop) [ -e $sd/loaded ] || exit 5; rm -f $sd/active ;;
 enable) [ -e $sd/loaded ] || exit 1; touch $sd/enabled ;;
 disable) [ -e $sd/loaded ] || exit 1; rm -f $sd/enabled ;;
 daemon-reload) true ;;
 *) exit 1 ;;
esac
`

type acFixture struct {
	dir, bin, artifact, db, backups, sd string
	vars                                map[string]any
	env                                 map[string]any
}

func newACFixture(t *testing.T, installed, artifact string) acFixture {
	t.Helper()
	dir := t.TempDir()
	f := acFixture{
		dir:      dir,
		bin:      filepath.Join(dir, "pilot-agent-controller"),
		artifact: filepath.Join(dir, "artifact"),
		db:       filepath.Join(dir, "state.db"),
		backups:  filepath.Join(dir, "backups"),
	}
	acWrite(t, f.bin, installed, 0o755)
	acWrite(t, f.artifact, artifact, 0o755)
	acWrite(t, f.db, "state-before", 0o600)
	if err := os.Mkdir(f.backups, 0o700); err != nil {
		t.Fatal(err)
	}
	// A loaded, active, enabled unit: the healthy service an upgrade starts from.
	f.sd = filepath.Join(dir, "sd")
	fakebin := filepath.Join(dir, "fakebin")
	for _, d := range []string{f.sd, fakebin} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, flag := range []string{"loaded", "active", "enabled"} {
		acWrite(t, filepath.Join(f.sd, flag), "", 0o644)
	}
	acWrite(t, filepath.Join(fakebin, "systemctl"), acFakeSystemctl, 0o755)
	f.env = map[string]any{"PATH": fakebin + ":" + os.Getenv("PATH"), "FAKE_SD": f.sd}
	sum := sha256.Sum256([]byte(artifact))
	f.vars = map[string]any{
		"agent_controller_db_path":           f.db,
		"agent_controller_bin_dest":          f.bin,
		"agent_controller_backup_dir":        f.backups,
		"agent_controller_artifact_abs_path": f.artifact,
		"agent_controller_artifact_sha256":   hex.EncodeToString(sum[:]),
		"agent_controller_user":              "unused-in-tests",
	}
	return f
}

// serviceState is the fake unit's state after a run.
func (f acFixture) serviceState(t *testing.T) (active, enabled, stopped bool) {
	t.Helper()
	_, errA := os.Stat(filepath.Join(f.sd, "active"))
	_, errE := os.Stat(filepath.Join(f.sd, "enabled"))
	calls, _ := os.ReadFile(filepath.Join(f.sd, "calls.log"))
	return errA == nil, errE == nil, strings.Contains(string(calls), "stop")
}

func acWrite(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func acRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// runACPlay writes tasks into a localhost play and runs it; it returns the
// output, failing the test if ansible-playbook fails.
func runACPlay(t *testing.T, ansible string, f acFixture, tasks []any, args ...string) string {
	t.Helper()
	play := []any{map[string]any{
		"hosts": "localhost", "connection": "local", "gather_facts": false,
		"vars":        f.vars,
		"environment": f.env,
		"tasks":       tasks,
	}}
	out, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	playbook := filepath.Join(f.dir, "play.yml")
	acWrite(t, playbook, string(out), 0o600)
	cmd := exec.Command(ansible, append([]string{"-i", "localhost,", playbook}, args...)...)
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_RETRY_FILES_ENABLED=False")
	log, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ansible-playbook %v: %v\n%s", args, err, log)
	}
	return string(log)
}

var acRecapChanged = regexp.MustCompile(`localhost\s+:\s+ok=\d+\s+changed=(\d+)`)

func acChanged(t *testing.T, log string) string {
	t.Helper()
	m := acRecapChanged.FindStringSubmatch(log)
	if m == nil {
		// A selection that skips every task leaves the recap without a host
		// line: nothing ran, so nothing changed.
		if strings.Contains(log, "PLAY RECAP") && !strings.Contains(log, "TASK [") {
			return "0"
		}
		t.Fatalf("no PLAY RECAP for localhost:\n%s", log)
	}
	return m[1]
}

func TestAgentControllerBackupFollowsStep6TagSelection(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not installed")
	}
	reset, steps, _ := agentControllerTasks(t)
	for _, tt := range []struct {
		name string
		// wrap gives the tasks the tags an importing play would add (site.yml
		// imports components with their component tag).
		wrap  []string
		args  []string
		step6 bool
	}{
		{"no tags", nil, nil, true},
		{"--tags tagged", nil, []string{"--tags", "tagged"}, true},
		{"--tags agent-controller-C4", nil, []string{"--tags", "agent-controller-C4"}, true},
		{"--tags agent-controller (imported with the component tag)", []string{"agent-controller"}, []string{"--tags", "agent-controller"}, true},
		{"--skip-tags tagged", nil, []string{"--skip-tags", "tagged"}, false},
		{"--skip-tags agent-controller-C4", nil, []string{"--skip-tags", "agent-controller-C4"}, false},
		{"--tags agent-controller --skip-tags agent-controller-C4", []string{"agent-controller"}, []string{"--tags", "agent-controller", "--skip-tags", "agent-controller-C4"}, false},
		{"another row of this component", nil, []string{"--tags", "agent-controller-C2"}, false},
		{"other components only", nil, []string{"--tags", "docker,host-monitoring,detection-engine"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newACFixture(t, acOldBin, acNewBin)
			body := append(append([]any{}, reset...), steps...)
			tasks := body
			if tt.wrap != nil {
				tasks = []any{map[string]any{"block": body, "tags": tt.wrap}}
			}
			log := runACPlay(t, ansible, f, tasks, tt.args...)

			upgraded := acRead(t, f.bin) == acNewBin
			dbSnaps, _ := filepath.Glob(filepath.Join(f.backups, "apply-*", "pre-upgrade.db"))
			binSnaps, _ := filepath.Glob(filepath.Join(f.backups, "apply-*", "pilot-agent-controller.prev"))
			if upgraded != tt.step6 {
				t.Fatalf("Step 6 ran = %v, want %v (the selection itself changed; update the table)", upgraded, tt.step6)
			}
			if upgraded && (len(dbSnaps) != 1 || len(binSnaps) != 1) {
				t.Errorf("Step 6 replaced the binary but this run's snapshots are missing (pre-upgrade.db: %d, previous binary: %d)", len(dbSnaps), len(binSnaps))
			}
			if !upgraded {
				if len(dbSnaps)+len(binSnaps) != 0 {
					t.Errorf("a run that does not replace the binary still took a backup (pre-upgrade.db: %d, previous binary: %d)", len(dbSnaps), len(binSnaps))
				}
				if got := acChanged(t, log); got != "0" {
					t.Errorf("a run that does not replace the binary reported changed=%s; it must converge", got)
				}
			}
			if upgraded {
				for _, snap := range binSnaps {
					if acRead(t, snap) != acOldBin {
						t.Errorf("%s is not the previously installed binary", snap)
					}
				}
				// The second apply has nothing to upgrade.
				if got := acChanged(t, runACPlay(t, ansible, f, tasks, tt.args...)); got != "0" {
					t.Errorf("second apply reported changed=%s, want 0", got)
				}
			}
		})
	}
}

// acFailingPlay runs the real reset and Steps 3-6, then beforeFail and an
// injected failure, in one block whose rescue is the real rescue (without its
// final fail) followed by a task that records the outcome. preReset runs
// before the reset, as an earlier play's leftovers would.
func acFailingPlay(reset, steps, rescue []any, factsPath string, preReset, beforeFail []any, failTags []string) []any {
	fail := map[string]any{"name": "injected failure after Step 6", "ansible.builtin.fail": map[string]any{"msg": "injected"}}
	if failTags != nil {
		fail["tags"] = failTags
	}
	body := append(append(append([]any{}, steps...), beforeFail...), fail)
	record := map[string]any{
		"name": "record the rescue's outcome",
		"tags": []string{"always"},
		"ansible.builtin.copy": map[string]any{
			"dest":    factsPath,
			"content": "{{ {'restored': agent_controller_rollback_restored, 'failed': agent_controller_rollback_failed, 'rollback': agent_controller_rollback} | to_json }}",
		},
	}
	out := append(append([]any{}, preReset...), reset...)
	return append(out, map[string]any{
		"name":   "install block under test",
		"block":  body,
		"rescue": append(append([]any{}, rescue...), record),
	})
}

type acOutcome struct {
	Restored bool           `json:"restored"`
	Failed   bool           `json:"failed"`
	Rollback map[string]any `json:"rollback"`
}

func readACOutcome(t *testing.T, path string) acOutcome {
	t.Helper()
	var o acOutcome
	if err := json.Unmarshal([]byte(acRead(t, path)), &o); err != nil {
		t.Fatalf("rescue outcome: %v", err)
	}
	return o
}

func acTask(name, module string, args map[string]any) map[string]any {
	return map[string]any{"name": name, module: args}
}

func TestAgentControllerRescueRestoresOnlyThisRunsSnapshots(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not installed")
	}
	reset, steps, rescue := agentControllerTasks(t)
	run := func(t *testing.T, f acFixture, preReset, beforeFail []any, failTags []string, args ...string) acOutcome {
		t.Helper()
		facts := filepath.Join(f.dir, "outcome.json")
		runACPlay(t, ansible, f, acFailingPlay(reset, steps, rescue, facts, preReset, beforeFail, failTags), args...)
		return readACOutcome(t, facts)
	}
	staleSnapshots := func(t *testing.T, f acFixture) {
		acWrite(t, filepath.Join(f.backups, "pilot-agent-controller.prev"), "#!/bin/sh\n# stale\n", 0o755)
		acWrite(t, filepath.Join(f.backups, "pre-upgrade.db"), "state-stale", 0o600)
	}

	t.Run("upgrade fails after Step 6: binary and state.db come back, service restarted", func(t *testing.T) {
		f := newACFixture(t, acOldBin, acNewBin)
		staleSnapshots(t, f)
		migrate := acTask("the new binary migrates state.db and leaves WAL/SHM", "ansible.builtin.shell", map[string]any{
			"cmd": "printf state-migrated > " + f.db + " && touch " + f.db + "-wal " + f.db + "-shm",
		})
		o := run(t, f, nil, []any{migrate}, nil)
		if !o.Restored || o.Failed {
			t.Fatalf("restored=%v failed=%v, want a restore", o.Restored, o.Failed)
		}
		if got := acRead(t, f.bin); got != acOldBin {
			t.Errorf("binary not restored: %q", got)
		}
		if got := acRead(t, f.db); got != "state-before" {
			t.Errorf("state.db not restored from this run's snapshot: %q", got)
		}
		for _, side := range []string{"-wal", "-shm"} {
			if _, err := os.Stat(f.db + side); err == nil {
				t.Errorf("the new database's %s file was left next to the restored snapshot", side)
			}
		}
		if active, enabled, stopped := f.serviceState(t); !active || !enabled || !stopped {
			t.Errorf("service active=%v enabled=%v stopped-first=%v, want stopped for the restore and then active+enabled", active, enabled, stopped)
		}
	})

	t.Run("upgrade without a state.db keeps the database the new binary created", func(t *testing.T) {
		f := newACFixture(t, acOldBin, acNewBin)
		if err := os.Remove(f.db); err != nil {
			t.Fatal(err)
		}
		staleSnapshots(t, f)
		create := acTask("the new binary creates state.db", "ansible.builtin.copy", map[string]any{"dest": f.db, "content": "SERVICE-CREATED"})
		o := run(t, f, nil, []any{create}, nil)
		if !o.Restored || o.Rollback["db_ready"] == true {
			t.Fatalf("restored=%v rollback=%v, want the binary restored with no database authority", o.Restored, o.Rollback)
		}
		if got := acRead(t, f.bin); got != acOldBin {
			t.Errorf("binary not restored: %q", got)
		}
		if got := acRead(t, f.db); got != "SERVICE-CREATED" {
			t.Errorf("state.db = %q; a stale snapshot replaced the database this run created", got)
		}
	})

	for _, tc := range []struct {
		name, installed string
	}{
		{"`db backup` fails before Step 6: healthy service left running", acOldBinBackupFails},
		{"the database snapshot fails `db check` before Step 6: healthy service left running", acOldBinCheckBad},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newACFixture(t, tc.installed, acNewBin)
			staleSnapshots(t, f)
			o := run(t, f, nil, nil, nil)
			if o.Restored || o.Failed || o.Rollback["install_started"] == true {
				t.Fatalf("restored=%v failed=%v rollback=%v, want the run to stop before Step 6", o.Restored, o.Failed, o.Rollback)
			}
			if got := acRead(t, f.bin); got != tc.installed {
				t.Errorf("binary changed: %q", got)
			}
			if got := acRead(t, f.db); got != "state-before" {
				t.Errorf("state.db changed: %q", got)
			}
			if active, enabled, stopped := f.serviceState(t); !active || !enabled || stopped {
				t.Errorf("service active=%v enabled=%v stopped=%v, want it untouched (nothing was replaced)", active, enabled, stopped)
			}
		})
	}

	t.Run("a run that never selected Step 6 leaves binary and service alone", func(t *testing.T) {
		f := newACFixture(t, acOldBin, acNewBin)
		staleSnapshots(t, f)
		o := run(t, f, nil, nil, []string{"agent-controller-C2"}, "--tags", "agent-controller-C2")
		if o.Restored || o.Failed || o.Rollback["install_started"] == true {
			t.Fatalf("restored=%v failed=%v rollback=%v, want no restore authority", o.Restored, o.Failed, o.Rollback)
		}
		if acRead(t, f.bin) != acOldBin {
			t.Errorf("binary changed by a run that did not select Step 6")
		}
		if active, enabled, stopped := f.serviceState(t); !active || !enabled || stopped {
			t.Errorf("service active=%v enabled=%v stopped=%v, want it untouched", active, enabled, stopped)
		}
	})

	t.Run("no upgrade: stale fixed-name snapshots are never restored", func(t *testing.T) {
		f := newACFixture(t, acNewBin, acNewBin)
		staleSnapshots(t, f)
		acWrite(t, f.db, "state-current", 0o600)
		o := run(t, f, nil, nil, nil)
		if o.Restored || o.Failed {
			t.Fatalf("restored=%v failed=%v, want nothing restored", o.Restored, o.Failed)
		}
		if acRead(t, f.bin) != acNewBin || acRead(t, f.db) != "state-current" {
			t.Errorf("a stale backup was restored: bin=%q db=%q", acRead(t, f.bin), acRead(t, f.db))
		}
	})

	t.Run("restore authority left by an earlier play is reset", func(t *testing.T) {
		f := newACFixture(t, acNewBin, acNewBin)
		stale := filepath.Join(f.backups, "apply-earlier")
		if err := os.Mkdir(stale, 0o700); err != nil {
			t.Fatal(err)
		}
		acWrite(t, filepath.Join(stale, "pilot-agent-controller.prev"), acOldBin, 0o755)
		sum := sha256.Sum256([]byte(acOldBin))
		leftover := acTask("an earlier play granted restore authority", "ansible.builtin.set_fact", map[string]any{
			"agent_controller_rollback": map[string]any{"binary_ready": true, "db_ready": false, "install_started": true, "path": stale, "binary_sha256": hex.EncodeToString(sum[:])},
		})
		o := run(t, f, []any{leftover}, nil, nil)
		if o.Restored || o.Rollback["binary_ready"] == true {
			t.Fatalf("restored=%v rollback=%v, want the earlier play's authority reset by Step 0e", o.Restored, o.Rollback)
		}
		if acRead(t, f.bin) != acNewBin {
			t.Errorf("binary restored from an earlier play's snapshot")
		}
	})

	for _, tc := range []struct{ name, file string }{
		{"a binary snapshot changed after validation is refused", "pilot-agent-controller.prev"},
		{"a database snapshot changed after validation is refused", "pre-upgrade.db"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newACFixture(t, acOldBin, acNewBin)
			tamper := acTask("something rewrites this run's snapshot", "ansible.builtin.shell", map[string]any{
				"cmd": "for d in " + f.backups + "/apply-*; do printf tampered > \"$d/" + tc.file + "\"; done",
			})
			o := run(t, f, nil, []any{tamper}, nil)
			if o.Restored || !o.Failed {
				t.Fatalf("restored=%v failed=%v, want the restore refused", o.Restored, o.Failed)
			}
			if got := acRead(t, f.bin); got != acNewBin {
				t.Errorf("binary was overwritten from a tampered snapshot set: %q", got)
			}
			if active, _, _ := f.serviceState(t); active {
				t.Errorf("service restarted after a refused restore")
			}
		})
	}
}

// TestAgentControllerBackupInCheckMode: --check on an upgrade host takes no
// snapshot, replaces nothing and does not fail.
func TestAgentControllerBackupInCheckMode(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not installed")
	}
	reset, steps, _ := agentControllerTasks(t)
	f := newACFixture(t, acOldBin, acNewBin)
	runACPlay(t, ansible, f, append(append([]any{}, reset...), steps...), "--check")
	if got := acRead(t, f.bin); got != acOldBin {
		t.Errorf("--check replaced the binary")
	}
	if snaps, _ := filepath.Glob(filepath.Join(f.backups, "apply-*")); len(snaps) != 0 {
		t.Errorf("--check created snapshot directories: %v", snaps)
	}
}

// TestAgentControllerBackupStepsAreNotAlways locks the tag shape statically, so
// it also runs where ansible-playbook is missing.
func TestAgentControllerBackupStepsAreNotAlways(t *testing.T) {
	_, steps, _ := agentControllerTasks(t)
	for _, task := range steps {
		m := task.(map[string]any)
		tags, _ := m["tags"].([]any)
		if len(tags) != 1 || tags[0] != "agent-controller-C4" {
			t.Errorf("%v: tags %v, want exactly Step 6's [agent-controller-C4]", m["name"], tags)
		}
	}
}
