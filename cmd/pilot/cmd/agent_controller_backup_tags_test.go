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

// loadAgentControllerPlay returns the real Step 0e reset, the install block's
// tasks and its rescue's tasks, freshly parsed (callers modify them).
func loadAgentControllerPlay(t *testing.T) (reset, block, rescue []any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRootForTest(t), "playbooks", "apply", "agent-controller-apply.yml"))
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
	return reset, block, rescue
}

// agentControllerTasks returns the real Step 0e reset, the Steps 3-6 of the
// install block and the rescue, unprivileged. The rescue's final `fail` is
// kept as the real task with its real message template, but it records the
// rendered message in agent_controller_rescue_message instead of failing, so
// the play goes on to write down what the rescue did.
func agentControllerTasks(t *testing.T) (reset, steps, restore []any) {
	t.Helper()
	reset, block, rescue := loadAgentControllerPlay(t)
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
	sawRestore, sawMessage := false, false
	for _, task := range rescue {
		m, ok := task.(map[string]any)
		if !ok {
			continue
		}
		if fail, isFail := m["ansible.builtin.fail"].(map[string]any); isFail {
			delete(m, "ansible.builtin.fail")
			m["ansible.builtin.set_fact"] = map[string]any{"agent_controller_rescue_message": fail["msg"]}
			sawMessage = true
		}
		if m["name"] == "ROLLBACK — restore only this invocation's validated material" {
			sawRestore = true
		}
		restore = append(restore, acUnprivileged(m))
	}
	if !sawRestore {
		t.Fatal("the rescue lost its \"restore only this invocation's validated material\" block")
	}
	if !sawMessage {
		t.Fatal("the rescue lost its final `fail` task")
	}
	return reset, steps, restore
}

// agentControllerSteps returns the real install-block tasks whose names start
// with one of prefixes, in file order, unprivileged, with the systemd unit
// path moved into the fixture (the real path needs root). Nothing else of the
// tasks is changed.
func agentControllerSteps(t *testing.T, f acFixture, prefixes ...string) []any {
	t.Helper()
	_, block, _ := loadAgentControllerPlay(t)
	var steps []any
	for _, task := range block {
		m, ok := task.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		for _, prefix := range prefixes {
			if strings.HasPrefix(name, prefix) {
				if args, ok := m["ansible.builtin.copy"].(map[string]any); ok && args["dest"] == acUnitDest {
					args["dest"] = f.unit
				}
				steps = append(steps, acUnprivileged(m))
				break
			}
		}
	}
	if len(steps) < len(prefixes) {
		t.Fatalf("found %d install-block tasks for the prefixes %q, want at least %d", len(steps), prefixes, len(prefixes))
	}
	return steps
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

// acUnitDest is where Step 11 writes the unit; it needs root, so the tests that
// run Step 11 redirect it into the fixture (acFixture.unit).
const acUnitDest = "/etc/systemd/system/pilot-agent-controller.service"

// acFakeSystemctl stands in for systemctl under ansible.builtin.systemd: the
// unit's state is files in $FAKE_SD (loaded, active, enabled) and every call
// is appended to $FAKE_SD/calls.log. Taken from the #195 review's harness.
// FAKE_STOP_FAILS makes `stop` fail on a loaded unit (a service that cannot be
// stopped); FAKE_SHOW_FAILS makes `show` fail (a status query that fails, which
// is not the same as a unit that does not exist).
const acFakeSystemctl = `#!/bin/bash
sd=$FAKE_SD; cmd=; skip=0
for a in "$@"; do
  if [ $skip = 1 ]; then skip=0; continue; fi
  case "$a" in -p|--property) skip=1;; -*) ;; *) [ -z "$cmd" ] && cmd=$a;; esac
done
echo "$*" >> $sd/calls.log
case "$cmd" in
 show) [ -n "$FAKE_SHOW_FAILS" ] && { echo "Failed to connect to bus" >&2; exit 1; }
       if [ -e $sd/loaded ]; then echo LoadState=loaded
         [ -e $sd/active ] && echo ActiveState=active || echo ActiveState=inactive
         [ -e $sd/enabled ] && echo UnitFileState=enabled || echo UnitFileState=disabled
       else echo LoadState=not-found; echo ActiveState=inactive; echo UnitFileState=; fi ;;
 is-active) [ -e $sd/active ] && { echo active; exit 0; }; echo inactive; exit 3 ;;
 is-enabled) [ -e $sd/enabled ] && { echo enabled; exit 0; }; echo disabled; exit 1 ;;
 start|restart) [ -e $sd/loaded ] || exit 5; touch $sd/active ;;
 stop) [ -e $sd/loaded ] || exit 5; [ -n "$FAKE_STOP_FAILS" ] && exit 1; rm -f $sd/active ;;
 enable) [ -e $sd/loaded ] || exit 1; touch $sd/enabled ;;
 disable) [ -e $sd/loaded ] || exit 1; rm -f $sd/enabled ;;
 daemon-reload) true ;;
 *) exit 1 ;;
esac
`

type acFixture struct {
	dir, bin, artifact, db, backups, sd string
	// unit is where Step 11 writes the systemd unit, conf the directory of
	// config.yaml and webhook-secret.env.
	unit, conf string
	vars       map[string]any
	env        map[string]any
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
		unit:     filepath.Join(dir, "pilot-agent-controller.service"),
		conf:     filepath.Join(dir, "conf"),
	}
	if err := os.Mkdir(f.conf, 0o755); err != nil {
		t.Fatal(err)
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
		// What Steps 8, 9 and 11 render (the values are synthetic).
		"agent_controller_config_dir":                 f.conf,
		"agent_controller_config_path":                filepath.Join(f.conf, "config.yaml"),
		"agent_controller_data_dir":                   filepath.Join(dir, "data"),
		"agent_controller_status_path":                filepath.Join(dir, "status.json"),
		"agent_controller_textfile_path":              filepath.Join(dir, "pilot_agent_controller.prom"),
		"agent_controller_listen_addr":                "127.0.0.1",
		"agent_controller_listen_port":                8090,
		"agent_controller_max_body_bytes":             1048576,
		"agent_controller_max_concurrent_runs":        4,
		"agent_controller_max_runs_per_host":          1,
		"agent_controller_dispatcher_kind":            "fake",
		"agent_controller_dispatcher_endpoint":        "",
		"agent_controller_dispatcher_timeout_seconds": 30,
		"agent_controller_webhook_secret":             "synthetic-webhook-secret-for-tests",
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

// calls counts the logged systemctl calls whose verb (first word) is verb.
func (f acFixture) calls(t *testing.T, verb string) int {
	t.Helper()
	log, _ := os.ReadFile(filepath.Join(f.sd, "calls.log"))
	n := 0
	for _, line := range strings.Split(string(log), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == verb {
			n++
		}
	}
	return n
}

// resetCalls forgets the systemctl calls so far, so the next run is counted alone.
func (f acFixture) resetCalls(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.sd, "calls.log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
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
		// Under --check the outcome file is written anyway.
		"check_mode": false,
		"ansible.builtin.copy": map[string]any{
			"dest":    factsPath,
			"content": "{{ {'restored': agent_controller_rollback_restored, 'failed': agent_controller_rollback_failed, 'rollback': agent_controller_rollback, 'message': (agent_controller_rescue_message | default(''))} | to_json }}",
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
	// Message is what the rescue's final `fail` would have told the operator,
	// whitespace-normalized.
	Message string `json:"message"`
}

func readACOutcome(t *testing.T, path string) acOutcome {
	t.Helper()
	var o acOutcome
	if err := json.Unmarshal([]byte(acRead(t, path)), &o); err != nil {
		t.Fatalf("rescue outcome: %v", err)
	}
	o.Message = strings.Join(strings.Fields(o.Message), " ")
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

// acFailAfterSteps runs the real Step 0e reset, the given real steps, an
// injected failure after the last of them and the real rescue, and returns what
// the rescue recorded. failTags tags the injected failure (nil: untagged).
func acFailAfterSteps(t *testing.T, ansible string, f acFixture, steps []any, failTags []string, args ...string) acOutcome {
	t.Helper()
	reset, _, rescue := agentControllerTasks(t)
	facts := filepath.Join(f.dir, "outcome.json")
	runACPlay(t, ansible, f, acFailingPlay(reset, steps, rescue, facts, nil, nil, failTags), args...)
	o := readACOutcome(t, facts)
	t.Logf("rescue message: %s", o.Message)
	return o
}

// acInstallSteps are the install-block steps a run that renders the service's
// files and restarts it goes through, in file order.
var acInstallSteps = []string{"Step 3", "Step 4", "Step 5", "Step 6:", "Step 8:", "Step 9:", "Step 11:", "Step 12:", "Step 13:", "Step 14:"}

// TestAgentControllerRescueMessageSaysWhatHappened runs the real rescue,
// including the real final message, after failures whose effect on the host
// differs, and holds the message to what the host and the fake systemd show:
//
//   - A run that does not select Step 6 can still rewrite config and unit files
//     and restart the service before it fails. The message said "left as it
//     was" for every run that failed before Step 6 or did not select it.
//   - A first install that fails between Step 6 and the unit being rendered has
//     no unit to stop. The message said the service "could NOT be stopped".
func TestAgentControllerRescueMessageSaysWhatHappened(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not installed")
	}
	mustContain := func(t *testing.T, msg string, want ...string) {
		t.Helper()
		for _, w := range want {
			if !strings.Contains(msg, w) {
				t.Errorf("message lacks %q:\n%s", w, msg)
			}
		}
	}
	mustNotContain := func(t *testing.T, msg string, bad ...string) {
		t.Helper()
		for _, b := range bad {
			if strings.Contains(msg, b) {
				t.Errorf("message says %q, which did not happen:\n%s", b, msg)
			}
		}
	}

	t.Run("--skip-tags agent-controller-C4: files rewritten and the service restarted before Steps 15-17 fail", func(t *testing.T) {
		f := newACFixture(t, acNewBin, acNewBin)
		o := acFailAfterSteps(t, ansible, f, agentControllerSteps(t, f, acInstallSteps...), nil, "--skip-tags", "agent-controller-C4")
		if o.Rollback["install_started"] == true {
			t.Fatalf("rollback=%v, want a run that never reached Step 6", o.Rollback)
		}
		// The oracle is the host, not the message: this run did restart the service.
		if n := f.calls(t, "restart"); n != 1 {
			t.Fatalf("restart calls = %d, want the one Step 14 made (the scenario itself changed)", n)
		}
		if _, err := os.Stat(f.unit); err != nil {
			t.Fatalf("Step 11 did not render the unit: %v", err)
		}
		mustContain(t, o.Message, "rewrote webhook-secret.env", "rewrote the systemd unit", "restarted the service", "None of that was rolled back")
		mustNotContain(t, o.Message, "left as it was", "rewrote config.yaml")
	})

	t.Run("--skip-tags agent-controller-C4 with nothing to change: the service is left as it was", func(t *testing.T) {
		f := newACFixture(t, acNewBin, acNewBin)
		reset, _, _ := agentControllerTasks(t)
		runACPlay(t, ansible, f, append(append([]any{}, reset...), agentControllerSteps(t, f, acInstallSteps...)...))
		f.resetCalls(t)
		o := acFailAfterSteps(t, ansible, f, agentControllerSteps(t, f, acInstallSteps...), nil, "--skip-tags", "agent-controller-C4")
		if n := f.calls(t, "restart"); n != 0 {
			t.Fatalf("restart calls = %d, want none (nothing changed)", n)
		}
		mustContain(t, o.Message, "left as it was")
		mustNotContain(t, o.Message, "restarted the service", "rewrote", "started or enabled")
	})

	t.Run("--check changes nothing and the message does not claim otherwise", func(t *testing.T) {
		f := newACFixture(t, acNewBin, acNewBin)
		o := acFailAfterSteps(t, ansible, f, agentControllerSteps(t, f, acInstallSteps...), nil, "--check")
		for _, path := range []string{f.unit, filepath.Join(f.conf, "config.yaml"), filepath.Join(f.conf, "webhook-secret.env")} {
			if _, err := os.Stat(path); err == nil {
				t.Errorf("--check created %s", path)
			}
		}
		if n := f.calls(t, "restart") + f.calls(t, "stop"); n != 0 {
			t.Errorf("--check made %d restart/stop calls", n)
		}
		mustContain(t, o.Message, "left as it was")
		mustNotContain(t, o.Message, "rewrote", "restarted the service")
	})

	t.Run("--tags agent-controller-C12: only webhook-secret.env is rewritten, nothing restarted", func(t *testing.T) {
		f := newACFixture(t, acNewBin, acNewBin)
		o := acFailAfterSteps(t, ansible, f, agentControllerSteps(t, f, acInstallSteps...), []string{"agent-controller-C12"}, "--tags", "agent-controller-C12")
		if n := f.calls(t, "restart"); n != 0 {
			t.Fatalf("restart calls = %d, want none (Step 14 is not selected)", n)
		}
		mustContain(t, o.Message, "rewrote webhook-secret.env", "None of that was rolled back")
		mustNotContain(t, o.Message, "left as it was", "restarted the service", "rewrote the systemd unit")
	})

	firstInstall := func(t *testing.T) acFixture {
		t.Helper()
		f := newACFixture(t, acNewBin, acNewBin)
		for _, path := range []string{f.bin, f.db, filepath.Join(f.sd, "loaded"), filepath.Join(f.sd, "active"), filepath.Join(f.sd, "enabled")} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		return f
	}
	upToStep6 := []string{"Step 3", "Step 4", "Step 5", "Step 6:"}

	t.Run("first install fails after Step 6, before any unit exists: there is no service to stop", func(t *testing.T) {
		f := firstInstall(t)
		o := acFailAfterSteps(t, ansible, f, agentControllerSteps(t, f, upToStep6...), nil)
		if o.Rollback["install_started"] != true {
			t.Fatalf("rollback=%v, want a run that reached Step 6", o.Rollback)
		}
		if acRead(t, f.bin) != acNewBin {
			t.Fatalf("Step 6 did not install the binary (the scenario itself changed)")
		}
		mustContain(t, o.Message, "systemd has no pilot-agent-controller.service", "no service to stop", "nothing was restored")
		mustNotContain(t, o.Message, "could NOT be stopped")
	})

	t.Run("a unit that exists but cannot be stopped is still reported as one", func(t *testing.T) {
		f := newACFixture(t, acOldBin, acNewBin)
		f.env["FAKE_STOP_FAILS"] = "1"
		o := acFailAfterSteps(t, ansible, f, agentControllerSteps(t, f, upToStep6...), nil)
		if active, _, _ := f.serviceState(t); !active {
			t.Fatalf("the fake service is not running (the scenario itself changed)")
		}
		mustContain(t, o.Message, "could NOT be stopped", "Nothing was restored")
		mustNotContain(t, o.Message, "no service to stop")
		if acRead(t, f.bin) != acNewBin {
			t.Errorf("the binary was restored although the service could not be stopped")
		}
	})

	t.Run("a status query that fails is not reported as a missing unit", func(t *testing.T) {
		f := newACFixture(t, acOldBin, acNewBin)
		f.env["FAKE_SHOW_FAILS"] = "1"
		o := acFailAfterSteps(t, ansible, f, agentControllerSteps(t, f, upToStep6...), nil)
		mustContain(t, o.Message, "could NOT be stopped")
		mustNotContain(t, o.Message, "no service to stop", "systemd has no")
	})
}

// TestAgentControllerRestartDecisionReadsOnlyWhatTheSelectionRegistered runs
// the real Steps 6, 8, 9 and 11-14 under tag selections that skip some of the
// steps whose results Steps 12 and 14 read. A selection that skips a step never
// registers its result, and a bare `x is changed` on a missing result fails the
// run (AGENTS.md section 4.4). Each selection must run without an undefined
// variable, not restart when nothing changed, and restart when a file this
// selection renders changed.
func TestAgentControllerRestartDecisionReadsOnlyWhatTheSelectionRegistered(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not installed")
	}
	steps := []string{"Step 6:", "Step 8:", "Step 9:", "Step 11:", "Step 12:", "Step 13:", "Step 14:"}
	for _, tt := range []struct {
		name string
		args []string
		// restarts: files this selection renders, so changing one must restart
		// the service. leavesAlone: files it does not render, so changing one
		// is not this run's change.
		restarts, leavesAlone []string
	}{
		{"no tags", nil, []string{"config", "unit", "secret"}, nil},
		{"--skip-tags agent-controller-C4 (Steps 6 and 8 register nothing)", []string{"--skip-tags", "agent-controller-C4"}, []string{"unit", "secret"}, []string{"config"}},
		{"--skip-tags agent-controller-C1 (Steps 11 and 13 register nothing; Step 12 asks about the unit)", []string{"--skip-tags", "agent-controller-C1"}, []string{"config", "secret"}, []string{"unit"}},
		// Steps 12 and 14 carry no tag, so --tags agent-controller-C1 selects
		// neither of them: the run renders the unit and is done.
		{"--tags agent-controller-C1 (Steps 12 and 14 are not selected)", []string{"--tags", "agent-controller-C1"}, nil, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newACFixture(t, acNewBin, acNewBin)
			files := map[string]string{
				"config": filepath.Join(f.conf, "config.yaml"),
				"unit":   f.unit,
				"secret": filepath.Join(f.conf, "webhook-secret.env"),
			}
			tasks := agentControllerSteps(t, f, steps...)
			// Converge first, so the next run starts from the rendered state.
			runACPlay(t, ansible, f, tasks)
			f.resetCalls(t)

			runACPlay(t, ansible, f, tasks, tt.args...)
			if n := f.calls(t, "restart"); n != 0 {
				t.Errorf("a run that changed nothing restarted the service %d times", n)
			}
			if n := f.calls(t, "daemon-reload"); n != 0 {
				t.Errorf("a run that changed nothing reloaded systemd %d times", n)
			}

			const marker = "\n# edited outside the playbook\n"
			tamper := func(which string) {
				t.Helper()
				acWrite(t, files[which], acRead(t, files[which])+marker, 0o600)
				f.resetCalls(t)
			}
			for _, which := range tt.restarts {
				tamper(which)
				runACPlay(t, ansible, f, tasks, tt.args...)
				if n := f.calls(t, "restart"); n != 1 {
					t.Errorf("%s changed and this selection renders it, but the service was restarted %d times, want 1", which, n)
				}
				if strings.Contains(acRead(t, files[which]), marker) {
					t.Errorf("%s was not rendered again", which)
				}
			}
			for _, which := range tt.leavesAlone {
				tamper(which)
				runACPlay(t, ansible, f, tasks, tt.args...)
				if n := f.calls(t, "restart"); n != 0 {
					t.Errorf("%s is not rendered by this selection, yet the service was restarted %d times", which, n)
				}
				if !strings.Contains(acRead(t, files[which]), marker) {
					t.Errorf("%s was rewritten by a selection that does not render it", which)
				}
			}
			if tt.restarts == nil && tt.leavesAlone == nil {
				// The selection renders the unit and nothing else.
				tamper("unit")
				runACPlay(t, ansible, f, tasks, tt.args...)
				if strings.Contains(acRead(t, files["unit"]), marker) {
					t.Errorf("--tags agent-controller-C1 did not render the unit again")
				}
			}
		})
	}
}
