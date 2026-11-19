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
// install block and the rescue's restore block, unprivileged.
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
	for _, task := range rescue {
		if m, ok := task.(map[string]any); ok && m["name"] == "ROLLBACK — restore only this invocation's validated material" {
			restore = append(restore, acUnprivileged(m))
		}
	}
	if len(restore) != 1 {
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
)

type acFixture struct {
	dir, bin, artifact, db, backups string
	vars                            map[string]any
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
	sum := sha256.Sum256([]byte(artifact))
	f.vars = map[string]any{
		"agent_controller_db_path":           f.db,
		"agent_controller_bin_dest":          f.bin,
		"agent_controller_backup_dir":        f.backups,
		"agent_controller_artifact_abs_path": f.artifact,
		"agent_controller_artifact_sha256":   hex.EncodeToString(sum[:]),
		"agent_controller_user":              "unused-in-tests",
		// The rescue's stop result, as a succeeded registered result.
		"agent_controller_rescue_stop": map[string]any{"failed": false, "changed": true},
	}
	return f
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
		"vars":  f.vars,
		"tasks": tasks,
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

// acFailingPlay injects the failure: a task right after Step 6, in the
// same block as the real steps, with the real restore block as the rescue.
func acFailingPlay(reset, steps, restore []any, factsPath string, beforeFail []any, failTags []string) []any {
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
	return append(append([]any{}, reset...), map[string]any{
		"name":   "install block under test",
		"block":  body,
		"rescue": append(append([]any{}, restore...), record),
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

func TestAgentControllerRescueRestoresOnlyThisRunsSnapshots(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not installed")
	}
	reset, steps, restore := agentControllerTasks(t)

	t.Run("upgrade fails after Step 6: binary and state.db come back", func(t *testing.T) {
		f := newACFixture(t, acOldBin, acNewBin)
		facts := filepath.Join(f.dir, "outcome.json")
		migrate := map[string]any{"name": "the new binary migrates state.db", "ansible.builtin.copy": map[string]any{"dest": f.db, "content": "state-migrated"}}
		runACPlay(t, ansible, f, acFailingPlay(reset, steps, restore, facts, []any{migrate}, nil))
		o := readACOutcome(t, facts)
		if !o.Restored || o.Failed {
			t.Fatalf("restored=%v failed=%v, want a restore", o.Restored, o.Failed)
		}
		if got := acRead(t, f.bin); got != acOldBin {
			t.Errorf("binary not restored: %q", got)
		}
		if got := acRead(t, f.db); got != "state-before" {
			t.Errorf("state.db not restored: %q", got)
		}
	})

	t.Run("a stale snapshot under the old fixed names is never restored", func(t *testing.T) {
		// The installed binary already matches the artifact: no upgrade, no
		// snapshot this run. An older run left fixed-name backups behind.
		f := newACFixture(t, acNewBin, acNewBin)
		acWrite(t, filepath.Join(f.backups, "pilot-agent-controller.prev"), "#!/bin/sh\n# stale\n", 0o755)
		acWrite(t, filepath.Join(f.backups, "pre-upgrade.db"), "state-stale", 0o600)
		acWrite(t, f.db, "state-current", 0o600)
		facts := filepath.Join(f.dir, "outcome.json")
		runACPlay(t, ansible, f, acFailingPlay(reset, steps, restore, facts, nil, nil))
		o := readACOutcome(t, facts)
		if o.Restored || o.Failed {
			t.Fatalf("restored=%v failed=%v, want nothing restored", o.Restored, o.Failed)
		}
		if acRead(t, f.bin) != acNewBin || acRead(t, f.db) != "state-current" {
			t.Errorf("a stale backup was restored: bin=%q db=%q", acRead(t, f.bin), acRead(t, f.db))
		}
	})

	t.Run("a run that never selected Step 6 restores nothing", func(t *testing.T) {
		f := newACFixture(t, acOldBin, acNewBin)
		facts := filepath.Join(f.dir, "outcome.json")
		runACPlay(t, ansible, f, acFailingPlay(reset, steps, restore, facts, nil, []string{"agent-controller-C2"}), "--tags", "agent-controller-C2")
		o := readACOutcome(t, facts)
		if o.Restored || o.Failed || o.Rollback["install_started"] == true {
			t.Fatalf("restored=%v failed=%v rollback=%v, want no restore authority", o.Restored, o.Failed, o.Rollback)
		}
		if acRead(t, f.bin) != acOldBin {
			t.Errorf("binary changed by a run that did not select Step 6")
		}
	})

	t.Run("a snapshot changed after validation is refused", func(t *testing.T) {
		f := newACFixture(t, acOldBin, acNewBin)
		facts := filepath.Join(f.dir, "outcome.json")
		tamper := map[string]any{
			"name": "something rewrites this run's binary snapshot",
			"ansible.builtin.shell": map[string]any{
				"cmd": "for d in " + f.backups + "/apply-*; do printf tampered > \"$d/pilot-agent-controller.prev\"; done",
			},
		}
		runACPlay(t, ansible, f, acFailingPlay(reset, steps, restore, facts, []any{tamper}, nil))
		o := readACOutcome(t, facts)
		if o.Restored || !o.Failed {
			t.Fatalf("restored=%v failed=%v, want the restore refused", o.Restored, o.Failed)
		}
		if got := acRead(t, f.bin); got != acNewBin {
			t.Errorf("binary was overwritten from a tampered snapshot: %q", got)
		}
	})
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
