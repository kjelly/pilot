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

// The pre-upgrade backup (Steps 3-5) has to run exactly when Step 6 replaces
// the binary, under every tag selection Ansible makes. It used to be
// `always`, so a run that never reached Step 6 (pilot deploy --limit passes
// only the limited hosts' component tags and still pulls in it-core) kept
// "backing up" an upgrade that never happened, and Step 4's changed_when: true
// failed the second-apply idempotency check. A hand-written predicate over
// ansible_run_tags was no better: it missed the `tagged` selector and
// --skip-tags, so Step 6 upgraded the binary with no backup to restore from.
//
// This runs the real Steps 3-6 with real ansible-playbook for each selection.
func TestDetectionEngineBackupFollowsStep6TagSelection(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not installed")
	}
	raw, err := os.ReadFile(filepath.Join(repoRootForTest(t), "playbooks", "apply", "detection-engine-apply.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	var block []any
	for _, play := range plays {
		tasks, _ := play["tasks"].([]any)
		for _, task := range tasks {
			if m, ok := task.(map[string]any); ok && m["name"] == "Detection Engine install + systemd service" {
				block, _ = m["block"].([]any)
			}
		}
	}
	if block == nil {
		t.Fatal("the install block is gone from detection-engine-apply.yml")
	}
	var picked []any
	prefixes := []string{"Step 3", "Step 4", "Step 5", "Step 6:"}
	seen := map[string]bool{}
	for _, task := range block { // in playbook order, every task of these steps
		m, ok := task.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		for _, prefix := range prefixes {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			seen[prefix] = true
			// Run unprivileged: drop the root ownership the real tasks ask for.
			for _, module := range []string{"ansible.builtin.copy", "ansible.builtin.file"} {
				if args, ok := m[module].(map[string]any); ok {
					delete(args, "owner")
					delete(args, "group")
				}
			}
			picked = append(picked, m)
			break
		}
	}
	for _, prefix := range prefixes {
		if !seen[prefix] {
			t.Fatalf("no task named %q* in the install block", prefix)
		}
	}

	for _, tt := range []struct {
		name  string
		args  []string
		step6 bool
	}{
		{"no tags", nil, true},
		{"--tags tagged", []string{"--tags", "tagged"}, true},
		{"--tags detection-engine-C1", []string{"--tags", "detection-engine-C1"}, true},
		{"--tags detection-engine", []string{"--tags", "detection-engine"}, true},
		{"--tags observability", []string{"--tags", "observability"}, true},
		{"--skip-tags tagged", []string{"--skip-tags", "tagged"}, false},
		{"--tags detection-engine --skip-tags detection-engine-C1", []string{"--tags", "detection-engine", "--skip-tags", "detection-engine-C1"}, false},
		{"other components only (pilot deploy --limit)", []string{"--tags", "audit-log-forwarding,host-monitoring,docker"}, false},
		{"another row of this component", []string{"--tags", "detection-engine-C2"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "pilot-detection-engine")
			artifact := filepath.Join(dir, "artifact")
			db := filepath.Join(dir, "state.db")
			backups := filepath.Join(dir, "backups")
			const oldBin = "#!/bin/sh\n# old build\nif [ \"$1 $2\" = \"db check\" ]; then echo ok; exit 0; fi\n[ \"$1 $2\" = \"db backup\" ] && cp \"$4\" \"$6\"\n"
			const newBin = "#!/bin/sh\n# new build\n"
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
			sum := sha256.Sum256([]byte(newBin))

			play := []any{map[string]any{
				"hosts": "localhost", "connection": "local", "gather_facts": false,
				"vars": map[string]any{
					"detection_engine_rollback":          map[string]any{"binary_ready": false, "db_ready": false, "install_started": false},
					"detection_engine_rescue_stop":       map[string]any{"failed": false},
					"detection_engine_db_path":           db,
					"detection_engine_bin_dest":          bin,
					"detection_engine_backup_dir":        backups,
					"detection_engine_artifact_abs_path": artifact,
					"detection_engine_artifact_sha256":   hex.EncodeToString(sum[:]),
				},
				// What site.yml's import gives every task of the real play.
				"tasks": []any{map[string]any{"block": picked, "tags": []string{"observability", "detection-engine"}}},
			}}
			out, err := yaml.Marshal(play)
			if err != nil {
				t.Fatal(err)
			}
			playbook := filepath.Join(dir, "play.yml")
			write(playbook, string(out), 0o600)

			cmd := exec.Command(ansible, append([]string{"-i", "localhost,", playbook}, tt.args...)...)
			cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
			if log, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("ansible-playbook: %v\n%s", err, log)
			}

			got, err := os.ReadFile(bin)
			if err != nil {
				t.Fatal(err)
			}
			upgraded := string(got) == newBin
			dbMatches, _ := filepath.Glob(filepath.Join(backups, "apply-*", "pre-upgrade.db"))
			binMatches, _ := filepath.Glob(filepath.Join(backups, "apply-*", "pilot-detection-engine.prev"))
			var dbErr, binErr error
			if len(dbMatches) != 1 {
				dbErr = os.ErrNotExist
			}
			if len(binMatches) != 1 {
				binErr = os.ErrNotExist
			}
			backedUp := dbErr == nil && binErr == nil
			anyBackup := dbErr == nil || binErr == nil
			if upgraded != tt.step6 {
				t.Fatalf("Step 6 ran = %v, want %v (the selection itself changed; update the table)", upgraded, tt.step6)
			}
			if upgraded && !backedUp {
				t.Errorf("Step 6 replaced the binary but the backups are missing (pre-upgrade.db: %v, previous binary: %v): a failure would leave nothing to restore", dbErr == nil, binErr == nil)
			}
			if !upgraded && anyBackup {
				t.Errorf("a run that does not replace the binary still took a backup (pre-upgrade.db: %v, previous binary: %v)", dbErr == nil, binErr == nil)
			}
		})
	}
}
