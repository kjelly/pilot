package spec

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestRegression_WazuhCredentialBearingTasksSuppressOutputAndDiff(t *testing.T) {
	sites := map[string][]string{
		"wazuh-manager-apply.yml": {
			"Snapshot: retain existing configuration content",
			"Step 7: Remove the legacy managed UDP syslog_output on migration or disable",
			"Step 7a: Retire the managed development-only delivery localfile",
			"Step 9: Read the live manager configuration",
			"Step 9b: Verify legacy UDP forwarding is absent in the live configuration",
			"ROLLBACK — restore the previous files with their original metadata",
			"ROLLBACK — validate the restored rsyslog configuration",
		},
		"tasks/wazuh-alert-forward.yml": {"Wazuh: inspect the actual container logs mount"},
		"audit-log-forwarding-apply.yml": {
			"Step 7: Capture current-run forward config bytes",
			"Step 7: Keep the existing forward config for rollback",
			"ROLLBACK — restore the previous siem forward config",
			"ROLLBACK — validate the restored rsyslog configuration",
		},
		"tasks/rsyslog-relp-tls.yml": {
			"RELP: snapshot existing TLS files for rollback",
			"RELP: retain sender module declarations for rollback",
			"RELP: migrate the legacy audit-owned output module declaration",
		},
		"tasks/rsyslog-relp-restore.yml": {
			"RELP rollback: restore previous sender module declarations",
			"RELP rollback: restore the previous TLS files and profile",
		},
	}
	for file, names := range sites {
		doc := loadYAML(t, filepath.Join("../../playbooks/apply", file))
		for _, name := range names {
			task := findNamedTask(t, doc, name)
			if task["no_log"] != true || task["diff"] != false {
				t.Errorf("%s: %s must protect both output and diff", file, name)
			}
		}
	}
	main := loadFirstPlay(t, "wazuh-manager-apply.yml")
	include := findNamedTask(t, main, "ROLLBACK — restore the Wazuh transport material")
	apply := include["ansible.builtin.include_tasks"].(map[string]any)["apply"].(map[string]any)
	if apply["no_log"] != true || apply["diff"] != false {
		t.Error("credential-bearing rollback include must propagate no_log and diff protection")
	}
}

// Execute actual slurp/command/blockinfile/replace/copy modules with production
// task metadata under -vvv --diff. Only target paths, Docker's cat argv, and the
// intentional failure are adapted for an unprivileged local harness. Secrets
// are synthetic, and no captured output is echoed into a test failure.
func TestRegression_WazuhSnapshotRecoveryDoesNotLeakCredentials(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip(err)
	}
	for _, tc := range []struct {
		name, family, removeGuard string
		wantLeak                  bool
	}{
		{name: "Wazuh snapshot live read mutation and recovery", family: "main"},
		{name: "shared sender snapshot migration and recovery", family: "module"},
		{name: "counterexample unprotected snapshot", family: "main", removeGuard: "snapshot", wantLeak: true},
		{name: "counterexample unprotected restore loop", family: "main", removeGuard: "restore", wantLeak: true},
		{name: "counterexample unprotected live read", family: "main", removeGuard: "live", wantLeak: true},
		{name: "counterexample unprotected config diff", family: "main", removeGuard: "mutation", wantLeak: true},
		{name: "counterexample unprotected shared snapshot", family: "module", removeGuard: "snapshot", wantLeak: true},
		{name: "counterexample unprotected shared restore", family: "module", removeGuard: "restore", wantLeak: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			secret := "PILOT-SYNTHETIC-CREDENTIAL-211-" + strings.ReplaceAll(tc.removeGuard+tc.family, " ", "")
			original := "<ossec_config><indexer><password>" + secret + "</password></indexer></ossec_config>\n" +
				"<!-- BEGIN ANSIBLE MANAGED BLOCK (wazuh-manager-apply.yml siem forward) -->\n" +
				"<ossec_config><syslog_output><server>siem-log-server</server></syslog_output></ossec_config>\n" +
				"<!-- END ANSIBLE MANAGED BLOCK (wazuh-manager-apply.yml siem forward) -->\n"
			if tc.family == "module" {
				original = "# operator credential: " + secret + "\nmodule(load=\"omrelp\" tls.tlsLib=\"gnutls\")\nlocal6.* action(type=\"omrelp\" target=\"localhost\" port=\"20514\")\n"
			}
			file := filepath.Join(root, "operator.conf")
			if err := os.WriteFile(file, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			var snapshotStat, snapshot, mutation, restore map[string]any
			var live map[string]any
			if tc.family == "main" {
				play := loadFirstPlay(t, "wazuh-manager-apply.yml")
				snapshotStat = findNamedTask(t, play, "Snapshot: inspect files before Wazuh forwarding mutation")
				snapshotStat["loop"] = []any{file}
				snapshot = findNamedTask(t, play, "Snapshot: retain existing configuration content")
				mutation = findNamedTask(t, play, "Step 7: Remove the legacy managed UDP syslog_output on migration or disable")
				live = findNamedTask(t, play, "Step 9: Read the live manager configuration")
				live["ansible.builtin.command"] = map[string]any{"argv": []any{"cat", file}}
				restore = findNamedTask(t, play, "ROLLBACK — restore the previous files with their original metadata")
			} else {
				tasks := loadYAML(t, "../../playbooks/apply/tasks/rsyslog-relp-tls.yml")
				snapshotStat = findNamedTask(t, tasks, "RELP: snapshot module declarations before sender migration")
				snapshotStat["loop"] = []any{filepath.Join(root, "missing-shared.conf"), file}
				snapshot = findNamedTask(t, tasks, "RELP: retain sender module declarations for rollback")
				mutation = findNamedTask(t, tasks, "RELP: migrate the legacy audit-owned output module declaration")
				mutation["ansible.builtin.replace"].(map[string]any)["path"] = file
				restore = findNamedTask(t, loadYAML(t, "../../playbooks/apply/tasks/rsyslog-relp-restore.yml"), "RELP rollback: restore previous sender module declarations")
			}
			for key, task := range map[string]map[string]any{"snapshot": snapshot, "restore": restore, "live": live, "mutation": mutation} {
				if key == tc.removeGuard {
					delete(task, "no_log")
					delete(task, "diff")
				}
			}
			block := []any{snapshotStat, snapshot}
			if live != nil {
				block = append(block, live)
			}
			block = append(block, mutation, map[string]any{"name": "Trigger controlled recovery", "ansible.builtin.fail": map[string]any{"msg": "synthetic recovery control"}})
			rescue := []any{restore, map[string]any{"ansible.builtin.debug": map[string]any{"msg": "PILOT-SECRET-SAFE-RECOVERY-EXERCISED"}}}
			body, err := yaml.Marshal([]any{map[string]any{"hosts": "all", "gather_facts": false,
				"vars":  map[string]any{"wazuh_manager_conf": file, "siem_tls_enabled": true, "siem_tls_role": "wazuh-sender", "siem_tls_snapshot_role": "wazuh-sender"},
				"tasks": []any{map[string]any{"block": block, "rescue": rescue}}}})
			if err != nil {
				t.Fatal(err)
			}
			playbook := filepath.Join(root, "play.yml")
			if err := os.WriteFile(playbook, body, 0600); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(root, "ansible.cfg")
			if err := os.WriteFile(config, []byte("[defaults]\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("ansible-playbook", "-i", "localhost,", "-c", "local", "-vvv", "--diff", playbook)
			cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+config, "ANSIBLE_LOCAL_TEMP="+root)
			out, runErr := cmd.CombinedOutput()
			outputPath := filepath.Join(root, "output.log")
			if artifacts := os.Getenv("PILOT_SECRET_TEST_ARTIFACT_DIR"); artifacts != "" {
				if err := os.MkdirAll(artifacts, 0700); err != nil {
					t.Fatal(err)
				}
				stem := strings.ReplaceAll(tc.name, " ", "_")
				outputPath = filepath.Join(artifacts, stem+".combined.log")
				for suffix, data := range map[string][]byte{".play.yml": body, ".original.conf": []byte(original)} {
					if err := os.WriteFile(filepath.Join(artifacts, stem+suffix), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := os.WriteFile(outputPath, out, 0600); err != nil {
				t.Fatal(err)
			}
			if runErr != nil || !strings.Contains(string(out), "PILOT-SECRET-SAFE-RECOVERY-EXERCISED") {
				t.Fatalf("native recovery did not complete: %v; synthetic output location %s", runErr, outputPath)
			}
			if restored, err := os.ReadFile(file); err != nil || string(restored) != original {
				t.Fatalf("recovery did not restore exact original bytes: %v", err)
			}
			leaked := strings.Contains(string(out), secret) || strings.Contains(string(out), base64.StdEncoding.EncodeToString([]byte(original)))
			if leaked != tc.wantLeak {
				t.Fatalf("credential output leak=%v, want %v; synthetic output location %s", leaked, tc.wantLeak, outputPath)
			}
		})
	}
}
