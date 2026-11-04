package spec

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Real Ansible snapshot/copy/include/rescue modules run under the production
// selectors, and the restored config is checked by a byte-identical native
// rsyslog binary. Service operations are isolated canaries; the VM evidence
// separately establishes real systemd/TLS availability.
func TestRegression_WazuhTaggedRELPRecovery(t *testing.T) {
	for _, tool := range []string{"ansible-playbook", "rsyslogd", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(err)
		}
	}
	read := func(name string) []map[string]any {
		t.Helper()
		data, err := os.ReadFile("../../playbooks/apply/tasks/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var tasks []map[string]any
		if err := yaml.Unmarshal(data, &tasks); err != nil {
			t.Fatal(err)
		}
		return tasks
	}
	for _, tc := range []struct {
		name, selector                                 string
		partial, early, excluded, removeApply, invalid bool
	}{
		{name: "C11 restores existing private and module bytes", selector: "C11"},
		{name: "C10 removes new private and module files", selector: "C10", partial: true},
		{name: "full selection restores existing private bytes"},
		{name: "counterexample removing only apply tags", selector: "C11", removeApply: true},
		{name: "nonselected C1 ignores stale provider state", selector: "C1"},
		{name: "excluded reader ignores stale provider state", selector: "C11", excluded: true},
		{name: "failure before TLS snapshot ignores stale state", selector: "C11", early: true},
		{name: "invalid restored configuration leaves loaded service", selector: "C11", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			private := filepath.Join(root, "private")
			tls := filepath.Join(private, "pilot-relp-wazuh-sender")
			if err := os.MkdirAll(tls, 0700); err != nil {
				t.Fatal(err)
			}
			write := func(path, body string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
			}
			secret := "PILOT_TAGGED_PRIVATE_211_" + strings.ReplaceAll(tc.name, " ", "_")
			originals := map[string]string{}
			var mutations []any
			var privateValues []string
			for _, name := range []string{"ca.pem", "cert.pem", "key.pem", "profile.json", "09-pilot-omrelp.conf", "99-siem-forward.conf"} {
				path := filepath.Join(tls, name)
				if strings.HasSuffix(name, ".conf") {
					path = filepath.Join(private, name)
				}
				old := "old " + name + " " + secret
				if !tc.partial || name == "ca.pem" || name == "profile.json" || name == "99-siem-forward.conf" {
					write(path, old, 0600)
					originals[path] = old
				}
				fresh := "new " + name + " " + secret
				mutations = append(mutations, map[string]any{"path": path, "payload": fresh})
				privateValues = append(privateValues, old, fresh, base64.StdEncoding.EncodeToString([]byte(old)))
				write(filepath.Join(root, name), "unrelated "+name, 0600)
			}
			foreign := filepath.Join(root, "foreign-provider.pem")
			write(foreign, "foreign-current", 0600)
			staleJournal := filepath.Join(root, "foreign-journal.json")
			write(staleJournal, "foreign-journal", 0600)
			foreignInfo, _ := os.Stat(foreign)
			owner := foreignInfo.Sys().(*syscall.Stat_t)
			staleItem := map[string]any{"item": map[string]any{"stat": map[string]any{"path": foreign, "uid": owner.Uid, "gid": owner.Gid, "mode": "0600"}}, "content": base64.StdEncoding.EncodeToString([]byte("foreign-old"))}
			main := loadFirstPlay(t, "wazuh-manager-apply.yml")
			var snapshots []map[string]any
			for _, task := range read("rsyslog-relp-tls.yml") {
				switch task["name"] {
				case "RELP: inspect the role's TLS files and desired profile", "RELP: refuse symlinks and non-regular certificate files", "RELP: snapshot existing TLS files for rollback", "RELP: record this snapshot's role", "RELP: snapshot module declarations before sender migration", "RELP: retain sender module declarations for rollback":
					snapshots = append(snapshots, task)
				}
			}
			if len(snapshots) != 6 {
				t.Fatal("missing production TLS/module snapshots")
			}
			selected := []any{}
			if tc.early {
				selected = append(selected, map[string]any{"ansible.builtin.fail": map[string]any{"msg": "PILOT_BEFORE_TLS_SNAPSHOT"}})
			}
			selected = append(selected, withPath(t, snapshots, "/etc/rsyslog.d", private)...)
			selected = append(selected,
				map[string]any{"name": "Controlled private mutation", "no_log": true, "diff": false, "ansible.builtin.copy": map[string]any{"dest": "{{ item.path }}", "content": "{{ item.payload }}", "mode": "0640"}, "loop": mutations},
				map[string]any{"ansible.builtin.copy": map[string]any{"dest": filepath.Join(root, "mutated"), "content": "mutation completed", "mode": "0600"}})
			marshalFile := func(path string, data any) {
				t.Helper()
				body, err := yaml.Marshal(data)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			marshalFile(filepath.Join(root, "selected.yml"), selected)
			marshalFile(filepath.Join(root, "restore.yml"), withPath(t, read("rsyslog-relp-restore.yml"), "/etc/rsyslog.d", private))
			include := findNamedTask(t, main, "Step 9c: Configure isolated host imfile forwarding")
			include["ansible.builtin.include_tasks"].(map[string]any)["file"] = filepath.Join(root, "selected.yml")
			restore := findNamedTask(t, main, "ROLLBACK — restore the Wazuh transport material")
			restoreArgs := restore["ansible.builtin.include_tasks"].(map[string]any)
			restoreArgs["file"] = filepath.Join(root, "restore.yml")
			if tc.removeApply {
				delete(restoreArgs["apply"].(map[string]any), "tags")
			}
			binary, _ := exec.LookPath("rsyslogd")
			bytes, err := os.ReadFile(binary)
			if err != nil {
				t.Fatal(err)
			}
			validator := filepath.Join(root, "rsyslogd")
			if err := os.WriteFile(validator, bytes, 0755); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(root, "rsyslog.conf")
			configBody := "*.* action(type=\"omfile\" file=\"" + filepath.Join(root, "service.log") + "\")\n"
			if tc.invalid {
				configBody = "PILOT_INTENTIONALLY_INVALID_RESTORED_CONFIGURATION(\n"
			}
			write(config, configBody, 0600)
			validate := findNamedTask(t, main, "ROLLBACK — validate the restored rsyslog configuration")
			validate["ansible.builtin.command"] = map[string]any{"argv": []any{validator, "-N1", "-f", config}}
			restart := findNamedTask(t, main, "ROLLBACK — load restored rsyslog configuration")
			delete(restart, "ansible.builtin.systemd")
			restart["ansible.builtin.command"] = map[string]any{"argv": []any{"python3", "-c", "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('validated restart')", filepath.Join(root, "restarted")}}
			verify := findNamedTask(t, main, "ROLLBACK — verify the restored rsyslog service remains active")
			verify["ansible.builtin.command"] = map[string]any{"argv": []any{"/bin/true"}}
			var canaries []any
			for _, name := range []string{"ROLLBACK — reload restored AppArmor permissions", "ROLLBACK — recreate manager with its restored source configuration", "ROLLBACK — wait for the restored manager agent listener"} {
				task := findNamedTask(t, main, name)
				for key := range task {
					if strings.HasPrefix(key, "ansible.") || strings.HasPrefix(key, "community.") {
						delete(task, key)
					}
				}
				task["ansible.builtin.copy"] = map[string]any{"dest": filepath.Join(root, "unexpected-side-effect"), "content": name, "mode": "0600"}
				canaries = append(canaries, task)
			}
			rescue := []any{restore, validate, restart, verify}
			rescue = append(rescue, canaries...)
			rescue = append(rescue, findNamedTask(t, main, "ROLLBACK — surface the original failure"))
			pre := []any{
				map[string]any{"tags": []any{"always"}, "no_log": true, "ansible.builtin.set_fact": map[string]any{"siem_tls_snapshot_role": "wazuh-sender", "siem_tls_snapshot": map[string]any{"results": []any{staleItem}}, "wazuh_acl_journal": map[string]any{"path": staleJournal}, "wazuh_apparmor_result": map[string]any{"changed": true}, "wazuh_reload_pending": map[string]any{}, "wazuh_live_config": map[string]any{}}},
				read("rsyslog-relp-inputs.yml")[0],
				findNamedTask(t, main, "Reset per-run ACL journal completion state"),
			}
			pre = append(pre, map[string]any{"block": []any{include, map[string]any{"tags": []any{"always"}, "ansible.builtin.fail": map[string]any{"msg": "PILOT_TAGGED_RELP_FAILURE_WITNESS"}}}, "rescue": rescue,
				"always": []any{findNamedTask(t, main, "Retire the transient ACL journal only after commit or successful recovery")}})
			playbook := filepath.Join(root, "play.yml")
			marshalFile(playbook, []any{map[string]any{"hosts": "all", "gather_facts": false, "vars": map[string]any{"siem_tls_role": "wazuh-sender", "siem_tls_enabled": true}, "tasks": pre}})
			ansibleConfig := filepath.Join(root, "ansible.cfg")
			write(ansibleConfig, "[defaults]\n", 0600)
			args := []string{"-i", "localhost,", "-c", "local", "-vvv", "--diff", playbook}
			if tc.selector != "" {
				args = append(args, "--tags", tc.selector)
			}
			if tc.excluded {
				args = append(args, "--skip-tags", "C10,C11")
			}
			cmd := exec.Command("ansible-playbook", args...)
			cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+ansibleConfig, "ANSIBLE_LOCAL_TEMP="+filepath.Join(root, "local"), "ANSIBLE_REMOTE_TEMP="+filepath.Join(root, "remote"), "ANSIBLE_FORKS=1")
			out, runErr := cmd.CombinedOutput()
			artifact := filepath.Join(root, "output.log")
			if folder := os.Getenv("PILOT_TAGGED_RELP_TEST_ARTIFACT_DIR"); folder != "" {
				if err := os.MkdirAll(folder, 0700); err != nil {
					t.Fatal(err)
				}
				artifact = filepath.Join(folder, strings.ReplaceAll(tc.name, " ", "_")+".log")
			}
			if err := os.WriteFile(artifact, out, 0600); err != nil {
				t.Fatal(err)
			}
			if runErr == nil || !strings.Contains(string(out), "wazuh-manager apply failed") {
				t.Fatalf("original failure was not retained; output at %s", artifact)
			}
			for _, value := range privateValues {
				if strings.Contains(string(out), value) {
					t.Fatalf("private output leaked; output at %s", artifact)
				}
			}
			selectedRun := (tc.selector == "" || tc.selector == "C10" || tc.selector == "C11") && !tc.excluded && !tc.early
			_, mutatedErr := os.Stat(filepath.Join(root, "mutated"))
			if (mutatedErr == nil) != selectedRun {
				t.Fatalf("unexpected mutation selection; output at %s", artifact)
			}
			if body, err := os.ReadFile(foreign); err != nil || string(body) != "foreign-current" {
				t.Fatal("stale provider snapshot was used")
			}
			if body, err := os.ReadFile(staleJournal); err != nil || string(body) != "foreign-journal" {
				t.Fatal("unrelated journal was retired")
			}
			if _, err := os.Stat(filepath.Join(root, "unexpected-side-effect")); err == nil {
				t.Fatal("nonselected AppArmor/manager recovery ran")
			}
			_, restarted := os.Stat(filepath.Join(root, "restarted"))
			if (restarted == nil) != (selectedRun && !tc.removeApply && !tc.invalid) {
				t.Fatalf("restart validation/selection invariant failed; output at %s", artifact)
			}
			for _, raw := range mutations {
				item := raw.(map[string]any)
				path := item["path"].(string)
				body, err := os.ReadFile(path)
				if tc.removeApply {
					if err != nil || string(body) != item["payload"] {
						t.Fatal("missing-apply control did not leave the intended mutation")
					}
				} else if old, exists := originals[path]; exists {
					info, statErr := os.Stat(path)
					if err != nil || string(body) != old || statErr != nil || info.Mode().Perm() != 0600 {
						t.Fatalf("original private/module bytes or mode not restored; output at %s", artifact)
					}
					if stat := info.Sys().(*syscall.Stat_t); stat.Uid != owner.Uid || stat.Gid != owner.Gid {
						t.Fatal("original owner was not restored")
					}
				} else if !os.IsNotExist(err) {
					t.Fatal("new private/module material survived rollback")
				}
			}
			for _, name := range []string{"ca.pem", "cert.pem", "key.pem", "profile.json", "09-pilot-omrelp.conf", "99-siem-forward.conf"} {
				if body, err := os.ReadFile(filepath.Join(root, name)); err != nil || string(body) != "unrelated "+name {
					t.Fatal("unrelated basename file changed")
				}
			}
		})
	}
}
