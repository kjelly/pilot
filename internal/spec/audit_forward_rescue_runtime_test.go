package spec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Run the production C19 control flow and builtin systemd module. Only the
// external service commands are shims, so the controller's rsyslog is untouched.
func TestRegression_AuditForwardRescuePreservesUnchangedRuntime(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	for _, tc := range []struct {
		name, mode string
		restarts   int
		failed     bool
		active     bool
		stale      bool
	}{
		{"fatal config before runtime change", "fatal", 0, true, true, false},
		{"stale register from an earlier play", "fatal", 0, true, true, true},
		{"unchanged valid runtime", "unchanged", 0, false, true, false},
		{"failed restart recovers validated config", "recover", 2, true, true, false},
		{"invalid restored config never restarts again", "invalid-restore", 1, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			// RELP adds an always-tagged relative include before C19.
			// Keep that production include intact in the local play fixture.
			sourceTasks, err := filepath.Abs("../../playbooks/apply/tasks")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(sourceTasks, filepath.Join(dir, "tasks")); err != nil {
				t.Fatal(err)
			}
			write := func(path, body string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			const shim = `import os,pathlib,sys
d=pathlib.Path(os.environ['AUDIT_RESCUE_TEST_DIR']);mode=os.environ['AUDIT_RESCUE_TEST_MODE']
name=pathlib.Path(sys.argv[0]).name;args=sys.argv[1:]
with (d/'calls').open('a') as f:f.write(name+' '+' '.join(args)+'\n')
if name=='rsyslogd':
 p=d/'validations';n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))
 if mode=='fatal' or (mode=='invalid-restore' and n>1):
  print('fatal on-disk configuration',file=sys.stderr);sys.exit(1)
elif name=='systemctl':
 if args[0]=='show':
  if '-p' in args:
   print('2099-01-01 00:00:00 UTC' if mode=='unchanged' else '2000-01-01 00:00:00 UTC')
  else:print('LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled')
 elif args[0]=='is-enabled':print('enabled')
 elif args[0]=='restart':
  p=d/'restarts';n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))
  if mode in ('recover','invalid-restore') and n==1:
   (d/'state').write_text('inactive');sys.exit(1)
  (d/'state').write_text('active')
 else:raise RuntimeError('unexpected systemctl command: '+repr(args))
elif name!='augenrules':raise RuntimeError(name)
`
			for _, name := range []string{"rsyslogd", "systemctl", "augenrules"} {
				write(filepath.Join(bin, name), "#!"+python+"\n"+shim, 0o700)
			}
			write(filepath.Join(dir, "state"), "active", 0o600)
			conf := filepath.Join(dir, "forward.conf")
			const original = "# existing, loaded forwarding configuration\n"
			write(conf, original, 0o600)
			write(conf+".pre-audit-forwarding.bak", "# stale backup from a previous play\n", 0o600)
			audit := filepath.Join(dir, "audit.rules")
			write(audit, "# current audit rules\n", 0o600)
			write(audit+".old", "# stale audit backup\n", 0o600)
			play := loadFirstPlay(t, "audit-log-forwarding-apply.yml")
			play["gather_facts"], play["become"] = false, false
			play["environment"] = map[string]any{"PATH": bin + string(os.PathListSeparator) + os.Getenv("PATH"), "AUDIT_RESCUE_TEST_DIR": dir, "AUDIT_RESCUE_TEST_MODE": tc.mode}
			vars := play["vars"].(map[string]any)
			vars["siem_forward_conf"], vars["audit_rules_dest"] = conf, audit
			plays := []any{}
			if tc.stale {
				plays = append(plays, map[string]any{"hosts": "all", "gather_facts": false, "tasks": []any{map[string]any{"tags": []string{"always"}, "ansible.builtin.set_fact": map[string]any{
					"audit_rules_result": map[string]any{"changed": true, "backup_file": audit + ".old"}, "siem_forward_conf_result": map[string]any{"changed": true}, "rsyslog_selinux_port_label": map[string]any{"changed": true},
					"siem_forward_rsyslog_start_result": map[string]any{"changed": true}, "siem_forward_rsyslog_restart_result": map[string]any{"changed": true, "failed": true},
				}}}})
			}
			plays = append(plays, play)
			data, err := yaml.Marshal(plays)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "play.yml")
			write(path, string(data), 0o600)
			command := exec.Command("ansible-playbook", "-i", "localhost,", "-c", "local", path, "--tags", "C19", "-e", "target_group=all")
			command.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "local"), "ANSIBLE_REMOTE_TEMP="+filepath.Join(dir, "remote"), "ANSIBLE_CACHE_PLUGIN=memory", "ANSIBLE_FORKS=1")
			out, runErr := command.CombinedOutput()
			if tc.failed != (runErr != nil) {
				t.Fatalf("error=%v, want failed=%t\n%s", runErr, tc.failed, out)
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
			if !strings.Contains(string(calls), "rsyslogd -N1") {
				t.Fatalf("C19 never reached its real validation command\n%s", out)
			}
			count := "0"
			if b, err := os.ReadFile(filepath.Join(dir, "restarts")); err == nil {
				count = string(b)
			}
			state, _ := os.ReadFile(filepath.Join(dir, "state"))
			current, _ := os.ReadFile(conf)
			currentAudit, _ := os.ReadFile(audit)
			if count != fmt.Sprint(tc.restarts) || (string(state) == "active") != tc.active || string(current) != original || string(currentAudit) != "# current audit rules\n" {
				t.Fatalf("restarts=%s, state=%s, config unchanged=%t\n%s\n%s", count, state, string(current) == original, calls, out)
			}
		})
	}
}

// Every rsyslog rescue restart must be gated by a successful validation of
// the restored effective configuration, including future apply playbooks.
func TestRegression_RsyslogRescueRestartsRequireValidation(t *testing.T) {
	files, err := filepath.Glob("../../playbooks/apply/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	var walk func(string, any)
	walk = func(file string, node any) {
		switch value := node.(type) {
		case []any:
			for _, child := range value {
				walk(file, child)
			}
		case map[string]any:
			if rescue, ok := value["rescue"].([]any); ok {
				validated := map[string]bool{}
				for _, raw := range rescue {
					task := raw.(map[string]any)
					if strings.Contains(fmt.Sprint(task["ansible.builtin.command"]), "rsyslogd -N1") {
						if register, ok := task["register"].(string); ok {
							validated[register] = true
						}
					}
					for _, module := range []string{"ansible.builtin.systemd", "ansible.builtin.systemd_service", "ansible.builtin.service"} {
						service, _ := task[module].(map[string]any)
						if service["name"] != "rsyslog" || service["state"] != "restarted" {
							continue
						}
						guarded := false
						for register := range validated {
							when := fmt.Sprint(task["when"])
							guarded = guarded || (strings.Contains(when, register+".rc") && strings.Contains(when, "== 0"))
						}
						if !guarded {
							t.Errorf("%s: %v restarts rsyslog without restored-config validation", file, task["name"])
						}
					}
				}
			}
			for _, child := range value {
				walk(file, child)
			}
		}
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var document any
		if err := yaml.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		walk(file, document)
	}
}
