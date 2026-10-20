package spec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// Execute production snapshot and rollback tasks with real Ansible modules.
// Only the /etc/rsyslog.d prefix moves into the disposable test directory.
func TestRegression_SIEMRelpRollbackRestoresPartialAndFreshFiles(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip(err)
	}
	source, err := filepath.Abs("../../playbooks/apply/tasks")
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) []map[string]any {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		var tasks []map[string]any
		if err := yaml.Unmarshal(data, &tasks); err != nil {
			t.Fatal(err)
		}
		return tasks
	}
	var snapshot []map[string]any
	for _, task := range read("rsyslog-relp-tls.yml") {
		switch task["name"] {
		case "RELP: inspect the role's TLS files and desired profile", "RELP: refuse symlinks and non-regular certificate files", "RELP: snapshot existing TLS files for rollback", "RELP: record this snapshot's role":
			snapshot = append(snapshot, task)
		}
	}
	if len(snapshot) != 4 {
		t.Fatalf("expected four production snapshot tasks, got %d", len(snapshot))
	}
	for _, role := range []string{"sender", "receiver"} {
		for _, scenario := range []struct {
			name     string
			existing []string
		}{
			{"existing RELP failure", []string{"ca.pem", "cert.pem", "key.pem", "profile.json"}},
			{"fresh failure", nil},
			{"TCP to RELP failure", []string{"profile.json"}},
			{"partial material failure", []string{"ca.pem", "key.pem"}},
		} {
			t.Run(role+"/"+scenario.name, func(t *testing.T) {
				dir := t.TempDir()
				tlsRoot := filepath.Join(dir, "private")
				tlsDir := filepath.Join(tlsRoot, "pilot-relp-"+role)
				if err := os.MkdirAll(tlsDir, 0o700); err != nil {
					t.Fatal(err)
				}
				write := func(path, body string, mode os.FileMode) {
					t.Helper()
					if err := os.WriteFile(path, []byte(body), mode); err != nil {
						t.Fatal(err)
					}
				}
				names := []string{"ca.pem", "cert.pem", "key.pem", "profile.json"}
				for _, name := range names {
					// A basename cleanup would delete these unrelated cwd files.
					write(filepath.Join(dir, name), "unrelated "+name, 0o600)
				}
				existing := map[string]bool{}
				for _, name := range scenario.existing {
					existing[name] = true
					write(filepath.Join(tlsDir, name), "original "+name, 0o600)
				}
				tasks := withPath(t, snapshot, "/etc/rsyslog.d", tlsRoot)
				restore := withPath(t, read("rsyslog-relp-restore.yml"), "/etc/rsyslog.d", tlsRoot)
				tasks = append(tasks, map[string]any{
					"block": []any{
						map[string]any{"name": "Simulate material written before validation fails", "ansible.builtin.copy": map[string]any{"dest": tlsDir + "/{{ item }}", "content": "new test material", "mode": "0640"}, "loop": names},
						map[string]any{"ansible.builtin.fail": map[string]any{"msg": "injected certificate validation failure"}},
					}, "rescue": restore,
				})
				play := []any{map[string]any{"hosts": "all", "gather_facts": false, "vars": map[string]any{"siem_tls_role": role}, "tasks": tasks}}
				data, err := yaml.Marshal(play)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, "play.yml")
				write(path, string(data), 0o600)
				command := exec.Command("ansible-playbook", "-i", "localhost,", "-c", "local", path)
				command.Dir = dir
				command.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "local"), "ANSIBLE_REMOTE_TEMP="+filepath.Join(dir, "remote"), "ANSIBLE_CACHE_PLUGIN=memory", "ANSIBLE_FORKS=1")
				out, runErr := command.CombinedOutput()
				if runErr != nil {
					t.Fatalf("rollback execution: %v\n%s", runErr, out)
				}
				for _, name := range names {
					path := filepath.Join(tlsDir, name)
					body, err := os.ReadFile(path)
					if existing[name] {
						info, statErr := os.Stat(path)
						if err != nil || string(body) != "original "+name || statErr != nil || info.Mode().Perm() != 0o600 {
							t.Errorf("original %s was not restored with its original mode: %v, %v", name, err, statErr)
						}
					} else if !os.IsNotExist(err) {
						t.Errorf("new %s survived rollback: %v", name, err)
					}
					sentinel, err := os.ReadFile(filepath.Join(dir, name))
					if err != nil || string(sentinel) != "unrelated "+name {
						t.Errorf("rollback touched unrelated cwd file %s: %v", name, err)
					}
				}
			})
		}
	}
}

// Real copy/slurp/systemd modules reproduce the loaded-state effect of TLS
// rollback. Only external service commands are replaced by isolated shims.
func TestRegression_SIEMTLSRollbackReloadsChangedMaterial(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	read := func(name string) []map[string]any {
		t.Helper()
		b, err := os.ReadFile("../../playbooks/apply/tasks/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var tasks []map[string]any
		if err := yaml.Unmarshal(b, &tasks); err != nil {
			t.Fatal(err)
		}
		return tasks
	}
	var snapshot []map[string]any
	for _, task := range read("rsyslog-relp-tls.yml") {
		switch task["name"] {
		case "RELP: inspect the role's TLS files and desired profile", "RELP: refuse symlinks and non-regular certificate files", "RELP: snapshot existing TLS files for rollback", "RELP: record this snapshot's role":
			snapshot = append(snapshot, task)
		}
	}
	if len(snapshot) != 4 {
		t.Fatal("missing production snapshot tasks")
	}
	for _, tc := range []struct {
		name, mode string
		change     bool
		restart    bool
		pending    bool
	}{
		{"changed TLS restore reloads validated state", "valid", true, true, false},
		{"invalid global restore leaves loaded daemon", "fatal", true, false, true},
		{"unchanged TLS restore leaves loaded daemon", "valid", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin, private := filepath.Join(dir, "bin"), filepath.Join(dir, "private")
			tlsDir := filepath.Join(private, "pilot-relp-sender")
			for _, path := range []string{bin, tlsDir} {
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path, body string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			const shim = `import os,pathlib,sys
d=pathlib.Path(os.environ['TLS_RELOAD_CASE_DIR']);a=sys.argv[1:]
if pathlib.Path(sys.argv[0]).name=='rsyslogd':
 sys.exit(1 if os.environ['TLS_RELOAD_CASE_MODE']=='fatal' else 0)
if a[0]=='show':
 if 'MainPID' in a:print('1234')
 elif 'ActiveEnterTimestamp' in a:print('2099-01-01 00:00:00 UTC' if (d/'restarted').exists() else '2000-01-01 00:00:00 UTC')
 else:print('LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled')
elif a[0]=='is-enabled':print('enabled')
elif a[0]=='restart':(d/'restarted').write_text('1')
else:raise RuntimeError(a)
`
			for _, name := range []string{"systemctl", "rsyslogd"} {
				write(filepath.Join(bin, name), "#!"+python+"\n"+shim, 0700)
			}
			config := filepath.Join(dir, "forward.conf")
			files := []string{config}
			for _, name := range []string{"ca.pem", "cert.pem", "key.pem", "profile.json"} {
				files = append(files, filepath.Join(tlsDir, name))
			}
			for _, path := range files {
				write(path, "old material", 0600)
				if err := os.Chtimes(path, time.Unix(1000, 0), time.Unix(1000, 0)); err != nil {
					t.Fatal(err)
				}
			}
			tasks := []any{read("rsyslog-relp-inputs.yml")[0]}
			tasks = append(tasks, withPath(t, snapshot, "/etc/rsyslog.d", private)...)
			if tc.change {
				tasks = append(tasks, map[string]any{"ansible.builtin.copy": map[string]any{"dest": filepath.Join(tlsDir, "key.pem"), "content": "new invalid key", "mode": "0600"}})
			}
			tasks = append(tasks, withPath(t, read("rsyslog-relp-restore.yml"), "/etc/rsyslog.d", private)...)
			play := loadFirstPlay(t, "audit-log-forwarding-apply.yml")
			tasks = append(tasks, findNamedTask(t, play, "ROLLBACK — validate the restored rsyslog configuration"), findNamedTask(t, play, "ROLLBACK — restart rsyslog with the restored configuration"))
			env := map[string]any{"PATH": bin + string(os.PathListSeparator) + os.Getenv("PATH"), "TLS_RELOAD_CASE_DIR": dir, "TLS_RELOAD_CASE_MODE": tc.mode}
			body, err := yaml.Marshal([]any{map[string]any{"hosts": "all", "gather_facts": false, "environment": env, "vars": map[string]any{"siem_tls_role": "sender", "siem_forward_rsyslog_start_result": map[string]any{}, "siem_forward_rsyslog_restart_result": map[string]any{}}, "tasks": tasks}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "play.yml")
			write(path, string(body), 0600)
			command := exec.Command("ansible-playbook", "-i", "localhost,", "-c", "local", path)
			command.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "local"), "ANSIBLE_REMOTE_TEMP="+filepath.Join(dir, "remote"), "ANSIBLE_FORKS=1")
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("rollback: %v\n%s", err, out)
			}
			_, restarted := os.Stat(filepath.Join(dir, "restarted"))
			if (restarted == nil) != tc.restart {
				t.Fatalf("restart=%v want %v", restarted == nil, tc.restart)
			}
			helper, err := filepath.Abs("../../playbooks/files/pilot-siem-relp-check")
			if err != nil {
				t.Fatal(err)
			}
			code := fmt.Sprintf("import pathlib,runpy; h=runpy.run_path(%q); p={'config':%q,'directory':pathlib.Path(%q),'enabled':True}; print(h['service_state'](p)[1])", helper, config, tlsDir)
			probe := exec.Command(python, "-c", code)
			probe.Env = append(os.Environ(), "PATH="+env["PATH"].(string), "TLS_RELOAD_CASE_DIR="+dir, "TLS_RELOAD_CASE_MODE="+tc.mode)
			out, err := probe.CombinedOutput()
			want := "False\n"
			if tc.pending {
				want = "True\n"
			}
			if err != nil || string(out) != want {
				t.Fatalf("pending: %v %s want %s", err, out, want)
			}
		})
	}
}
