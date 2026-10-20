package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

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
