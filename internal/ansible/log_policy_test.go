package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	raw := `password: hunter2 token=abc123 api_key: "key value" --secret cli-secret`
	got := RedactSecrets(raw)
	for _, secret := range []string{"hunter2", "abc123", "key value", "cli-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("RedactSecrets leaked %q: %q", secret, got)
		}
	}
	if !strings.Contains(got, "password: [REDACTED]") || !strings.Contains(got, "token= [REDACTED]") {
		t.Fatalf("RedactSecrets did not preserve the key and redact its value: %q", got)
	}
}

func TestMaintainLogRedactsRotatesAndRestrictsPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible.log")
	if err := os.WriteFile(path, []byte("password: first-secret\nordinary line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	policy := LogPolicy{MaxBytes: 10, MaxFiles: 2}
	if err := MaintainLogWithPolicy(path, policy); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("active log mode = %o, want 600", info.Mode().Perm())
	}
	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rotated), "first-secret") {
		t.Fatalf("rotated log leaked secret: %q", rotated)
	}
	if info, err := os.Stat(path + ".1"); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("rotated log mode = %v, want 600", info)
	}
}

func TestMaintainLogFromEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible.log")
	if err := os.WriteFile(path, []byte("secret: value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MaintainLogFromEnv([]string{"ANSIBLE_LOG_PATH=" + path}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "value") {
		t.Fatalf("log still contains secret: %q", data)
	}
}
