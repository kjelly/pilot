package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileBlocksSensitivePaths(t *testing.T) {
	tf := &ReadFileTool{}
	bad := []string{
		"/etc/shadow",
		"/etc/shadow-",
		"/etc/sudoers",
		"/etc/sudoers.d/custom",
		"/root/.ssh/id_rsa",
		"/home/user/.ssh/id_ed25519",
		"/home/user/.aws/credentials",
		"/home/user/.docker/config.json",
		"/home/user/.kube/config",
		"/proc/1/environ",
		"/sys/kernel/security",
		"/var/log/auth.log",
		"/var/log/wtmp",
		"/boot/grub/grub.cfg",
	}
	for _, p := range bad {
		t.Run(p, func(t *testing.T) {
			res, err := tf.Execute(context.Background(), json.RawMessage(`{"path":"`+p+`"}`))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !res.IsError {
				t.Fatalf("expected error for %s, got: %s", p, res.Content)
			}
		})
	}
}

func TestReadFileAllowsDefaultPaths(t *testing.T) {
	tf := &ReadFileTool{}
	if err := tf.ValidatePath("/etc/hosts"); err != nil {
		t.Errorf("/etc/hosts should be allowed by default, got: %v", err)
	}
	if err := tf.ValidatePath("/etc/os-release"); err != nil {
		if err2 := tf.ValidatePath("/usr/lib/os-release"); err2 != nil {
			t.Errorf("/etc/os-release should be allowed by default (or its symlink target /usr/lib/os-release), got: %v / %v", err, err2)
		}
	}
	if err := tf.ValidatePath("/var/log/syslog"); err != nil {
		t.Errorf("/var/log/syslog should be allowed by default, got: %v", err)
	}
}

func TestReadFileBaseDirRestrictsToDirectory(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "allowed.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "secret.txt"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}

	tf := &ReadFileTool{BaseDir: tmp}

	res, err := tf.Execute(context.Background(), json.RawMessage(`{"path":"`+filepath.Join(tmp, "allowed.txt")+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Errorf("expected success in BaseDir, got error: %s", res.Content)
	}

	res, err = tf.Execute(context.Background(), json.RawMessage(`{"path":"`+filepath.Join(other, "secret.txt")+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Errorf("expected error for path outside BaseDir, got: %s", res.Content)
	}
}

func TestReadFileBlockedEvenWithBaseDir(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to create symlink in /etc")
	}
	tmp := t.TempDir()
	if err := os.Symlink("/etc/shadow", filepath.Join(tmp, "shadow")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	tf := &ReadFileTool{BaseDir: tmp}
	res, err := tf.Execute(context.Background(), json.RawMessage(`{"path":"`+filepath.Join(tmp, "shadow")+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("symlink to /etc/shadow should be blocked, got: %s", res.Content)
	}
}

func TestReadFileAllowedPrefixesCustom(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "x.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	tf := &ReadFileTool{AllowedPrefixes: []string{tmp + "/"}}
	res, err := tf.Execute(context.Background(), json.RawMessage(`{"path":"`+filepath.Join(tmp, "x.txt")+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Errorf("custom allowed prefix should work, got: %s", res.Content)
	}
}
