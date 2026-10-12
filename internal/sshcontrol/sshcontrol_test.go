package sshcontrol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func useBase(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	t.Setenv(BaseEnv, base)
	return base
}

func TestDir_DeterministicPerKindAndKey(t *testing.T) {
	base := useBase(t)
	a := Dir("vmt", "vb-1")
	if a != Dir("vmt", "vb-1") {
		t.Fatal("the same kind and key gave two directories")
	}
	for _, other := range []string{Dir("vmt", "vb-2"), Dir("ssh", "vb-1")} {
		if other == a {
			t.Fatalf("different owners share %s", a)
		}
	}
	if filepath.Dir(a) != base || !strings.HasPrefix(filepath.Base(a), "pilot-vmt-") {
		t.Fatalf("Dir = %s, want pilot-vmt-* directly under %s", a, base)
	}
}

func TestBase_DefaultsToTmp(t *testing.T) {
	t.Setenv(BaseEnv, "")
	if Base() != "/tmp" {
		t.Fatalf("Base() = %s, want /tmp", Base())
	}
}

// TestControlPath_FitsSocketBudget: under the production base the
// ControlPath with %C expanded (40 hex) plus the ".<16 chars>" suffix ssh
// binds first fits sun_path (108 bytes including NUL), however long the key.
func TestControlPath_FitsSocketBudget(t *testing.T) {
	t.Setenv(BaseEnv, "")
	cp := ControlPath(Dir("vmt", strings.Repeat("k", 4096)))
	if !strings.HasSuffix(cp, "/%C") {
		t.Fatalf("ControlPath %s should be named by %%C", cp)
	}
	expanded := strings.TrimSuffix(cp, "%C") + strings.Repeat("0", 40)
	if budget := 108 - 1 - len(".0123456789abcdef"); len(expanded) > budget {
		t.Fatalf("expanded ControlPath is %d bytes, over the %d-byte budget: %s", len(expanded), budget, expanded)
	}
}

func TestEnsure_CreatesPrivateDirAndTightensPermissions(t *testing.T) {
	useBase(t)
	dir := Dir("vmt", "vb-1")
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("%s: %v %v, want a 0700 directory", dir, info, err)
	}
}

func TestEnsureAndRemove_RejectSymlinkAndFile(t *testing.T) {
	useBase(t)
	link := Dir("vmt", "link")
	target := t.TempDir()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(link); err == nil {
		t.Fatal("Ensure accepted a symlink")
	}
	if err := Remove(link); err == nil {
		t.Fatal("Remove followed a symlink")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("symlink target was removed: %v", err)
	}
	file := Dir("vmt", "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(file); err == nil {
		t.Fatal("Ensure accepted a regular file")
	}
	if err := Remove(file); err == nil {
		t.Fatal("Remove deleted a regular file")
	}
}

func TestRemove_DeletesDirAndSocketsAndIsIdempotent(t *testing.T) {
	useBase(t)
	dir := Dir("vmt", "vb-1")
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, strings.Repeat("a", 40)), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Remove(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("%s still exists: %v", dir, err)
	}
	if err := Remove(dir); err != nil {
		t.Fatalf("second Remove: %v", err)
	}
}
