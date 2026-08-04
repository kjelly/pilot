package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyManagedFilesToTemp_PreservesContentAndStructure(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {web: {}}\n")
	writeTestFile(t, filepath.Join(dir, "group_vars", "freeipa.yml"), "a: 1\n")

	tempDir, cleanup, err := copyManagedFilesToTemp(dir)
	if err != nil {
		t.Fatalf("copyManagedFilesToTemp() error = %v", err)
	}
	defer cleanup()

	got, err := os.ReadFile(filepath.Join(tempDir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read copied hosts.yml: %v", err)
	}
	if string(got) != "hosts: {web: {}}\n" {
		t.Fatalf("copied hosts.yml = %q, want original content", got)
	}
	got, err = os.ReadFile(filepath.Join(tempDir, "group_vars", "freeipa.yml"))
	if err != nil {
		t.Fatalf("read copied group_vars/freeipa.yml: %v", err)
	}
	if string(got) != "a: 1\n" {
		t.Fatalf("copied group_vars/freeipa.yml = %q, want original content", got)
	}
}

func TestCopyManagedFilesToTemp_NeverRecreatesASymlink(t *testing.T) {
	dir := t.TempDir()
	outsideTarget := filepath.Join(t.TempDir(), "outside.yml")
	writeTestFile(t, outsideTarget, "sensitive: true\n")
	if err := os.Symlink(outsideTarget, filepath.Join(dir, "hosts.yml")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	tempDir, cleanup, err := copyManagedFilesToTemp(dir)
	if err != nil {
		t.Fatalf("copyManagedFilesToTemp() error = %v", err)
	}
	defer cleanup()

	lst, err := os.Lstat(filepath.Join(tempDir, "hosts.yml"))
	if err != nil {
		t.Fatalf("lstat copied hosts.yml: %v", err)
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		t.Fatal("expected the copy to materialize a plain regular file, not recreate the symlink — otherwise writing into the copy could mutate the outside target")
	}
	got, err := os.ReadFile(filepath.Join(tempDir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read copied hosts.yml: %v", err)
	}
	if string(got) != "sensitive: true\n" {
		t.Fatalf("copied content = %q, want the resolved target's content", got)
	}
}

func TestCopyManagedFilesToTemp_LandsOutsideSourceWorkspace(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")

	tempDir, cleanup, err := copyManagedFilesToTemp(dir)
	if err != nil {
		t.Fatalf("copyManagedFilesToTemp() error = %v", err)
	}
	defer cleanup()

	if strings.HasPrefix(tempDir, dir) {
		t.Fatalf("temp copy %q must not be nested inside the source workspace %q", tempDir, dir)
	}
}

func TestCopyManagedFilesToTemp_CleanupRemovesTempDir(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")

	tempDir, cleanup, err := copyManagedFilesToTemp(dir)
	if err != nil {
		t.Fatalf("copyManagedFilesToTemp() error = %v", err)
	}
	cleanup()

	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Fatalf("expected cleanup to remove %s, stat error = %v", tempDir, err)
	}
}
