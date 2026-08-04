package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeWorkspaceRevision_DeterministicForSameContent(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {web: {}}\n")
	writeTestFile(t, filepath.Join(dir, "group_vars", "freeipa.yml"), "a: 1\n")

	first, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	second, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	if first != second {
		t.Fatalf("revision not deterministic: %q != %q", first, second)
	}
	if first == "" {
		t.Fatal("expected a non-empty revision")
	}
}

func TestComputeWorkspaceRevision_EmptyWorkspaceIsStable(t *testing.T) {
	dir := t.TempDir()
	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() on empty workspace error = %v", err)
	}
	if rev == "" {
		t.Fatal("expected a non-empty revision even for zero managed files")
	}
}

func TestComputeWorkspaceRevision_ChangesWhenManagedFileContentChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.yml")
	writeTestFile(t, path, "hosts: {web: {}}\n")
	before, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	writeTestFile(t, path, "hosts: {web: {}, db: {}}\n")
	after, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	if before == after {
		t.Fatal("expected revision to change when a managed file's content changes")
	}
}

func TestComputeWorkspaceRevision_UnaffectedByNonManagedFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	before, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	writeTestFile(t, filepath.Join(dir, "README.md"), "not managed\n")
	writeTestFile(t, filepath.Join(dir, "group_vars", "notes.txt"), "also not managed\n")
	after, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	if before != after {
		t.Fatal("expected revision to be unaffected by files outside the managed set")
	}
}

func TestComputeWorkspaceRevision_DiffersForSymlinkVsRegularFileWithSameContent(t *testing.T) {
	content := "hosts: {web: {}}\n"

	regularDir := t.TempDir()
	writeTestFile(t, filepath.Join(regularDir, "hosts.yml"), content)
	regularRev, err := computeWorkspaceRevision(regularDir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	symlinkDir := t.TempDir()
	target := filepath.Join(symlinkDir, "real.yml")
	writeTestFile(t, target, content)
	if err := os.Symlink(target, filepath.Join(symlinkDir, "hosts.yml")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	symlinkRev, err := computeWorkspaceRevision(symlinkDir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	if regularRev == symlinkRev {
		t.Fatal("expected a symlinked managed file to produce a different revision than an identical-content regular file")
	}
}
