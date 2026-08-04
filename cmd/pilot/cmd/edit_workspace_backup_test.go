package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRestoreManagedFiles_RewritesChangedFileBackToSnapshot(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {web: {}}\n")
	snapshot, err := managedFileEntries(dir)
	if err != nil {
		t.Fatalf("managedFileEntries() error = %v", err)
	}

	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {web: {}, db: {}}\n")

	if err := restoreManagedFiles(dir, snapshot); err != nil {
		t.Fatalf("restoreManagedFiles() error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	if string(got) != "hosts: {web: {}}\n" {
		t.Fatalf("hosts.yml = %q, want the snapshotted content", got)
	}
}

func TestRestoreManagedFiles_RemovesFileCreatedAfterSnapshot(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	snapshot, err := managedFileEntries(dir)
	if err != nil {
		t.Fatalf("managedFileEntries() error = %v", err)
	}

	writeTestFile(t, filepath.Join(dir, "role-presets.yml"), "presets: []\n")

	if err := restoreManagedFiles(dir, snapshot); err != nil {
		t.Fatalf("restoreManagedFiles() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "role-presets.yml")); !os.IsNotExist(err) {
		t.Fatalf("expected role-presets.yml (created after the snapshot) to be removed, stat error = %v", err)
	}
}

func TestRestoreManagedFiles_RevisionMatchesSnapshotRevisionAfterRestore(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {web: {}}\n")
	revisionBefore, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	snapshot, err := managedFileEntries(dir)
	if err != nil {
		t.Fatalf("managedFileEntries() error = %v", err)
	}

	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {web: {}, db: {}}\n")
	writeTestFile(t, filepath.Join(dir, "group_vars", "new.yml"), "x: 1\n")

	if err := restoreManagedFiles(dir, snapshot); err != nil {
		t.Fatalf("restoreManagedFiles() error = %v", err)
	}
	revisionAfter, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}
	if revisionAfter != revisionBefore {
		t.Fatalf("revision after restore = %q, want the pre-change revision %q", revisionAfter, revisionBefore)
	}
}
