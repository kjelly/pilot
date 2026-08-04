package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDiffManagedFiles_IdenticalDirsProduceEmptyDiff(t *testing.T) {
	before := t.TempDir()
	after := t.TempDir()
	writeTestFile(t, filepath.Join(before, "hosts.yml"), "hosts: {web: {}}\n")
	writeTestFile(t, filepath.Join(after, "hosts.yml"), "hosts: {web: {}}\n")

	patch, affected, _, err := diffManagedFiles(before, after)
	if err != nil {
		t.Fatalf("diffManagedFiles() error = %v", err)
	}
	if patch != "" || len(affected) != 0 {
		t.Fatalf("expected no diff for identical dirs, got patch=%q affected=%v", patch, affected)
	}
}

func TestDiffManagedFiles_ChangedContentIsReported(t *testing.T) {
	before := t.TempDir()
	after := t.TempDir()
	writeTestFile(t, filepath.Join(before, "hosts.yml"), "hosts: {web: {}}\n")
	writeTestFile(t, filepath.Join(after, "hosts.yml"), "hosts: {web: {}, db: {}}\n")

	patch, affected, _, err := diffManagedFiles(before, after)
	if err != nil {
		t.Fatalf("diffManagedFiles() error = %v", err)
	}
	if len(affected) != 1 || affected[0] != "hosts.yml" {
		t.Fatalf("affected = %v, want [hosts.yml]", affected)
	}
	if !strings.Contains(patch, "hosts.yml") || !strings.Contains(patch, "db") {
		t.Fatalf("expected patch to mention the changed file and content, got:\n%s", patch)
	}
}

func TestDiffManagedFiles_CreatedFileDiffsAgainstEmpty(t *testing.T) {
	before := t.TempDir() // hosts.yml doesn't exist yet
	after := t.TempDir()
	writeTestFile(t, filepath.Join(after, "hosts.yml"), "hosts: {web: {}}\n")

	patch, affected, _, err := diffManagedFiles(before, after)
	if err != nil {
		t.Fatalf("diffManagedFiles() error = %v", err)
	}
	if len(affected) != 1 || affected[0] != "hosts.yml" {
		t.Fatalf("affected = %v, want [hosts.yml]", affected)
	}
	if !strings.Contains(patch, "web") {
		t.Fatalf("expected patch to show the new file's content, got:\n%s", patch)
	}
}

func TestDiffEntries_SecretFileIsRedactedNotDiffed(t *testing.T) {
	before := []managedFileEntry{{RelPath: ".vault/main.yaml", Content: []byte("ipa_admin_password: old-secret-value\n"), IsSecret: true}}
	after := []managedFileEntry{{RelPath: ".vault/main.yaml", Content: []byte("ipa_admin_password: new-secret-value\n"), IsSecret: true}}

	patch, affected, redacted := diffEntries(before, after)
	if !redacted {
		t.Fatal("expected redacted = true for a changed secret file")
	}
	if len(affected) != 1 || affected[0] != ".vault/main.yaml" {
		t.Fatalf("affected = %v, want [.vault/main.yaml]", affected)
	}
	if strings.Contains(patch, "old-secret-value") || strings.Contains(patch, "new-secret-value") {
		t.Fatalf("expected the patch to omit real secret content, got:\n%s", patch)
	}
	if !strings.Contains(patch, ".vault/main.yaml") {
		t.Fatalf("expected the patch to still name the changed file, got:\n%s", patch)
	}
}

func TestDiffEntries_UnchangedSecretFileIsNotFlaggedRedacted(t *testing.T) {
	entries := []managedFileEntry{{RelPath: ".vault/main.yaml", Content: []byte("x: y\n"), IsSecret: true}}
	patch, affected, redacted := diffEntries(entries, entries)
	if redacted {
		t.Fatal("expected redacted = false when no secret file actually changed")
	}
	if patch != "" || len(affected) != 0 {
		t.Fatalf("expected no diff for an unchanged secret file, got patch=%q affected=%v", patch, affected)
	}
}

func TestDiffManagedFiles_RemovedFileDiffsAgainstEmpty(t *testing.T) {
	before := t.TempDir()
	after := t.TempDir() // role-presets.yml removed in "after"
	writeTestFile(t, filepath.Join(before, "role-presets.yml"), "presets: [{label: x, roles: [docker]}]\n")

	patch, affected, _, err := diffManagedFiles(before, after)
	if err != nil {
		t.Fatalf("diffManagedFiles() error = %v", err)
	}
	if len(affected) != 1 || affected[0] != "role-presets.yml" {
		t.Fatalf("affected = %v, want [role-presets.yml]", affected)
	}
	if !strings.Contains(patch, "docker") {
		t.Fatalf("expected patch to show the removed file's content, got:\n%s", patch)
	}
}
