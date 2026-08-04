package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestManagedFileEntries_EnumeratesExpectedFilesSorted(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	writeTestFile(t, filepath.Join(dir, "role-presets.yml"), "presets: []\n")
	writeTestFile(t, filepath.Join(dir, "group_vars", "freeipa.yml"), "a: 1\n")
	writeTestFile(t, filepath.Join(dir, "group_vars", "zzz.yaml"), "b: 2\n")
	writeTestFile(t, filepath.Join(dir, "group_vars", "not-managed.txt"), "ignored\n")
	writeTestFile(t, filepath.Join(dir, "host_vars", "web-01.yml"), "c: 3\n")

	entries, err := managedFileEntries(dir)
	if err != nil {
		t.Fatalf("managedFileEntries() error = %v", err)
	}
	var gotPaths []string
	for _, e := range entries {
		gotPaths = append(gotPaths, e.RelPath)
	}
	want := []string{"group_vars/freeipa.yml", "group_vars/zzz.yaml", "host_vars/web-01.yml", "hosts.yml", "role-presets.yml"}
	if len(gotPaths) != len(want) {
		t.Fatalf("paths = %v, want %v", gotPaths, want)
	}
	for i, w := range want {
		if gotPaths[i] != w {
			t.Fatalf("paths[%d] = %q, want %q (want sorted: %v)", i, gotPaths[i], w, want)
		}
	}
}

func TestManagedFileEntries_IncludesVaultFilesTaggedSecret(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")
	writeTestFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: hunter2\n")
	writeTestFile(t, filepath.Join(dir, ".vault", "extra.yml"), "another_secret: x\n")

	entries, err := managedFileEntries(dir)
	if err != nil {
		t.Fatalf("managedFileEntries() error = %v", err)
	}
	byPath := map[string]managedFileEntry{}
	for _, e := range entries {
		byPath[e.RelPath] = e
	}
	for _, path := range []string{".vault/main.yaml", ".vault/extra.yml"} {
		e, ok := byPath[path]
		if !ok {
			t.Fatalf("expected %s to be enumerated, got %v", path, entries)
		}
		if !e.IsSecret {
			t.Fatalf("expected %s to be tagged IsSecret", path)
		}
	}
	if hostsEntry, ok := byPath["hosts.yml"]; !ok || hostsEntry.IsSecret {
		t.Fatalf("expected hosts.yml to NOT be tagged IsSecret, got %+v", hostsEntry)
	}
}

func TestManagedFileEntries_IgnoresNestedSubdirectories(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "group_vars", "nested", "deep.yml"), "x: 1\n")

	entries, err := managedFileEntries(dir)
	if err != nil {
		t.Fatalf("managedFileEntries() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected nested group_vars files to be ignored (non-recursive glob), got %+v", entries)
	}
}

func TestManagedFileEntries_MissingWorkspaceIsNotAnError(t *testing.T) {
	dir := t.TempDir() // nothing written at all
	entries, err := managedFileEntries(dir)
	if err != nil {
		t.Fatalf("managedFileEntries() on an empty workspace error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected zero entries, got %+v", entries)
	}
}

func TestManagedFileEntries_SymlinkResolvesContentAndSetsFlag(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "real-hosts.yml")
	writeTestFile(t, targetPath, "hosts: {web: {}}\n")
	linkPath := filepath.Join(dir, "hosts.yml")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	entries, err := managedFileEntries(dir)
	if err != nil {
		t.Fatalf("managedFileEntries() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %+v, want exactly one (hosts.yml)", entries)
	}
	if !entries[0].IsSymlink {
		t.Fatal("expected IsSymlink = true for a symlinked managed file")
	}
	if string(entries[0].Content) != "hosts: {web: {}}\n" {
		t.Fatalf("Content = %q, want the resolved target's content", entries[0].Content)
	}
}

func TestManagedFileEntries_BrokenSymlinkIsAnError(t *testing.T) {
	dir := t.TempDir()
	linkPath := filepath.Join(dir, "hosts.yml")
	if err := os.Symlink(filepath.Join(dir, "does-not-exist.yml"), linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := managedFileEntries(dir); err == nil {
		t.Fatal("expected an error for a broken symlink managed file, fail-closed rather than silently skipping it")
	}
}
