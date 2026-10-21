package secretpath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateSymlinkAndParentAliases(t *testing.T) {
	dir := t.TempDir()
	vars := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(filepath.Join(vars, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(vars, "nested"), filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	// Preserve '..' until after resolving the symlink: cleaning first would
	// incorrectly classify this new file as dir/new.yml, outside group_vars.
	path := dir + "/alias/../new.yml"
	if Validate(dir, path) == nil {
		t.Fatal("symlink/.. alias bypassed vars boundary")
	}
	if err := os.Symlink(filepath.Join(vars, "missing.yml"), filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	if Validate(dir, filepath.Join(dir, "dangling")) == nil {
		t.Fatal("dangling symlink accepted")
	}
}

func TestValidateAllowsExternalReferencesAndUnrelatedHardlinks(t *testing.T) {
	dir, external := t.TempDir(), t.TempDir()
	if err := os.Symlink(external, filepath.Join(dir, ".vault")); err != nil {
		t.Fatal(err)
	}
	if err := Validate(dir, filepath.Join(dir, ".vault", "new", "secret.yml")); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(external, "source.yml")
	if err := os.WriteFile(source, []byte("password: DUMMY130\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(external, "alias.yml")
	if err := os.Link(source, alias); err != nil {
		t.Fatal(err)
	}
	if err := Validate(dir, alias); err != nil {
		t.Fatal("unrelated external hardlink rejected:", err)
	}
}
