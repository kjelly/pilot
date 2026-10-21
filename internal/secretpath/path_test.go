package secretpath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestValidateReverseDirectoryAliases(t *testing.T) {
	for _, tree := range []string{"group_vars", "host_vars"} {
		for _, nested := range []bool{false, true} {
			for _, existing := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/nested=%v/existing=%v", tree, nested, existing), func(t *testing.T) {
					dir, external := t.TempDir(), t.TempDir()
					path := filepath.Join(external, "new", "all.yml")
					if existing {
						if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(path, []byte("port: 8080\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					alias := filepath.Join(dir, tree)
					if nested {
						if err := os.MkdirAll(alias, 0o700); err != nil {
							t.Fatal(err)
						}
						alias = filepath.Join(alias, "all")
					}
					if err := os.Symlink(external, alias); err != nil {
						t.Fatal(err)
					}
					if Validate(dir, path) == nil {
						t.Fatal("external destination exposed through vars directory was accepted")
					}
					if err := Validate(dir, external+"-sibling/all.yml"); err != nil {
						t.Fatalf("unrelated external sibling rejected: %v", err)
					}
				})
			}
		}
	}
}

func TestValidateDirectoryAliasesFailClosed(t *testing.T) {
	for _, kind := range []string{"dangling_root", "cyclic_root", "dangling_nested", "cyclic_nested"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			alias := filepath.Join(dir, "group_vars")
			if strings.HasSuffix(kind, "nested") {
				if err := os.MkdirAll(alias, 0o700); err != nil {
					t.Fatal(err)
				}
				alias = filepath.Join(alias, "all")
			}
			target := filepath.Join(dir, "missing")
			if strings.HasPrefix(kind, "cyclic") {
				target = alias
			}
			if err := os.Symlink(target, alias); err != nil {
				t.Fatal(err)
			}
			if Validate(dir, filepath.Join(t.TempDir(), "safe.yml")) == nil {
				t.Fatal("unresolved vars alias accepted")
			}
		})
	}
}

func TestValidateNestedDirectoryAliasHardlink(t *testing.T) {
	dir, external, unrelated := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "host_vars"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(dir, "host_vars", "host")); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(unrelated, "secret.yml")
	if err := os.WriteFile(source, []byte("port: 8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(source, filepath.Join(external, "all.yml")); err != nil {
		t.Fatal(err)
	}
	if Validate(dir, source) == nil {
		t.Fatal("hardlink behind nested directory alias accepted")
	}
}

func TestValidateDirectoryBacklinkTerminates(t *testing.T) {
	dir := t.TempDir()
	vars := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(vars, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(vars, filepath.Join(vars, "back")); err != nil {
		t.Fatal(err)
	}
	if err := Validate(dir, filepath.Join(t.TempDir(), "safe.yml")); err != nil {
		t.Fatal(err)
	}
}
