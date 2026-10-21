package secretpath

import (
	"fmt"
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

// A vars-tree alias can appear after an editor has opened an external source.
// Validate must inspect both trees on every save, including files not yet made.
func TestValidateRejectsVarsDirectoryAliases(t *testing.T) {
	for _, tree := range []string{"group_vars", "host_vars"} {
		for _, nested := range []bool{false, true} {
			for _, existing := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/nested=%t/existing=%t", tree, nested, existing), func(t *testing.T) {
					dir, external := t.TempDir(), t.TempDir()
					path := filepath.Join(external, "all.yml")
					if existing {
						if err := os.WriteFile(path, []byte("port: 8080\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					alias := filepath.Join(dir, tree)
					if nested {
						alias = filepath.Join(alias, "nested")
					}
					if err := os.MkdirAll(filepath.Dir(alias), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(external, alias); err != nil {
						t.Fatal(err)
					}
					if err := Validate(dir, path); err == nil {
						t.Fatal("vars directory alias accepted")
					}
				})
			}
		}
	}
}

func TestValidateRejectsUninspectableVarsTrees(t *testing.T) {
	for _, tree := range []string{"group_vars", "host_vars"} {
		for _, problem := range []string{"dangling", "cyclic", "unreadable"} {
			t.Run(tree+"/"+problem, func(t *testing.T) {
				dir := t.TempDir()
				base := filepath.Join(dir, tree)
				if err := os.Mkdir(base, 0o700); err != nil {
					t.Fatal(err)
				}
				bad := filepath.Join(base, "nested")
				switch problem {
				case "dangling":
					if err := os.Symlink(filepath.Join(dir, "missing"), bad); err != nil {
						t.Fatal(err)
					}
				case "cyclic":
					if err := os.Symlink(bad, bad); err != nil {
						t.Fatal(err)
					}
				case "unreadable":
					if err := os.Mkdir(bad, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(bad, 0); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Chmod(bad, 0o700) })
					// Assert the fixture really exercises a traversal error.
					if _, err := os.ReadDir(bad); !os.IsPermission(err) {
						t.Fatalf("fixture is readable: %v", err)
					}
				}
				for _, existing := range []bool{false, true} {
					path := filepath.Join(dir, fmt.Sprintf("secret-%t.yml", existing))
					if existing {
						if err := os.WriteFile(path, []byte("port: 8080\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					if Validate(dir, path) == nil {
						t.Errorf("uninspectable tree accepted, existing=%t", existing)
					}
				}
			})
		}
	}
}

func TestValidateRejectsVarsFileAliases(t *testing.T) {
	for _, tree := range []string{"group_vars", "host_vars"} {
		for _, kind := range []string{"symlink", "hardlink"} {
			t.Run(tree+"/"+kind, func(t *testing.T) {
				dir, external := t.TempDir(), t.TempDir()
				source := filepath.Join(external, "source.yml")
				if err := os.WriteFile(source, []byte("port: 8080\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				base := filepath.Join(dir, tree)
				if err := os.Mkdir(base, 0o700); err != nil {
					t.Fatal(err)
				}
				link := os.Symlink
				if kind == "hardlink" {
					link = os.Link
				}
				if err := link(source, filepath.Join(base, "all.yml")); err != nil {
					t.Fatal(err)
				}
				if Validate(dir, source) == nil {
					t.Fatal("vars file alias accepted")
				}
			})
		}
	}
}
