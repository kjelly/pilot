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
					if Validate(dir, external+"-sibling/all.yml") == nil {
						t.Fatal("uninspectable vars alias accepted for an unrelated external sibling")
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
	if Validate(dir, filepath.Join(t.TempDir(), "safe.yml")) == nil {
		t.Fatal("vars directory backlink must be rejected without traversing it")
	}
}

func TestValidateChecksSourceAncestorsBeforeFileExists(t *testing.T) {
	for _, tree := range []string{"group_vars", "host_vars"} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nested=%t", tree, nested), func(t *testing.T) {
				workspace, sourceRoot, unrelated := t.TempDir(), t.TempDir(), t.TempDir()
				path := filepath.Join(sourceRoot, "not-created", "secret.yml")
				if err := Validate(workspace, path); err != nil {
					t.Fatalf("safe external destination rejected: %v", err)
				}
				alias := filepath.Join(sourceRoot, tree)
				if nested {
					alias = filepath.Join(alias, "nested")
				}
				if err := os.MkdirAll(filepath.Dir(alias), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(unrelated, alias); err != nil {
					t.Fatal(err)
				}
				// The stricter storage policy rejects any vars directory
				// alias, even when it exposes a different external directory.
				if Validate(workspace, path) == nil {
					t.Fatal("missing destination skipped its source-ancestor vars tree")
				}
				if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
					t.Fatal("validation created the missing destination directory")
				}
			})
		}
	}
}

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

// Canonical names one file one way: absolute, relative and chained links,
// a relative path and a symlinked directory all resolve to the real file;
// a file not created yet resolves through its nearest existing directory;
// a dangling link fails rather than counting as a new file.
func TestCanonicalNamesOneFileOneWay(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	target := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := func(dest, at string) string {
		t.Helper()
		if err := os.Symlink(dest, at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, target)
	if err != nil {
		t.Fatal(err)
	}
	linkedDir := link(dir, filepath.Join(other, "dir"))
	mid := link("real.yaml", filepath.Join(dir, "mid.yaml"))
	for name, tt := range map[string]struct{ path, want string }{
		"real file":               {target, target},
		"absolute link":           {link(target, filepath.Join(other, "abs.yaml")), target},
		"relative link":           {link("real.yaml", filepath.Join(dir, "rel.yaml")), target},
		"chained link":            {link(mid, filepath.Join(other, "chain.yaml")), target},
		"relative path":           {relative, target},
		"linked directory":        {filepath.Join(linkedDir, "real.yaml"), target},
		"new file":                {filepath.Join(dir, "new.yaml"), filepath.Join(dir, "new.yaml")},
		"new file, linked dir":    {filepath.Join(linkedDir, "new.yaml"), filepath.Join(dir, "new.yaml")},
		"new file, new directory": {filepath.Join(linkedDir, "sub", "new.yaml"), filepath.Join(dir, "sub", "new.yaml")},
		// .. after a link is the link destination's parent, as for open(2).
		"link then ..": {linkedDir + "/../" + filepath.Base(dir) + "/real.yaml", target},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Canonical(tt.path)
			if err != nil || got != tt.want {
				t.Fatalf("Canonical(%s) = %q, %v; want %q", tt.path, got, err, tt.want)
			}
		})
	}
	for name, path := range map[string]string{
		"dangling link":          link(filepath.Join(dir, "missing.yaml"), filepath.Join(other, "dangling.yaml")),
		"under a dangling link":  filepath.Join(link(filepath.Join(dir, "missing-dir"), filepath.Join(other, "dangling-dir")), "new.yaml"),
		"dangling relative link": link("missing.yaml", filepath.Join(dir, "dangling-rel.yaml")),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := Canonical(path); err == nil {
				t.Fatalf("Canonical(%s) = %q, want an error", path, got)
			}
		})
	}
}
