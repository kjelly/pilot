package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRosterPersistenceRejectsReverseDirectoryAlias(t *testing.T) {
	for _, tree := range []string{"group_vars", "host_vars"} {
		t.Run(tree, func(t *testing.T) {
			dir, external := t.TempDir(), t.TempDir()
			t.Chdir(dir)
			path := filepath.Join(external, "new", "roster.yml")
			if err := os.Symlink(external, filepath.Join(dir, tree)); err != nil {
				t.Fatal(err)
			}
			if err := WriteMinimalRosterSkeleton(path, "admin", "DUMMY130_PASSWORD"); err == nil {
				t.Fatal("roster creation accepted reverse vars alias")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("roster creation wrote forbidden destination")
			}
			if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
				t.Fatal("roster creation created forbidden parent directory")
			}
			const original = "port: 8080\n"
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := writeSecretSourceFile(path, []byte("password: DUMMY130_PASSWORD\n"), 0o600); err == nil {
				t.Fatal("roster persistence accepted reverse vars alias")
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != original {
				t.Fatal("roster persistence changed forbidden destination")
			}
		})
	}
}
