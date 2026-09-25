package spec

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// archivedYAMLModule is gopkg.in/yaml.v3, whose repository was archived in
// April 2025. The maintained fork with the same API is go.yaml.in/yaml/v3;
// the whole repo moved to it at once. The path is assembled so this file
// does not match itself.
var archivedYAMLModule = "gopkg.in/" + "yaml.v3"

// importsArchivedYAML reports whether Go source imports archivedYAMLModule,
// with or without an alias.
func importsArchivedYAML(src string) bool {
	re := regexp.MustCompile(`(?m)^\s*(?:import\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"` + regexp.QuoteMeta(archivedYAMLModule) + `"`)
	return re.MatchString(src)
}

func TestRegression_NoArchivedYAMLImport(t *testing.T) {
	root := filepath.Join("..", "..")
	skipDirs := map[string]bool{".git": true, "tmp": true, ".verification": true, "node_modules": true}
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if importsArchivedYAML(string(src)) {
			rel, _ := filepath.Rel(root, path)
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("import go.yaml.in/yaml/v3, not the archived %s:\n%s", archivedYAMLModule, strings.Join(offenders, "\n"))
	}
}

func TestImportsArchivedYAML(t *testing.T) {
	cases := map[string]bool{
		"import \"" + archivedYAMLModule + "\"\n":                         true,
		"import (\n\t\"os\"\n\t\"" + archivedYAMLModule + "\"\n)\n":       true,
		"import (\n\tyamlv3 \"" + archivedYAMLModule + "\"\n)\n":          true,
		"import (\n\t\"os\"\n\n\t\"go.yaml.in/yaml/v3\"\n)\n":             false,
		"// see " + archivedYAMLModule + " for the history\n":             false,
		"const note = \"moved off " + archivedYAMLModule + " in 2026\"\n": false,
	}
	for src, want := range cases {
		if got := importsArchivedYAML(src); got != want {
			t.Errorf("importsArchivedYAML(%q) = %v, want %v", src, got, want)
		}
	}
}
